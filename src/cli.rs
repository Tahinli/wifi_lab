//! Headless `wifilab crack` subcommand: crack one capture file with no UI,
//! no radio and no root. The capture file is hc22000 text (one `WPA*01*` /
//! `WPA*02*` line per capture, hashcat -m 22000); the first line that parses
//! is the target, everything else is ignored.
//!
//! Exit codes: 0 password found, 1 keyspace exhausted, 2 usage/IO error.

use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::attack::{self, Attack};
use crate::common::Event;
use crate::crypto::{self, CrackTarget};

/// Owned, clap-free view of the `crack` subcommand flags (main.rs converts
/// its derived `CrackArgs` 1:1 into this so the CLI logic stays testable).
pub struct CliCrack {
    /// Path to the hc22000 capture file.
    pub capture: String,
    /// Attack mode: "wordlist" | "rules" | "bruteforce".
    pub mode: String,
    /// Wordlist path (wordlist-family modes).
    pub wordlist: Option<String>,
    /// Rules file path (rules mode).
    pub rules: Option<String>,
    /// Bruteforce-ish minimum length.
    pub min: usize,
    /// Bruteforce-ish maximum length.
    pub max: usize,
    /// Hybrid: wordlist × append-charset sweep (requires `wordlist`).
    pub hybrid: bool,
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub special: bool,
    /// Force the CPU backend (also disables PMK-cache writes).
    pub cpu: bool,
}

/// Union of the toggled charset presets; when nothing is toggled the
/// default is lower+digits (the most common password soup).
fn cli_charset(args: &CliCrack) -> Vec<u8> {
    let (mut lower, mut digits) = (args.lower, args.digits);
    if !args.lower && !args.upper && !args.digits && !args.special {
        lower = true;
        digits = true;
    }
    attack::charset::compose(lower, args.upper, digits, args.special, &[])
}

fn build_attack(args: &CliCrack) -> Result<Attack, String> {
    let wordlist = |what: &str| -> Result<PathBuf, String> {
        args.wordlist
            .clone()
            .map(PathBuf::from)
            .ok_or_else(|| format!("error: --wordlist is required for {what} mode"))
    };
    if args.hybrid {
        return Ok(Attack::Hybrid {
            wordlist: wordlist("hybrid")?,
            charset: cli_charset(args),
            min: args.min,
            max: args.max,
        });
    }
    match args.mode.as_str() {
        "rules" => Ok(Attack::Rules {
            wordlist: wordlist("rules")?,
            rules: args
                .rules
                .clone()
                .map(PathBuf::from)
                .ok_or_else(|| "error: --rules is required for rules mode".to_string())?,
        }),
        "bruteforce" => Ok(Attack::Bruteforce {
            charset: cli_charset(args),
            min: args.min,
            max: args.max,
            freq_order: true,
        }),
        _ => Ok(Attack::Wordlist(wordlist("wordlist")?)),
    }
}

/// First crackable target in an hc22000 file: the bare `WPA*` prefix hashcat
/// emits is stripped (`crypto::parse_hc22000` takes the bare form).
fn first_target(path: &str) -> Result<CrackTarget, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("error: cannot read capture file {path}: {e}"))?;
    for line in text.lines() {
        let stripped = line.strip_prefix("WPA*").unwrap_or(line);
        if let Ok(target) = crypto::parse_hc22000(stripped) {
            return Ok(target);
        }
    }
    Err(format!("error: no crackable WPA* line in {path}"))
}

/// Run the crack to completion on the calling thread. Progress prints are
/// throttled to one line per 2 s; all engine `Log` lines pass through.
pub fn run_crack_cli(args: CliCrack, out: &mut dyn Write) -> i32 {
    let target = match first_target(&args.capture) {
        Ok(t) => t,
        Err(msg) => {
            let _ = writeln!(out, "{msg}");
            return 2;
        }
    };
    let attack = match build_attack(&args) {
        Ok(a) => a,
        Err(msg) => {
            let _ = writeln!(out, "{msg}");
            return 2;
        }
    };
    if let Err(e) = attack.validate() {
        let _ = writeln!(out, "error: {e:#}");
        return 2;
    }
    let _ = writeln!(out, "target: {}", target.describe());
    let _ = writeln!(out, "attack: {}", attack.describe());

    let (tx, rx) = crossbeam_channel::unbounded();
    let _stop = attack::spawn_crack(target.describe(), target, attack, 0, tx, args.cpu);

    let mut found = false;
    let mut exit = 1;
    let mut last = Instant::now() - Duration::from_secs(3);
    for ev in rx {
        match ev {
            Event::CrackProgress { done, hps, total } => {
                if last.elapsed() >= Duration::from_secs(2) {
                    last = Instant::now();
                    match total {
                        Some(t) => {
                            let _ = writeln!(out, "progress: {done}/{t} @ {hps:.0} H/s");
                        }
                        None => {
                            let _ = writeln!(out, "progress: {done} @ {hps:.0} H/s");
                        }
                    }
                }
            }
            Event::Log(line) => {
                let _ = writeln!(out, "{line}");
            }
            Event::Error(line) => {
                let _ = writeln!(out, "error: {line}");
                exit = 2;
            }
            Event::CrackFound { password } => {
                let _ = writeln!(out, "FOUND: {password}");
                found = true;
            }
            Event::CrackStopped { found: f } => {
                if found || f {
                    return 0;
                }
                return if exit == 2 { 2 } else { 1 };
            }
            _ => {}
        }
    }
    // Channel closed without a terminator (worker panicked) — treat as error.
    let _ = writeln!(out, "error: cracker vanished without a CrackStopped");
    2
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::MacAddr;

    /// The fabricator writes a dummy MIC, so the UI's own capture is NOT
    /// crackable as-is. Build on its frame layout (MIC at offset 81..97,
    /// key_ver 2) and recompute a REAL MIC for the mock cracker's password
    /// (the private `MOCK_PASSWORD` const in ui/cracker.rs — value pinned
    /// here so the test trips loudly if the mock password ever changes).
    fn crackable_capture() -> crate::common::HandshakeCapture {
        const MOCK_PW: &str = "parafin2024!";
        let ap = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let client = MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let mut cap = crate::ui::mock::fabricate_handshake(ap, client, "testap", 7);
        let pmk = crypto::pmk(MOCK_PW.as_bytes(), b"testap");
        let ptk = crypto::ptk(&pmk, &ap, &client, &cap.anonce, &cap.snonce);
        let mic = crypto::mic(&ptk, &cap.eapol_m2, cap.key_ver);
        cap = crate::common::HandshakeCapture::new(
            ap,
            client,
            "testap".to_string(),
            cap.anonce,
            cap.snonce,
            mic,
            cap.eapol_m2,
            cap.key_ver,
        );
        let target = CrackTarget::Handshake(cap.clone());
        assert!(crypto::verify(&target, MOCK_PW.as_bytes()));
        cap
    }

    #[test]
    fn cli_crack_finds_fabricated() {
        let dir = std::env::temp_dir().join(format!(
            "wifilab-cli-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("tempdir");
        let capture = dir.join("cap.hc22000");
        let wordlist = dir.join("words.txt");

        let cap = crackable_capture();
        let line = crate::handshake::handshake_hc22000(&cap);
        std::fs::write(&capture, format!("junk line not hc22000\nWPA*99*bogus\n{line}\n"))
            .expect("write capture");
        std::fs::write(&wordlist, "not-the-password\nhunter2\nparafin2024!\n")
            .expect("write wordlist");

        let args = CliCrack {
            capture: capture.to_string_lossy().into_owned(),
            mode: "wordlist".to_string(),
            wordlist: Some(wordlist.to_string_lossy().into_owned()),
            rules: None,
            min: 8,
            max: 12,
            hybrid: false,
            lower: false,
            upper: false,
            digits: false,
            special: false,
            cpu: true, // deterministic CPU + no PMK-cache writes from tests
        };
        let mut buf = Vec::new();
        let ret = run_crack_cli(args, &mut buf);
        let text = String::from_utf8_lossy(&buf);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(ret, 0, "expected exit 0, output:\n{text}");
        assert!(text.contains("FOUND: parafin2024!"), "output:\n{text}");
    }

    #[test]
    fn cli_crack_missing_files_exit_2() {
        let mut buf = Vec::new();
        let args = CliCrack {
            capture: "/nonexistent/cap.hc22000".to_string(),
            mode: "wordlist".to_string(),
            wordlist: Some("/nonexistent/words.txt".to_string()),
            rules: None,
            min: 8,
            max: 12,
            hybrid: false,
            lower: false,
            upper: false,
            digits: false,
            special: false,
            cpu: true,
        };
        let ret = run_crack_cli(args, &mut buf);
        let text = String::from_utf8_lossy(&buf);
        assert_eq!(ret, 2);
        assert!(text.contains("cannot read capture file"), "output:\n{text}");

        // Capture fine (fabricated), wordlist missing → still exit 2.
        let dir = std::env::temp_dir().join(format!(
            "wifilab-cli-err-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("tempdir");
        let capture = dir.join("cap.hc22000");
        let line = crate::handshake::handshake_hc22000(&crackable_capture());
        std::fs::write(&capture, format!("{line}\n")).expect("write capture");
        let args = CliCrack {
            capture: capture.to_string_lossy().into_owned(),
            mode: "wordlist".to_string(),
            wordlist: Some("/nonexistent/words.txt".to_string()),
            rules: None,
            min: 8,
            max: 12,
            hybrid: false,
            lower: false,
            upper: false,
            digits: false,
            special: false,
            cpu: true,
        };
        let mut buf = Vec::new();
        let ret = run_crack_cli(args, &mut buf);
        let text = String::from_utf8_lossy(&buf);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(ret, 2);
        assert!(text.contains("cannot open wordlist"), "output:\n{text}");
    }
}
