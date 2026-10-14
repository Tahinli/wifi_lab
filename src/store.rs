//! Persistent UI-side data under `~/wifilab`:
//! - `labels.json` — user-assigned names by MAC (APs and clients share one
//!   namespace; a MAC is unique).
//! - `captures.jsonl` — every complete handshake / PMKID capture, one JSON
//!   line each, appended as they arrive and reloaded at startup (the
//!   cracker keeps working across restarts without re-attacking).
//!
//! UI-only data — the privileged service never touches it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::common::{HandshakeCapture, MacAddr, PmkidCapture};

/// `~/wifilab` — falls back to `./wifilab` when HOME is unset.
pub fn data_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("wifilab")
}

fn labels_path() -> PathBuf {
    data_dir().join("labels.json")
}

fn captures_path() -> PathBuf {
    data_dir().join("captures.jsonl")
}

fn session_path() -> PathBuf {
    data_dir().join("crack-session.json")
}

/// One persisted capture (tagged JSON line in `captures.jsonl`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum StoredCapture {
    Handshake(HandshakeCapture),
    Pmkid(PmkidCapture),
}

impl StoredCapture {
    /// Display identity used for dedup on load.
    fn id(&self) -> String {
        match self {
            StoredCapture::Handshake(h) => format!("hs:{}:{}", h.ap, h.client),
            StoredCapture::Pmkid(p) => format!("pmkid:{}", p.ap),
        }
    }
}

fn load_labels_from(path: &Path) -> Result<BTreeMap<MacAddr, String>> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(BTreeMap::new());
        }
        Err(e) => return Err(e).context("reading labels.json"),
    };
    let by_str: BTreeMap<String, String> =
        serde_json::from_str(&raw).context("parsing labels.json")?;
    let mut out = BTreeMap::new();
    for (mac, label) in by_str {
        let mac: MacAddr = mac.parse().with_context(|| format!("bad MAC key {mac:?}"))?;
        if !label.is_empty() {
            out.insert(mac, label);
        }
    }
    Ok(out)
}

/// Load all labels; a missing file is an empty store, a corrupt one is an
/// error (callers log it and start empty rather than clobbering).
pub fn load() -> Result<BTreeMap<MacAddr, String>> {
    load_labels_from(&labels_path())
}

fn save_labels_to(path: &Path, labels: &BTreeMap<MacAddr, String>) -> Result<()> {
    let dir = path.parent().expect("labels path has a parent");
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let by_str: BTreeMap<String, &String> =
        labels.iter().map(|(mac, l)| (mac.to_string(), l)).collect();
    let body = serde_json::to_string_pretty(&by_str).expect("string map serialization");
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, body).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} → {}", tmp.display(), path.display()))
}

/// Persist the whole label map (labels are few; rewriting is cheap and
/// atomic enough via write-to-tmp + rename).
pub fn save(labels: &BTreeMap<MacAddr, String>) -> Result<()> {
    save_labels_to(&labels_path(), labels)
}

fn append_capture_to(path: &Path, cap: &StoredCapture) -> Result<()> {
    let dir = path.parent().expect("captures path has a parent");
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let line = serde_json::to_string(cap).context("serializing capture")?;
    writeln!(f, "{line}").with_context(|| format!("appending to {}", path.display()))
}

/// Append one capture to `captures.jsonl`. Called the moment a capture
/// arrives — the file survives a crash right after.
pub fn append_capture(cap: &StoredCapture) -> Result<()> {
    append_capture_to(&captures_path(), cap)
}

fn load_captures_from(path: &Path) -> Result<Vec<StoredCapture>> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).context("reading captures.jsonl"),
    };
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for (n, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<StoredCapture>(line) {
            Ok(cap) => {
                if seen.insert(cap.id()) {
                    out.push(cap);
                }
            }
            // One corrupt line must not kill the whole archive.
            Err(e) => eprintln!("wifilab: skipping corrupt captures.jsonl line {}: {e}", n + 1),
        }
    }
    Ok(out)
}

/// Load every stored capture (deduped by AP/client identity). A corrupt
/// FILE is an error; individual corrupt lines are skipped.
pub fn load_captures() -> Result<Vec<StoredCapture>> {
    load_captures_from(&captures_path())
}

// ---------------------------------------------------------------------------
// Crack session (resume): the interrupted run's position, so a later start
// — in this or a future session — continues instead of restarting.
// ---------------------------------------------------------------------------

/// A stopped (not finished) crack run: which capture, which attack, how
/// far it had gotten. Written throttle-throttled on progress and once on
/// stop; deleted when the run finds the password or exhausts the space.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CrackSession {
    pub capture: StoredCapture,
    pub attack: crate::attack::Attack,
    /// Candidates checked so far (resume skips/seeks past these).
    pub done: u64,
    /// Worst-case total of the run (see the ETA plumbing), when countable.
    pub total: Option<u64>,
}

fn save_session_to(path: &Path, session: &CrackSession) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).context("creating ~/wifilab")?;
    }
    let json = serde_json::to_string_pretty(session).context("serializing crack session")?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("renaming {}", path.display()))?;
    Ok(())
}

/// Persist the session (atomic-ish: write tmp + rename, like labels).
pub fn save_session(session: &CrackSession) -> Result<()> {
    save_session_to(&session_path(), session)
}

fn load_session_from(path: &Path) -> Result<Option<CrackSession>> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(
            serde_json::from_str(&s).context("parsing crack-session.json")?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context("reading crack-session.json"),
    }
}

/// Load the saved session; `None` when no run was interrupted. A corrupt
/// file is an error (callers log it and start fresh rather than resuming
/// garbage).
pub fn load_session() -> Result<Option<CrackSession>> {
    load_session_from(&session_path())
}

/// Drop the saved session (run found/exhausted, or user discarded).
/// Missing file is fine.
pub fn clear_session() -> Result<()> {
    match std::fs::remove_file(session_path()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).context("removing crack-session.json"),
    }
}

// ---------------------------------------------------------------------------
// Per-SSID PMK cache: `~/wifilab/cache/<ssid-hex>.pmk` in rainbow text
// format — PMKs computed on earlier CPU runs are reusable for ANY capture
// of the same SSID without re-running PBKDF2.
// ---------------------------------------------------------------------------

/// `~/wifilab/cache` — created on use by the cache readers/writers.
pub fn cache_dir() -> PathBuf {
    data_dir().join("cache")
}

/// Cache table path for one SSID: lowercase hex of the raw SSID bytes +
/// `.pmk` (filesystem-safe for arbitrary SSID encodings).
pub fn cache_file(ssid: &str) -> PathBuf {
    let hex: String = ssid.bytes().map(|b| format!("{b:02x}")).collect();
    cache_dir().join(format!("{hex}.pmk"))
}

// ---------------------------------------------------------------------------
// Crack profiles + recent wordlists (`~/wifilab/profiles.json`): user-saved
// attack setups for one-click reuse on the cracker page.
// ---------------------------------------------------------------------------

/// One saved attack setup (mode/wl/rules as the cracker page fields).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CrackProfile {
    pub name: String,
    pub mode: String,
    pub wordlist: String,
    pub rules: Option<String>,
}

/// The whole profiles file: saved presets + MRU wordlist list (cap 5).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Profiles {
    pub profiles: Vec<CrackProfile>,
    pub recent_wordlists: Vec<String>,
}

fn profiles_path() -> PathBuf {
    data_dir().join("profiles.json")
}

fn load_profiles_from(path: &Path) -> Result<Profiles> {
    match std::fs::read_to_string(path) {
        Ok(s) => match serde_json::from_str::<Profiles>(&s) {
            Ok(p) => Ok(p),
            Err(e) => {
                eprintln!("wifilab: profiles.json unreadable ({e}), starting fresh");
                Ok(Profiles::default())
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Profiles::default()),
        Err(e) => Err(e).context("reading profiles.json"),
    }
}

/// Load profiles; missing or unparseable file starts empty (never clobbers).
pub fn load_profiles() -> Result<Profiles> {
    load_profiles_from(&profiles_path())
}

fn save_profiles_to(path: &Path, p: &Profiles) -> Result<()> {
    let dir = path.parent().expect("profiles path has a parent");
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let body = serde_json::to_string_pretty(p).context("serializing profiles")?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, body).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} → {}", tmp.display(), path.display()))
}

/// Persist profiles (atomic-ish: write tmp + rename, like labels).
pub fn save_profiles(p: &Profiles) -> Result<()> {
    save_profiles_to(&profiles_path(), p)
}

/// MRU-insert a wordlist path at the front of `recent_wordlists`, deduped,
/// capped at 5.
pub fn remember_wordlist(p: &mut Profiles, path: &str) {
    p.recent_wordlists.retain(|w| w != path);
    p.recent_wordlists.insert(0, path.to_string());
    p.recent_wordlists.truncate(5);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("wifilab-store-test-{}-{name}", std::process::id()))
    }

    #[test]
    fn labels_roundtrip() {
        let dir = tmp("labels");
        let path = dir.join("labels.json");
        let mac: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        let mut labels = BTreeMap::new();
        labels.insert(mac, "living room".to_string());
        save_labels_to(&path, &labels).unwrap();
        let back = load_labels_from(&path).unwrap();
        assert_eq!(back.get(&mac).map(String::as_str), Some("living room"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn labels_missing_file_is_empty() {
        let back = load_labels_from(&tmp("nope").join("labels.json")).unwrap();
        assert!(back.is_empty());
    }

    #[test]
    fn session_roundtrip_and_missing() {
        let dir = tmp("session");
        let path = dir.join("crack-session.json");
        assert!(load_session_from(&path).unwrap().is_none());
        let session = CrackSession {
            capture: StoredCapture::Pmkid(PmkidCapture {
                ap: "aa:bb:cc:dd:ee:ff".parse().unwrap(),
                client: "11:22:33:44:55:66".parse().unwrap(),
                essid: "parafin".into(),
                pmkid: [7u8; 16],
            }),
            attack: crate::attack::Attack::Bruteforce {
                charset: b"01".to_vec(),
                min: 8,
                max: 10,
                freq_order: true,
            },
            done: 12_345,
            total: Some(1_114_100),
        };
        save_session_to(&path, &session).unwrap();
        let back = load_session_from(&path).unwrap().expect("saved");
        assert_eq!(back, session);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn captures_append_and_load_dedups() {
        let dir = tmp("caps");
        let path = dir.join("captures.jsonl");
        let pm = PmkidCapture {
            ap: "aa:bb:cc:dd:ee:ff".parse().unwrap(),
            client: "11:22:33:44:55:66".parse().unwrap(),
            essid: "parafin".into(),
            pmkid: [7u8; 16],
        };
        let hs = HandshakeCapture::new(
            "aa:bb:cc:dd:ee:ff".parse().unwrap(),
            "11:22:33:44:55:66".parse().unwrap(),
            "parafin".into(),
            [1u8; 32],
            [2u8; 32],
            [3u8; 16],
            vec![9u8; 8],
            2,
        );
        let cap_pm = StoredCapture::Pmkid(pm.clone());
        let cap_hs = StoredCapture::Handshake(hs.clone());
        append_capture_to(&path, &cap_pm).unwrap();
        append_capture_to(&path, &cap_pm).unwrap(); // duplicate line on disk
        append_capture_to(&path, &cap_hs).unwrap();
        // One corrupt line must not kill the rest.
        std::fs::write(
            &path,
            format!("{}{{not json}}\n", std::fs::read_to_string(&path).unwrap()),
        )
        .unwrap();
        let back = load_captures_from(&path).unwrap();
        assert_eq!(back, vec![cap_pm, cap_hs]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn captures_missing_file_is_empty() {
        let back = load_captures_from(&tmp("nope").join("captures.jsonl")).unwrap();
        assert!(back.is_empty());
    }

    #[test]
    fn profiles_roundtrip_and_missing() {
        let dir = tmp("profiles");
        let path = dir.join("profiles.json");
        // Missing file = empty store.
        assert_eq!(load_profiles_from(&path).unwrap().profiles.len(), 0);
        let mut p = Profiles {
            profiles: vec![
                CrackProfile {
                    name: "wl:rockyou".into(),
                    mode: "wordlist".into(),
                    wordlist: "/usr/share/wordlists/rockyou.txt".into(),
                    rules: None,
                },
                CrackProfile {
                    name: "rules:corp".into(),
                    mode: "rules".into(),
                    wordlist: "/home/x/wl.txt".into(),
                    rules: Some("/home/x/best64.rule".into()),
                },
            ],
            recent_wordlists: vec!["/a.txt".into(), "/b.txt".into()],
        };
        p.recent_wordlists.insert(0, "/c.txt".into());
        save_profiles_to(&path, &p).unwrap();
        let back = load_profiles_from(&path).unwrap();
        assert_eq!(back.profiles.len(), 2);
        assert_eq!(back.profiles[0].name, "wl:rockyou");
        assert_eq!(back.profiles[1].rules.as_deref(), Some("/home/x/best64.rule"));
        assert_eq!(back.recent_wordlists, p.recent_wordlists);
        // Unparseable file = empty store, no error (never clobbered).
        std::fs::write(&path, "{{not json").unwrap();
        let back = load_profiles_from(&path).unwrap();
        assert!(back.profiles.is_empty() && back.recent_wordlists.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remember_wordlist_front_insert_dedup_cap5() {
        let mut p = Profiles::default();
        for w in ["/a", "/b", "/c", "/d", "/e", "/a"] {
            remember_wordlist(&mut p, w);
        }
        // "/a" re-remembered: moves to front, no duplicate.
        assert_eq!(p.recent_wordlists, vec!["/a", "/e", "/d", "/c", "/b"]);
        // Sixth distinct path evicts the oldest.
        remember_wordlist(&mut p, "/f");
        assert_eq!(p.recent_wordlists, vec!["/f", "/a", "/e", "/d", "/c"]);
    }

    #[test]
    fn cache_file_hex_naming() {
        let p = cache_file("parafin");
        assert_eq!(
            p.file_name().unwrap().to_str().unwrap(),
            "7061726166696e.pmk"
        );
        // Hex is lowercase and 2 chars per byte; non-ASCII bytes safe.
        let p2 = cache_file("aé");
        assert_eq!(p2.file_name().unwrap().to_str().unwrap(), "61c3a9.pmk");
        assert_eq!(p.parent().unwrap(), cache_dir());
    }
}

