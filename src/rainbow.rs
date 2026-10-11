//! SSID-scoped precomputed PMK tables — the "rainbow" attack for WPA-PSK.
//!
//! PBKDF2-HMAC-SHA1(pass, essid, 4096) is the entire per-candidate cost of
//! cracking; its output depends only on the passphrase and the SSID, not on
//! the captured handshake. Caching pass→PMK pairs for one SSID therefore
//! turns every later run against that SSID into a raw compare (millions of
//! candidates per second), at disk cost of ~64 B per entry.
//!
//! Text format, one entry per line:
//! ```text
//! # wifilab-pmk v1 ssid=Parafin
//! <64 lowercase hex chars of PMK> <passphrase bytes to end of line>
//! ```
//! The passphrase runs to the end of the line (spaces allowed); only the
//! first space separates it from the hex PMK. Lines that are empty, start
//! with `#`, or fail to parse are skipped.

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};

const MAGIC: &str = "# wifilab-pmk v1";

struct PmkIter {
    lines: std::io::Lines<BufReader<File>>,
    /// First line, kept when it turned out to be an entry, not the header.
    pending: Option<String>,
}

impl Iterator for PmkIter {
    type Item = ([u8; 32], Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(first) = self.pending.take() {
            return parse_entry(first.as_bytes());
        }
        for line in self.lines.by_ref() {
            let Ok(line) = line else { continue }; // unreadable line: skip, keep streaming
            let Some(entry) = parse_entry(line.as_bytes()) else {
                continue;
            };
            return Some(entry);
        }
        None
    }
}

/// `<64 hex> <pass>` → `(pmk, pass)`, or None when malformed.
fn parse_entry(line: &[u8]) -> Option<([u8; 32], Vec<u8>)> {
    if line.len() < 66 || line[64] != b' ' {
        return None;
    }
    let pmk = hex32(&line[..64])?;
    let pass = line[65..].to_vec();
    // Writer only emits WPA-legal passphrases; hold the same invariant when
    // reading foreign tables so the cracker never wastes a compare.
    if !(8..=63).contains(&pass.len()) {
        return None;
    }
    Some((pmk, pass))
}

/// Strict lowercase-or-uppercase 64-char hex → 32 bytes.
fn hex32(s: &[u8]) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let nibble = |b: u8| -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    };
    let mut out = [0u8; 32];
    for (i, pair) in s.chunks_exact(2).enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

/// Open a table for cracking. Returns the SSID recorded in the header
/// (`None` when the file has no header) plus a streaming iterator of
/// `(pmk, passphrase)` entries. The caller MUST verify the header SSID
/// matches the target — PMKs are salt-bound to the SSID and compare-fail
/// silently otherwise.
pub fn open(path: &Path) -> Result<(Option<String>, Box<dyn Iterator<Item = ([u8; 32], Vec<u8>)> + Send>)> {
    let f = File::open(path)
        .with_context(|| format!("opening PMK table {}", path.display()))?;
    let mut reader = BufReader::with_capacity(1 << 20, f);
    // Peek the first line for the header.
    let mut first = String::new();
    let n = reader
        .read_line(&mut first)
        .with_context(|| format!("reading PMK table {}", path.display()))?;
    let (ssid, pending) = if n > 0 {
        let trimmed = first.trim_end_matches(['\r', '\n']);
        match parse_header(trimmed) {
            Some(s) => (Some(s), None),
            // Not a header: the first line is an entry — don't drop it.
            None => (None, Some(first)),
        }
    } else {
        (None, None)
    };
    Ok((
        ssid,
        Box::new(PmkIter {
            lines: reader.lines(),
            pending,
        }),
    ))
}

/// `# wifilab-pmk v1 ssid=<essid>` → Some(essid); anything else → None.
fn parse_header(line: &str) -> Option<String> {
    let rest = line.strip_prefix(MAGIC)?;
    rest.strip_prefix(" ssid=").map(str::to_string)
}

/// Streaming table writer: [`create`], [`TableWriter::push`], done.
pub struct TableWriter {
    w: BufWriter<File>,
    entries: u64,
}

impl TableWriter {
    /// Append one entry. `pass` must be 8..=63 bytes (WPA passphrase range).
    pub fn push(&mut self, pmk: &[u8; 32], pass: &[u8]) -> std::io::Result<()> {
        debug_assert!((8..=63).contains(&pass.len()));
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut hex = [0u8; 64];
        for (i, b) in pmk.iter().enumerate() {
            hex[i * 2] = HEX[(b >> 4) as usize];
            hex[i * 2 + 1] = HEX[(b & 0xf) as usize];
        }
        self.w.write_all(&hex)?;
        self.w.write_all(b" ")?;
        self.w.write_all(pass)?;
        self.w.write_all(b"\n")?;
        self.entries += 1;
        Ok(())
    }

    /// Entries written so far. Flushes the buffer.
    pub fn finish(mut self) -> std::io::Result<u64> {
        self.w.flush()?;
        Ok(self.entries)
    }
}

/// Create a table file with the header for `ssid`. Existing file is
/// truncated. Parent directories are created.
pub fn create(path: &Path, ssid: &str) -> Result<TableWriter> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating PMK table directory {}", parent.display()))?;
    }
    let f = File::create(path)
        .with_context(|| format!("creating PMK table {}", path.display()))?;
    let mut w = BufWriter::with_capacity(1 << 20, f);
    writeln!(w, "{MAGIC} ssid={ssid}")
        .with_context(|| format!("writing PMK table header {}", path.display()))?;
    Ok(TableWriter { w, entries: 0 })
}

/// Open `path` for APPENDING as the table for `ssid` (per-SSID PMK cache
/// writer): a missing or zero-length file is created with a fresh header
/// (`create` semantics); an existing non-empty file MUST carry a header
/// whose SSID passes [`check_ssid`] against `ssid` — anything else is an
/// error (refusing to corrupt a table belonging to another SSID). The
/// file is opened append-mode, so existing entries are never touched.
pub fn append_open(path: &Path, ssid: &str) -> Result<TableWriter> {
    let needs_header = match std::fs::metadata(path) {
        Ok(m) => m.len() == 0,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(e) => {
            return Err(e).with_context(|| format!("stat'ing PMK table {}", path.display()));
        }
    };
    if needs_header {
        return create(path, ssid);
    }
    // Existing table: verify the recorded SSID before appending (PMKs are
    // salt-bound to the SSID; mixing tables would poison the cache).
    let first = {
        let f = File::open(path)
            .with_context(|| format!("opening PMK table {}", path.display()))?;
        let mut reader = BufReader::new(f);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .with_context(|| format!("reading PMK table header {}", path.display()))?;
        line
    };
    let header = parse_header(first.trim_end_matches(['\r', '\n']));
    check_ssid(header.as_deref(), ssid)
        .with_context(|| format!("cannot append to PMK table {}", path.display()))?;
    let f = std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .with_context(|| format!("appending to PMK table {}", path.display()))?;
    let w = BufWriter::with_capacity(1 << 20, f);
    Ok(TableWriter { w, entries: 0 })
}

/// Guard used before starting a rainbow run: the table's SSID must equal
/// the target's. Returns a human reason on mismatch.
pub fn check_ssid(table_ssid: Option<&str>, target_ssid: &str) -> Result<()> {
    match table_ssid {
        None => bail!("PMK table has no ssid header — cannot verify it matches the target"),
        Some(s) if s != target_ssid => bail!(
            "PMK table is for ssid \"{s}\" but the target's essid is \"{target_ssid}\" (PMKs are salt-bound to the ssid)"
        ),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_parse() {
        assert_eq!(
            parse_header("# wifilab-pmk v1 ssid=Parafin"),
            Some("Parafin".to_string())
        );
        assert_eq!(
            parse_header("# wifilab-pmk v1 ssid=with space"),
            Some("with space".to_string())
        );
        assert_eq!(parse_header("# wifilab-pmk v1"), None);
        assert_eq!(parse_header("garbage"), None);
    }

    #[test]
    fn entry_parse_strict() {
        let pmk = [0xabu8; 32];
        let hex = "ab".repeat(32);
        let line = format!("{hex} pass word1");
        let (got_pmk, got_pass) = parse_entry(line.as_bytes()).expect("parses");
        assert_eq!(got_pmk, pmk);
        assert_eq!(got_pass, b"pass word1");
        // No space separator, short hex, bad char, short pass → rejected.
        assert!(parse_entry(format!("{hex}pass word1").as_bytes()).is_none());
        assert!(parse_entry(b"ab short").is_none());
        assert!(parse_entry(format!("{}zz p", &hex[..62]).as_bytes()).is_none());
        assert!(parse_entry(format!("{hex} short").as_bytes()).is_none());
    }

    #[test]
    fn roundtrip_write_read() {
        let path = std::env::temp_dir().join(format!("wifilab-rainbow-test-{}", std::process::id()));
        let entries: Vec<([u8; 32], Vec<u8>)> = vec![
            ([0x11; 32], b"password1".to_vec()),
            ([0x22; 32], b"two words here".to_vec()),
            ([0x33; 32], b"a".repeat(63)),
        ];
        {
            let mut w = create(&path, "Parafin").unwrap();
            for (pmk, pass) in &entries {
                w.push(pmk, pass).unwrap();
            }
            assert_eq!(w.finish().unwrap(), 3);
        }
        let (ssid, it) = open(&path).unwrap();
        assert_eq!(ssid.as_deref(), Some("Parafin"));
        let got: Vec<_> = it.collect();
        assert_eq!(got, entries);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn headerless_table_reads_with_none_ssid() {
        let path = std::env::temp_dir().join(format!("wifilab-rainbow-hdr-{}", std::process::id()));
        std::fs::write(&path, format!("{} passw0rd\n", "cd".repeat(32))).unwrap();
        let (ssid, it) = open(&path).unwrap();
        assert_eq!(ssid, None);
        assert_eq!(it.count(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn append_open_create_vs_append() {
        let path =
            std::env::temp_dir().join(format!("wifilab-append-pmk-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        // Missing file → created WITH a header, writable.
        {
            let mut w = append_open(&path, "net1").unwrap();
            w.push(&[0x11; 32], b"password1").unwrap();
            w.finish().unwrap();
        }
        // Same SSID → appends, existing entries kept intact.
        {
            let mut w = append_open(&path, "net1").unwrap();
            w.push(&[0x22; 32], b"password2").unwrap();
            w.finish().unwrap();
        }
        let (ssid, it) = open(&path).unwrap();
        assert_eq!(ssid.as_deref(), Some("net1"));
        assert_eq!(it.count(), 2);
        // Truncated to zero bytes → treated like missing (fresh header).
        std::fs::write(&path, b"").unwrap();
        {
            let mut w = append_open(&path, "changed").unwrap();
            w.push(&[0x33; 32], b"password3").unwrap();
            w.finish().unwrap();
        }
        let (ssid, it) = open(&path).unwrap();
        assert_eq!(ssid.as_deref(), Some("changed"));
        assert_eq!(it.count(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn append_open_refuses_ssid_mismatch() {
        let path =
            std::env::temp_dir().join(format!("wifilab-append-mix-{}", std::process::id()));
        {
            let mut w = create(&path, "net1").unwrap();
            w.push(&[0x11; 32], b"password1").unwrap();
            w.finish().unwrap();
        }
        // A table for another SSID must NOT receive appends (poisoning).
        let e = append_open(&path, "othernet").err().expect("refused");
        assert!(format!("{e:#}").contains("othernet"), "{e:#}");
        // Headerless existing file: unverifiable → also refused.
        let raw = std::env::temp_dir().join(format!("wifilab-append-raw-{}", std::process::id()));
        std::fs::write(&raw, format!("{} passw0rd\n", "cd".repeat(32))).unwrap();
        assert!(append_open(&raw, "net1").is_err());
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&raw);
    }

    #[test]
    fn ssid_guard() {
        assert!(check_ssid(Some("Parafin"), "Parafin").is_ok());
        assert!(check_ssid(Some("other"), "Parafin").is_err());
        assert!(check_ssid(None, "Parafin").is_err());
    }
}
