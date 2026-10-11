//! Streaming wordlist reader: line-oriented, bytes-accurate, filters to the
//! WPA passphrase length range 8..=63 bytes.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};

struct WordIter {
    lines: std::io::Lines<BufReader<File>>,
}

impl Iterator for WordIter {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Vec<u8>> {
        loop {
            let line = match self.lines.next()? {
                Ok(l) => l,
                // Unreadable line (bad UTF-8 etc.): skip it, keep streaming.
                Err(_) => continue,
            };
            let bytes = line.into_bytes();
            if (8..=63).contains(&bytes.len()) {
                return Some(bytes);
            }
        }
    }
}

/// Count lines without parsing: byte-scan for `\n` in 8 MiB chunks
/// (fast even on multi-GB lists — the cracker's worst-case candidate
/// total). A final line without trailing newline counts too.
pub fn line_count(path: &Path) -> Result<u64> {
    use std::io::Read;

    let mut f = File::open(path)
        .with_context(|| format!("counting lines of {}", path.display()))?;
    let mut buf = vec![0u8; 1 << 23];
    let mut count = 0u64;
    let mut any = false;
    let mut ended_with_nl = true;
    loop {
        let n = f
            .read(&mut buf)
            .with_context(|| format!("counting lines of {}", path.display()))?;
        if n == 0 {
            break;
        }
        any = true;
        ended_with_nl = buf[n - 1] == b'\n';
        count += buf[..n].iter().filter(|&&b| b == b'\n').count() as u64;
    }
    if any && !ended_with_nl {
        count += 1;
    }
    Ok(count)
}

/// Open a wordlist file as a streaming iterator of passphrase candidates.
///
/// Lines are trimmed of `\r\n` only (no whitespace trimming), and only
/// candidates of 8..=63 *bytes* are yielded. The iterator is `Send` and does
/// not load the file into memory.
pub fn open(path: &Path) -> Result<Box<dyn Iterator<Item = Vec<u8>> + Send>> {
    let f = File::open(path)
        .with_context(|| format!("opening wordlist {}", path.display()))?;
    let reader = BufReader::with_capacity(1 << 20, f);
    Ok(Box::new(WordIter {
        lines: reader.lines(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn filters_and_trims() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("wifilab-wordlist-test-{}", std::process::id()));
        {
            let mut f = File::create(&path).unwrap();
            // too short, ok, crlf ok, trailing space kept (too short when
            // counted), exactly 8, exactly 63, 64 too long, empty line.
            writeln!(f, "short").unwrap();
            writeln!(f, "sup3r-secret").unwrap();
            f.write_all(b"crlf-pass\r\n").unwrap();
            writeln!(f, "eight88 ").unwrap();
            writeln!(f, "eight888").unwrap();
            writeln!(f, "{}", "a".repeat(63)).unwrap();
            writeln!(f, "{}", "b".repeat(64)).unwrap();
            f.write_all(b"\n").unwrap();
        }
        let mut it = open(&path).unwrap();
        let got: Vec<Vec<u8>> = std::iter::from_fn(|| it.next()).collect();
        // "eight88 " keeps its trailing space: only \r\n is trimmed.
        assert_eq!(
            got,
            vec![
                b"sup3r-secret".to_vec(),
                b"crlf-pass".to_vec(),
                b"eight88 ".to_vec(),
                b"eight888".to_vec(),
                "a".repeat(63).into_bytes(),
            ]
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_errors() {
        assert!(open(Path::new("/definitely/not/here.lst")).is_err());
    }

    #[test]
    fn line_count_edges() {
        let dir = std::env::temp_dir();
        for (name, bytes, want) in [
            ("empty", &b""[..], 0u64),
            ("one-no-nl", b"abc", 1),
            ("one-nl", b"abc\n", 1),
            ("two", b"abc\ndef\n", 2),
            ("trailing-nl-only", b"\n", 1),
            ("crlf", b"a\r\nb\r\n", 2),
        ] {
            let path = dir.join(format!("wifilab-lc-{name}-{}", std::process::id()));
            std::fs::write(&path, bytes).unwrap();
            assert_eq!(line_count(&path).unwrap(), want, "{name}");
            let _ = std::fs::remove_file(&path);
        }
    }
}
