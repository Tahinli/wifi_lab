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
}
