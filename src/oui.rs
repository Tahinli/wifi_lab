//! OUI vendor lookup for MAC prefixes.
//!
//! Three checked-in snapshot tables from IEEE registries (provenance and
//! update semantics in docs/CONTRACT.md `## oui.rs`):
//! - `src/data/oui.txt`   — MA-L 24-bit  (`AABBCC|Vendor`,  6 hex chars)
//! - `src/data/oui28.txt` — MA-M 28-bit  (`AABBCCD|Vendor`, 7 hex chars)
//! - `src/data/oui36.txt` — MA-S 36-bit  (`AABBCCDEE|Vendor`, 9 hex chars)
//!
//! Vendors (= short name, ≤32 chars) are byte-sorted and unique per file.
//! Lookup is longest-prefix-first: MA-S (36) → MA-M (28) → MA-L (24), since
//! the sub-assignments sit under someone else's MA-L base.

use std::sync::LazyLock;

use crate::common::MacAddr;

fn parse24(src: &'static str) -> Vec<(u32, &'static str)> {
    src.lines()
        .filter_map(|line| {
            let (hex, name) = line.split_once('|')?;
            let key = u32::from_str_radix(hex.trim(), 16).ok()?;
            (!name.is_empty()).then_some((key, name))
        })
        .collect()
}

/// Parsed `(prefix, vendor)` pairs from `data/oui.txt` (24-bit MA-L).
static TABLE24: LazyLock<Vec<(u32, &'static str)>> = LazyLock::new(|| parse24(include_str!("data/oui.txt")));
/// MA-M 28-bit sub-assignments.
static TABLE28: LazyLock<Vec<(u32, &'static str)>> = LazyLock::new(|| parse24(include_str!("data/oui28.txt")));
/// MA-S 36-bit sub-assignments.
static TABLE36: LazyLock<Vec<(u64, &'static str)>> = LazyLock::new(|| {
    include_str!("data/oui36.txt")
        .lines()
        .filter_map(|line| {
            let (hex, name) = line.split_once('|')?;
            let key = u64::from_str_radix(hex.trim(), 16).ok()?;
            (!name.is_empty()).then_some((key, name))
        })
        .collect()
});

/// True for locally administered MACs (U/L bit set, wire byte order): the
/// randomized/rotated addresses modern phones and laptops send. These have
/// no IEEE vendor — `lookup` returns None for them by design.
pub fn is_locally_administered(mac: &MacAddr) -> bool {
    mac.0[0] & 0x02 != 0
}

/// Vendor for a MAC's prefix; None for locally-administered/unknown
/// prefixes (see `is_locally_administered`).
pub fn lookup(mac: &MacAddr) -> Option<&'static str> {
    if is_locally_administered(mac) {
        return None;
    }
    let m = mac.0;
    let key36 = ((m[0] as u64) << 28)
        | ((m[1] as u64) << 20)
        | ((m[2] as u64) << 12)
        | ((m[3] as u64) << 4)
        | (m[4] >> 4) as u64;
    let t36 = &*TABLE36;
    if let Ok(i) = t36.binary_search_by_key(&key36, |&(k, _)| k) {
        return Some(t36[i].1);
    }
    let key28 = ((m[0] as u32) << 20) | ((m[1] as u32) << 12) | ((m[2] as u32) << 4) | (m[3] >> 4) as u32;
    let t28 = &*TABLE28;
    if let Ok(i) = t28.binary_search_by_key(&key28, |&(k, _)| k) {
        return Some(t28[i].1);
    }
    let key24 = ((m[0] as u32) << 16) | ((m[1] as u32) << 8) | m[2] as u32;
    let t24 = &*TABLE24;
    t24.binary_search_by_key(&key24, |&(k, _)| k)
        .ok()
        .map(|i| t24[i].1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(b: [u8; 6]) -> MacAddr {
        MacAddr(b)
    }

    #[test]
    fn tables_are_populated_and_sorted() {
        let t = &*TABLE24;
        assert!(t.len() > 10_000, "expected a real MA-L snapshot, got {}", t.len());
        assert!(t.windows(2).all(|w| w[0].0 < w[1].0), "MA-L must be sorted+unique");
        let t = &*TABLE28;
        assert!(t.len() > 1_000, "expected a real MA-M snapshot, got {}", t.len());
        assert!(t.windows(2).all(|w| w[0].0 < w[1].0), "MA-M must be sorted+unique");
        let t = &*TABLE36;
        assert!(t.len() > 1_000, "expected a real MA-S snapshot, got {}", t.len());
        assert!(t.windows(2).all(|w| w[0] .0 < w[1].0), "MA-S must be sorted+unique");
    }

    #[test]
    fn locally_administered_is_none() {
        assert!(is_locally_administered(&mac([0x02, 0, 0, 0, 0, 0])));
        assert!(!is_locally_administered(&mac([0x00, 0, 0, 0, 0, 0])));
        assert_eq!(lookup(&mac([0x02, 0, 0, 0, 0, 0])), None);
    }

    #[test]
    fn multicast_but_globally_unique_still_resolves() {
        // 01:00:5e… is multicast but not locally administered; resolve per tables.
        let key_ok = TABLE24.iter().any(|&(k, _)| k == 0x01005E)
            || TABLE36.iter().any(|&(k, _)| k == 0x01005E000)
            || TABLE28.iter().any(|&(k, _)| k == 0x01005E0);
        let got = lookup(&mac([0x01, 0x00, 0x5e, 0, 0, 1]));
        assert_eq!(got.is_some(), key_ok);
    }

    #[test]
    fn pinned_prefix_cisco() {
        // Pinned from the actual checked-in snapshot: 00000C|Cisco Systems, Inc
        assert_eq!(
            lookup(&mac([0x00, 0x00, 0x0c, 0xab, 0xcd, 0xef])),
            Some("Cisco Systems, Inc")
        );
    }

    #[test]
    fn pinned_mam_prefix_siretta() {
        // 28-bit MA-M: FCE498C|Siretta Ltd — matches any MAC FC:E4:98:CX….
        assert_eq!(
            lookup(&mac([0xfc, 0xe4, 0x98, 0xc7, 0x12, 0x34])),
            Some("Siretta Ltd")
        );
    }

    #[test]
    fn pinned_mas_prefix_converging() {
        // 36-bit MA-S: 001BC5000|Converging Systems Inc. — matches
        // 00:1B:C5:00:0x:…, and outranks the 24-bit 001BC5 base entry.
        assert_eq!(
            lookup(&mac([0x00, 0x1b, 0xc5, 0x00, 0x05, 0xaa])),
            Some("Converging Systems Inc.")
        );
    }
}
