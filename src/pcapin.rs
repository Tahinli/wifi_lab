//! libpcap capture-file importer: extracts crackable captures (4-way
//! handshakes and PMKIDs) from a `.pcap`/`.cap` file.
//!
//! Supported linktypes: 127 (`DLT_IEEE802_11_RADIO`, frames carry a
//! radiotap header that is stripped via [`crate::radiotap::strip`]) and
//! 105 (`DLT_IEEE802_11`, raw 802.11). Both byte orders of the file magic
//! are accepted; every other linktype is rejected with an error naming it.
//!
//! Two in-memory passes over the frames:
//! 1. beacons / probe-responses → bssid → essid map
//!    ([`crate::dot11::parse_beacon_or_probe`]);
//! 2. data frames → [`crate::dot11::parse_eapol`] →
//!    [`crate::dot11::parse_eapol_key`]: 4-way messages feed a
//!    [`crate::handshake::Tracker`] (essid from the pass-1 map); M1-shaped
//!    keys additionally get their `key_data` scanned for a PMKID KDE via
//!    [`crate::pmkid::extract_pmkid`].
//!
//! A capture whose AP's essid never appears in pass 1 cannot be cracked
//! (the essid is the PBKDF2 salt): it is skipped and the count is logged
//! through `tracing::warn!`.

use std::collections::BTreeMap;
use std::io::{self, ErrorKind};
use std::path::Path;

use anyhow::{bail, Context, Result};
use byteorder::{BigEndian as BE, LittleEndian as LE, ReadBytesExt};

use crate::common::{ImportedCapture, MacAddr, PmkidCapture};
use crate::dot11::{self, eapol_4way_msg, parse_eapol, parse_eapol_key};
use crate::handshake::Tracker;

const MAGIC_LE: u32 = 0xa1b2_c3d4;
const MAGIC_BE: u32 = 0xd4c3_b2a1;

/// DLT_IEEE802_11_RADIO (radiotap-prefixed) and DLT_IEEE802_11 (raw).
const LINKTYPE_RADIOTAP: u32 = 127;
const LINKTYPE_RAW_80211: u32 = 105;

/// Read the frame payloads out of a pcap file, validating the global
/// header. Timestamps and per-frame orig_len are not needed by the import
/// path, so frames come back as bare byte vectors.
pub(crate) fn frames(path: &Path) -> io::Result<(u32, Vec<Vec<u8>>)> {
    let buf = std::fs::read(path)?;
    if buf.len() < 24 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "pcap: file smaller than the 24-byte global header",
        ));
    }
    let mut cur = io::Cursor::new(&buf[..]);
    let magic = cur.read_u32::<LE>()?;
    let big_endian = match magic {
        MAGIC_LE => false,
        MAGIC_BE => true,
        _ => {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("pcap: bad magic 0x{magic:08x}"),
            ))
        }
    };
    macro_rules! read_u16 {
        ($c:expr) => {
            if big_endian { $c.read_u16::<BE>() } else { $c.read_u16::<LE>() }
        };
    }
    macro_rules! read_u32 {
        ($c:expr) => {
            if big_endian { $c.read_u32::<BE>() } else { $c.read_u32::<LE>() }
        };
    }
    let _version_major = read_u16!(&mut cur)?;
    let _version_minor = read_u16!(&mut cur)?;
    cur.set_position(16);
    let _snaplen = read_u32!(&mut cur)?;
    let linktype = read_u32!(&mut cur)?;

    let mut out = Vec::new();
    loop {
        let pos = cur.position() as usize;
        if buf.len() - pos < 16 {
            break; // clean EOF or trailing partial record header
        }
        let _ts_sec = read_u32!(&mut cur)?;
        let _ts_usec = read_u32!(&mut cur)?;
        let incl_len = read_u32!(&mut cur)? as usize;
        let _orig_len = read_u32!(&mut cur)?;
        let start = cur.position() as usize;
        let end = start.saturating_add(incl_len);
        if end > buf.len() {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                format!("pcap: packet at offset {pos} truncated ({incl_len} bytes declared)"),
            ));
        }
        out.push(buf[start..end].to_vec());
        cur.set_position(end as u64);
    }
    Ok((linktype, out))
}

/// Extract crackable captures from a pcap file (linktype 127 radiotap or
/// 105 raw 802.11). Returns handshakes completed by the on-wire replay
/// rules and PMKIDs found in M1 key-data. Captures whose AP essid is not
/// resolvable from the file's beacons/probe-responses are skipped (a
/// `tracing::warn!` reports the count).
pub fn extract(path: &Path) -> Result<Vec<ImportedCapture>> {
    let (linktype, raw_frames) =
        frames(path).with_context(|| format!("reading pcap {}", path.display()))?;
    if linktype != LINKTYPE_RADIOTAP && linktype != LINKTYPE_RAW_80211 {
        bail!(
            "pcap {}: unsupported linktype {linktype} (need 127 radiotap or 105 raw 802.11)",
            path.display()
        );
    }

    // Strip the radiotap prefix where the linktype demands it.
    let mut dot11_frames: Vec<&[u8]> = Vec::with_capacity(raw_frames.len());
    let mut strip_failures = 0u32;
    for f in &raw_frames {
        if linktype == LINKTYPE_RADIOTAP {
            match crate::radiotap::strip(f) {
                Some((_meta, body)) => dot11_frames.push(body),
                None => strip_failures += 1,
            }
        } else {
            dot11_frames.push(f);
        }
    }
    if strip_failures > 0 {
        tracing::warn!("pcap import: {strip_failures} frames with malformed radiotap headers skipped");
    }

    // Pass 1: bssid → essid map from beacons and probe responses.
    let mut essids: BTreeMap<MacAddr, String> = BTreeMap::new();
    for f in &dot11_frames {
        if let Some(info) = dot11::parse_beacon_or_probe(f) {
            if let Some(ssid) = info.ssid {
                if !ssid.is_empty() {
                    essids.entry(info.bssid).or_insert(ssid);
                }
            }
        }
    }

    // Pass 2: EAPOL through the handshake tracker + PMKID KDE scan.
    let (tx, rx) = crossbeam_channel::unbounded();
    let mut tracker = Tracker::new();
    let mut captures: Vec<ImportedCapture> = Vec::new();
    let mut skipped_no_essid = 0u32;
    for f in &dot11_frames {
        let Some((bssid, ap_sender, eapol)) = parse_eapol(f) else {
            continue;
        };
        let Some(key) = parse_eapol_key(eapol) else {
            continue;
        };
        if eapol_4way_msg(&key) == 0 {
            continue;
        }
        let Some((sta_ap, sta)) = dot11::data_endpoints(f) else {
            continue;
        };
        debug_assert_eq!(sta_ap, bssid);
        let essid = essids.get(&bssid).cloned().unwrap_or_default();
        if essid.is_empty() {
            // Track lightly but nothing crackable can come out; count the
            // skip once a completion/PMKID actually appears below.
        }
        // PMKID lives in the M1 key-data (AP → station message).
        if ap_sender && eapol_4way_msg(&key) == 1 {
            if let Some(pmkid) = crate::pmkid::extract_pmkid(key.key_data) {
                if essid.is_empty() {
                    skipped_no_essid += 1;
                } else {
                    captures.push(ImportedCapture::Pmkid(PmkidCapture {
                        ap: bssid,
                        client: sta,
                        essid: essid.clone(),
                        pmkid,
                    }));
                }
            }
        }
        if let Some(cap) = tracker.ingest(bssid, sta, &essid, &key, &tx) {
            captures.push(ImportedCapture::Handshake(Box::new(cap)));
        }
    }
    // Drain progress events; the tracker still emits them for state
    // consistency but the importer has no UI to notify.
    while rx.try_recv().is_ok() {}
    if skipped_no_essid > 0 {
        tracing::warn!(
            "pcap import: {skipped_no_essid} PMKID capture(s) skipped — AP essid not resolvable from the file"
        );
    }
    Ok(captures)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcapout::{self, PcapWriter};
    use byteorder::{LittleEndian as LE, WriteBytesExt};

    fn mac(bytes: [u8; 6]) -> MacAddr {
        MacAddr(bytes)
    }

    const BSSID: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    const CLIENT: [u8; 6] = [0x66, 0x55, 0x44, 0x33, 0x22, 0x11];

    #[test]
    fn pcap_roundtrip_frame_bytes() {
        let dir = std::env::temp_dir().join(format!(
            "wifilab-pcapin-test-{}-roundtrip",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("roundtrip.pcap");
        let frames_in: Vec<Vec<u8>> = vec![
            b"fake frame one".to_vec(),
            vec![0, 1, 2, 3, 250, 251, 252, 253],
            vec![0xaa; 100],
        ];
        {
            let mut w: PcapWriter = pcapout::create(&path).unwrap();
            for f in &frames_in {
                w.append(f).unwrap();
            }
            w.finish().unwrap();
        }
        let (linktype, frames_out) = frames(&path).unwrap();
        assert_eq!(linktype, 127);
        assert_eq!(frames_out, frames_in);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn extract_rejects_ethernet_linktype() {
        let dir = std::env::temp_dir().join(format!(
            "wifilab-pcapin-test-{}-linktype",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("eth.pcap");
        let mut buf: Vec<u8> = Vec::new();
        buf.write_u32::<LE>(MAGIC_LE).unwrap();
        buf.write_u16::<LE>(2).unwrap();
        buf.write_u16::<LE>(4).unwrap();
        buf.write_i32::<LE>(0).unwrap();
        buf.write_u32::<LE>(0).unwrap();
        buf.write_u32::<LE>(65535).unwrap();
        buf.write_u32::<LE>(1).unwrap(); // DLT_EN10MB
        std::fs::write(&path, &buf).unwrap();
        let err = extract(&path).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("linktype 1"),
            "error must name the linktype: {msg}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Minimal 8-byte radiotap header (version 0, len 8, no fields) — the
    /// spool file declares linktype 127, so every frame is radiotap-prefixed
    /// exactly as it is when the scanner writes what the raw socket read.
    const RADIOTAP_HDR: [u8; 8] = [0x00, 0x00, 0x08, 0x00, 0, 0, 0, 0];

    fn radiotap_wrap(frame: Vec<u8>) -> Vec<u8> {
        let mut v = RADIOTAP_HDR.to_vec();
        v.extend_from_slice(&frame);
        v
    }

    /// 802.11 beacon for `BSSID` advertising essid "testap" (no security IEs).
    fn test_beacon() -> Vec<u8> {
        let mut v = Vec::new();
        // fc: type 0 subtype 8 (beacon)
        v.extend_from_slice(&[0x80, 0x00]);
        v.extend_from_slice(&[0x00, 0x00]); // duration
        v.extend_from_slice(&MacAddr::BROADCAST.0); // addr1
        v.extend_from_slice(&BSSID); // addr2 transmitter
        v.extend_from_slice(&BSSID); // addr3 bssid
        v.extend_from_slice(&[0x00, 0x00]); // seq
        v.extend_from_slice(&[0x00; 8]); // timestamp
        v.extend_from_slice(&100u16.to_le_bytes()); // interval
        v.extend_from_slice(&[0x01, 0x04]); // capability (ESS)
        v.extend_from_slice(&[0x00, 0x06]); // SSID IE
        v.extend_from_slice(b"testap");
        v
    }

    /// EAPOL-Key frame bytes (starting at the EAPOL version byte).
    /// m1: ack set, mic flag clear; m2: mic flag set, ack clear.
    fn eapol_key(m1: bool, replay: u64, nonce: [u8; 32], mic: [u8; 16]) -> Vec<u8> {
        let mut v = Vec::with_capacity(99);
        v.push(2); // eapol version
        v.push(3); // type: EAPOL-Key
        v.extend_from_slice(&95u16.to_be_bytes()); // length of key descriptor
        v.push(2); // descriptor type: RSN key
        let mut key_info: u16 = 0x0002; // key_ver 2 (AES), kept small
        if m1 {
            key_info |= 1 << 7; // key_ack
        } else {
            key_info |= 1 << 8; // key_mic
        }
        v.extend_from_slice(&key_info.to_be_bytes());
        v.extend_from_slice(&16u16.to_be_bytes()); // key length
        v.extend_from_slice(&replay.to_be_bytes());
        v.extend_from_slice(&nonce);
        v.extend_from_slice(&[0; 16]); // iv
        v.extend_from_slice(&[0; 8]); // rsc
        v.extend_from_slice(&[0; 8]); // id
        v.extend_from_slice(&mic);
        v.extend_from_slice(&0u16.to_be_bytes()); // key_data_len
        v
    }

    /// Full 802.11 data frame (24-byte header) carrying an EAPOL-Key.
    /// `from_ap`: AP → station (FromDS) vs station → AP (ToDS).
    fn build_eapol_frame(from_ap: bool, eapol: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        // fc: type 2 subtype 0 (data); ToDS / FromDS.
        let fc: u16 = if from_ap { 0x0208 } else { 0x0108 };
        v.extend_from_slice(&fc.to_le_bytes());
        v.extend_from_slice(&[0x00, 0x00]); // duration
        if from_ap {
            v.extend_from_slice(&CLIENT); // addr1 = station
            v.extend_from_slice(&BSSID); // addr2 = bssid
            v.extend_from_slice(&BSSID); // addr3
        } else {
            v.extend_from_slice(&BSSID); // addr1 = bssid
            v.extend_from_slice(&CLIENT); // addr2 = station
            v.extend_from_slice(&BSSID); // addr3
        }
        v.extend_from_slice(&[0x10, 0x00]); // seq
        v.extend_from_slice(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e]); // LLC SNAP EAPOL
        v.extend_from_slice(eapol);
        v
    }

    #[test]
    fn extract_imports_handshake_e2e() {
        let dir = std::env::temp_dir().join(format!(
            "wifilab-pcapin-test-{}-e2e",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("import.pcap");

        let mut anonce = [0u8; 32];
        anonce[0] = 0xaa;
        let mut snonce = [0u8; 32];
        snonce[0] = 0xbb;
        let mut mic = [0u8; 16];
        mic[0] = 0xcc;

        let frames = vec![
            radiotap_wrap(test_beacon()),
            radiotap_wrap(build_eapol_frame(true, &eapol_key(true, 7, anonce, [0; 16]))),
            radiotap_wrap(build_eapol_frame(false, &eapol_key(false, 8, snonce, mic))),
        ];
        {
            let mut w = pcapout::create(&path).unwrap();
            for f in &frames {
                w.append(f).unwrap();
            }
            w.finish().unwrap();
        }

        let caps = extract(&path).unwrap();
        assert_eq!(caps.len(), 1, "expected exactly one capture, got {caps:?}");
        match &caps[0] {
            ImportedCapture::Handshake(h) => {
                assert_eq!(h.ap, mac(BSSID));
                assert_eq!(h.client, mac(CLIENT));
                assert_eq!(h.essid, "testap");
                assert_eq!(h.anonce, anonce);
                assert_eq!(h.snonce, snonce);
            }
            other => panic!("expected handshake capture, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn extract_skips_handshake_without_essid() {
        let dir = std::env::temp_dir().join(format!(
            "wifilab-pcapin-test-{}-noessid",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("noessid.pcap");
        let mut anonce = [0u8; 32];
        anonce[0] = 0xaa;
        let mut snonce = [0u8; 32];
        snonce[0] = 0xbb;
        let mut mic = [0u8; 16];
        mic[0] = 0xcc;
        // No beacon in the file → essid unresolvable → no capture.
        let frames = vec![
            radiotap_wrap(build_eapol_frame(true, &eapol_key(true, 1, anonce, [0; 16]))),
            radiotap_wrap(build_eapol_frame(false, &eapol_key(false, 2, snonce, mic))),
        ];
        {
            let mut w = pcapout::create(&path).unwrap();
            for f in &frames {
                w.append(f).unwrap();
            }
            w.finish().unwrap();
        }
        let caps = extract(&path).unwrap();
        assert!(caps.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
