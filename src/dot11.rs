//! 802.11 MAC frame parsing and building.
//!
//! Zero-copy where possible; all reads are bounds-checked through `get`.
//! Frames here never carry an FCS (the driver appends it on TX, and monitor
//! captures may or may not include one — parsers simply ignore trailing
//! bytes beyond what they need).

use crate::common::{MacAddr, Security};

/// LLC/SNAP header prefixing an EAPOL payload inside a data frame.
const SNAP_EAPOL: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e];

const IE_SSID: u8 = 0;
const IE_DS_PARAM: u8 = 3;
const IE_RSN: u8 = 48;
const IE_VENDOR: u8 = 221;

/// Microsoft (WPA) vendor IE OUI+type prefix.
const WPA_OUI: [u8; 4] = [0x00, 0x50, 0xf2, 0x01];

const CAP_PRIVACY: u16 = 0x0010;

/// Duration value used on injected management frames.
pub const INJECT_DURATION: u16 = 314;

// ---------------------------------------------------------------------------
// little helpers (all bounds-checked)
// ---------------------------------------------------------------------------

fn u16le(f: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(f.get(o..o + 2)?.try_into().ok()?))
}

fn mac_at(f: &[u8], o: usize) -> Option<MacAddr> {
    Some(MacAddr(f.get(o..o + 6)?.try_into().ok()?))
}

/// (type, subtype) from the frame-control field.
fn type_subtype(fc: u16) -> (u16, u16) {
    ((fc >> 2) & 3, (fc >> 4) & 0xf)
}

/// Walk information elements starting at `cur`, invoking `f(id, body)`.
/// Stops cleanly on a truncated trailing IE.
fn walk_ies<T>(f: &[u8], mut cur: usize, mut cb: T)
where
    T: FnMut(u8, &[u8]),
{
    while let Some(body_len) = f.get(cur + 1).map(|&l| l as usize) {
        let Some(body) = f.get(cur + 2..cur + 2 + body_len) else {
            break;
        };
        cb(f[cur], body);
        cur += 2 + body_len;
    }
}

// ---------------------------------------------------------------------------
// parsed metadata
// ---------------------------------------------------------------------------

pub struct MgmtInfo {
    pub bssid: MacAddr,
    pub transmitter: MacAddr, // addr2
    pub ssid: Option<String>, // None if hidden/zero-len
    pub channel: Option<u8>,  // DS parameter set IE
    pub security: Security,   // from RSN/WPA IEs + capability privacy bit
}

/// True if the RSN IE body lists AKM suite 00:0f:ac:8 (SAE → WPA3).
fn rsn_has_akm(body: &[u8], akm_type: u8) -> bool {
    // layout: version(2) group(4) pairwise_cnt(2) pairwise[4n]
    //         akm_cnt(2) akm[4m] ...
    let Some(pair_cnt) = u16le(body, 6).map(|c| c as usize) else {
        return false;
    };
    let mut o = 8usize + 4 * pair_cnt;
    let Some(akm_cnt) = u16le(body, o).map(|c| c as usize) else {
        return false;
    };
    o += 2;
    for i in 0..akm_cnt {
        let Some(suite) = body.get(o + 4 * i..o + 4 * i + 4) else {
            break;
        };
        if suite[0] == 0x00 && suite[1] == 0x0f && suite[2] == 0xac && suite[3] == akm_type {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// management frame parsers
// ---------------------------------------------------------------------------

/// Parse beacon OR probe-response; None for other/broken frames.
pub fn parse_beacon_or_probe(f: &[u8]) -> Option<MgmtInfo> {
    let fc = u16le(f, 0)?;
    let (ty, st) = type_subtype(fc);
    if ty != 0 || (st != 8 && st != 5) {
        return None;
    }
    // fixed params: timestamp(8) interval(2) capability(2) after 24B header
    let cap = u16le(f, 34)?;

    let mut ssid = None;
    let mut channel = None;
    let mut has_rsn = false;
    let mut has_sae = false;
    let mut has_wpa = false;
    walk_ies(f, 36, |id, body| match id {
        IE_SSID => {
            if !body.is_empty() {
                ssid = Some(String::from_utf8_lossy(body).into_owned());
            }
        }
        IE_DS_PARAM => {
            channel = body.first().copied();
        }
        IE_RSN => {
            has_rsn = true;
            has_sae |= rsn_has_akm(body, 8);
        }
        IE_VENDOR => {
            if body.len() >= 4 && body[..4] == WPA_OUI {
                has_wpa = true;
            }
        }
        _ => {}
    });

    let security = if has_rsn {
        if has_sae { Security::Wpa3 } else { Security::Wpa2 }
    } else if has_wpa {
        Security::Wpa
    } else if cap & CAP_PRIVACY != 0 {
        Security::Wep
    } else {
        Security::Open
    };

    Some(MgmtInfo {
        bssid: mac_at(f, 16)?,
        transmitter: mac_at(f, 10)?,
        ssid,
        channel,
        security,
    })
}

/// Parse probe-request → Some((sta, ssid of probe)); None on broadcast
/// (zero-len SSID) yields `(sta, None)`. Non-probe frames → None.
pub fn parse_probe_req(f: &[u8]) -> Option<(MacAddr, Option<String>)> {
    let fc = u16le(f, 0)?;
    if type_subtype(fc) != (0, 4) {
        return None;
    }
    let sta = mac_at(f, 10)?;
    let mut ssid = None;
    walk_ies(f, 24, |id, body| {
        if id == IE_SSID && !body.is_empty() {
            ssid = Some(String::from_utf8_lossy(body).into_owned());
        }
    });
    if f.len() < 24 {
        return None;
    }
    Some((sta, ssid))
}

/// Parse deauth/disassoc → (from-ap MacAddr as transmitter, target addr1).
pub fn parse_deauth(f: &[u8]) -> Option<(MacAddr, MacAddr)> {
    let fc = u16le(f, 0)?;
    let (ty, st) = type_subtype(fc);
    if ty != 0 || (st != 12 && st != 10) {
        return None;
    }
    Some((mac_at(f, 10)?, mac_at(f, 4)?))
}

// ---------------------------------------------------------------------------
// data frames
// ---------------------------------------------------------------------------

/// Header length of a data frame: 24 base, +6 for addr4 in WDS
/// (ToDS && FromDS), +2 for QoS control on QoS data subtypes.
fn data_hdr_len(fc: u16) -> usize {
    let mut n = 24;
    if fc & 0x0100 != 0 && fc & 0x0200 != 0 {
        n += 6; // addr4 (WDS)
    }
    if fc & 0x0080 != 0 {
        n += 2; // QoS control
    }
    n
}

/// Extract (bssid, station) that best describes a data frame's endpoints
/// using ToDS/FromDS bits. None for mgmt/ctrl frames.
pub fn data_endpoints(f: &[u8]) -> Option<(MacAddr, MacAddr)> {
    let fc = u16le(f, 0)?;
    if type_subtype(fc).0 != 2 {
        return None;
    }
    let to_ds = fc & 0x0100 != 0;
    let from_ds = fc & 0x0200 != 0;
    Some(match (to_ds, from_ds) {
        // IBSS / ad-hoc: bssid in addr3, station is the transmitter.
        (false, false) => (mac_at(f, 16)?, mac_at(f, 10)?),
        // AP → STA: bssid is addr2, station is addr1.
        (false, true) => (mac_at(f, 10)?, mac_at(f, 4)?),
        // STA → AP: bssid is addr1, station is addr2.
        (true, false) => (mac_at(f, 4)?, mac_at(f, 10)?),
        // WDS: addr1=RA, addr2=TA, addr4=SA.
        (true, true) => (mac_at(f, 10)?, mac_at(f, 24)?),
    })
}

/// If frame carries an EAPOL-Key payload (LLC/SNAP 88-8e in a data frame),
/// return (bssid, station_is_ap_sender, eapol_bytes).
pub fn parse_eapol(f: &[u8]) -> Option<(MacAddr, bool, &[u8])> {
    let fc = u16le(f, 0)?;
    if type_subtype(fc).0 != 2 {
        return None;
    }
    let to_ds = fc & 0x0100 != 0;
    let from_ds = fc & 0x0200 != 0;
    let hdr = data_hdr_len(fc);
    if *f.get(hdr..hdr + 8)? != SNAP_EAPOL {
        return None;
    }
    let eapol = f.get(hdr + 8..)?;
    let (bssid, ap_sender) = match (to_ds, from_ds) {
        (false, false) => (mac_at(f, 16)?, false),
        (false, true) => (mac_at(f, 10)?, true),
        (true, false) => (mac_at(f, 4)?, false),
        (true, true) => (mac_at(f, 10)?, true),
    };
    Some((bssid, ap_sender, eapol))
}

// ---------------------------------------------------------------------------
// EAPOL-Key
// ---------------------------------------------------------------------------

pub struct EapolKey<'a> {
    pub key_info: u16, // raw key info field (BE order as on wire)
    pub key_ver: u8,   // bits 0..3 of key_info (descriptor version)
    pub install: bool, // bit6
    pub key_ack: bool, // bit7
    pub key_mic: bool, // bit8
    pub secure: bool,  // bit9
    pub replay_counter: u64,
    pub nonce: [u8; 32],
    pub mic: [u8; 16], // raw mic field (or RSN IE scan for pmkid)
    pub key_data: &'a [u8], // RSN IE / KDEs (PMKID: 00-0f-ac:4)
    pub raw: &'a [u8],  // full eapol frame starting at version byte
}

/// Parse an EAPOL-Key frame. Frame offsets (descriptor body starts at 4):
/// key_info 5..7, replay 9..17, nonce 17..49, iv 49..65, rsc 65..73,
/// id 73..81, mic 81..97, key_data_len 97..99, key_data 99..
pub fn parse_eapol_key(eapol: &[u8]) -> Option<EapolKey<'_>> {
    // eapol header(4) + 95-byte key descriptor fixed part = 99 minimum
    if eapol.len() < 99 {
        return None;
    }
    if eapol[1] != 3 {
        return None; // not an EAPOL-Key packet
    }
    let key_info = u16::from_be_bytes([eapol[5], eapol[6]]);
    let key_data_len = u16::from_be_bytes([eapol[97], eapol[98]]) as usize;
    let key_data = &eapol[99..eapol.len().min(99 + key_data_len)];
    Some(EapolKey {
        key_info,
        key_ver: (key_info & 0x7) as u8,
        install: key_info & (1 << 6) != 0,
        key_ack: key_info & (1 << 7) != 0,
        key_mic: key_info & (1 << 8) != 0,
        secure: key_info & (1 << 9) != 0,
        replay_counter: u64::from_be_bytes(eapol[9..17].try_into().ok()?),
        nonce: eapol[17..49].try_into().ok()?,
        mic: eapol[81..97].try_into().ok()?,
        key_data,
        raw: eapol,
    })
}

/// 1..=4 4way message number derived from flags, 0 if not an EAPOL-Key.
pub fn eapol_4way_msg(k: &EapolKey) -> u8 {
    // descriptor type 2 = RSN key, 254 = legacy WPA key
    if !(k.raw.len() > 4 && (k.raw[4] == 2 || k.raw[4] == 254)) {
        return 0;
    }
    if k.key_ack && !k.key_mic {
        1 // M1: ack, no mic
    } else if k.key_ack && k.key_mic && k.install {
        3 // M3: ack+mic+install
    } else if !k.key_ack && k.key_mic && k.secure {
        4 // M4: mic+secure, no ack
    } else if !k.key_ack && k.key_mic && !k.secure {
        2 // M2: mic, no ack, not secure yet
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// frame builders (full 802.11 frame, NO radiotap — caller prepends INJECT_HDR)
// ---------------------------------------------------------------------------

fn hdr3(fc_lo: u8, addr1: &MacAddr, addr2: &MacAddr, addr3: &MacAddr, seq: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(24);
    v.extend_from_slice(&[fc_lo, 0x00]);
    v.extend_from_slice(&INJECT_DURATION.to_le_bytes());
    v.extend_from_slice(&addr1.0);
    v.extend_from_slice(&addr2.0);
    v.extend_from_slice(&addr3.0);
    v.extend_from_slice(&(seq << 4).to_le_bytes()); // seq control: seq in bits 4..16
    v
}

pub fn build_deauth(ap: &MacAddr, target: &MacAddr, reason: u16) -> Vec<u8> {
    let mut v = hdr3(0xC0, target, ap, ap, 0);
    v.extend_from_slice(&reason.to_le_bytes());
    v
}

pub fn build_disassoc(ap: &MacAddr, target: &MacAddr, reason: u16) -> Vec<u8> {
    let mut v = hdr3(0xA0, target, ap, ap, 0);
    v.extend_from_slice(&reason.to_le_bytes());
    v
}

/// Open-system authentication request sta → ap (algo 0, transaction 1).
pub fn build_auth_open(ap: &MacAddr, sta: &MacAddr, seq: u16) -> Vec<u8> {
    let mut v = hdr3(0xB0, ap, sta, ap, seq);
    v.extend_from_slice(&0u16.to_le_bytes()); // auth algorithm: open system
    v.extend_from_slice(&1u16.to_le_bytes()); // transaction sequence
    v.extend_from_slice(&0u16.to_le_bytes()); // status
    v
}

/// Association request sta → ap: capability + listen interval + SSID IE.
pub fn build_assoc_req(ap: &MacAddr, sta: &MacAddr, ssid: &[u8]) -> Vec<u8> {
    let mut v = hdr3(0x00, ap, sta, ap, 0);
    v.extend_from_slice(&0x0431u16.to_le_bytes()); // capability (ESS | short preamble ...)
    v.extend_from_slice(&10u16.to_le_bytes()); // listen interval
    v.push(IE_SSID);
    v.push(ssid.len().min(32) as u8);
    v.extend_from_slice(&ssid[..ssid.len().min(32)]);
    v
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const AP: MacAddr = MacAddr([0x24, 0x65, 0x11, 0xaa, 0xbb, 0xcc]);
    const STA: MacAddr = MacAddr([0x9c, 0xef, 0xd5, 0x11, 0x22, 0x33]);

    fn ie(id: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![id, body.len() as u8];
        v.extend_from_slice(body);
        v
    }

    fn rsn_ie(akm_type: u8) -> Vec<u8> {
        // version 1, group CCMP, 1×pairwise CCMP, 1×AKM, rsn caps 0
        let mut b = vec![
            0x01, 0x00, // version
            0x00, 0x0f, 0xac, 0x04, // group cipher CCMP
            0x01, 0x00, // pairwise count
            0x00, 0x0f, 0xac, 0x04, // pairwise CCMP
            0x01, 0x00, // akm count
            0x00, 0x0f, 0xac, akm_type, // PSK=2 / SAE=8
            0x00, 0x00, // rsn capabilities
        ];
        ie(IE_RSN, &b.split_off(0))
    }

    /// FCS-free beacon as it would appear after radiotap is stripped:
    /// SSID "parafin", channel 6, WPA2 (RSN, AKM PSK), privacy bit set.
    fn parafin_beacon() -> Vec<u8> {
        let mut v = vec![0x80, 0x00]; // FC: beacon
        v.extend_from_slice(&[0x00, 0x00]); // duration
        v.extend_from_slice(&MacAddr::BROADCAST.0); // addr1
        v.extend_from_slice(&AP.0); // addr2 = transmitter
        v.extend_from_slice(&AP.0); // addr3 = bssid
        v.extend_from_slice(&[0x00, 0x00]); // seq
        v.extend_from_slice(&[0x00; 8]); // timestamp
        v.extend_from_slice(&100u16.to_le_bytes()); // beacon interval
        v.extend_from_slice(&0x0411u16.to_le_bytes()); // capability: ESS | privacy | short preamble
        v.extend_from_slice(&ie(IE_SSID, b"parafin"));
        v.extend_from_slice(&ie(1, &[0x82, 0x84, 0x8b, 0x96])); // supported rates
        v.extend_from_slice(&ie(IE_DS_PARAM, &[6])); // channel 6
        v.extend_from_slice(&ie(5, &[0x00, 0x01, 0x00, 0x00])); // TIM
        v.extend_from_slice(&rsn_ie(2));
        v
    }

    #[test]
    fn parafin_beacon_parses_to_wpa2_ch6() {
        let info = parse_beacon_or_probe(&parafin_beacon()).expect("beacon parses");
        assert_eq!(info.bssid, AP);
        assert_eq!(info.transmitter, AP);
        assert_eq!(info.ssid.as_deref(), Some("parafin"));
        assert_eq!(info.channel, Some(6));
        assert_eq!(info.security, Security::Wpa2);
    }

    #[test]
    fn beacon_security_matrix() {
        // WPA3: same beacon but SAE AKM
        let mut f = parafin_beacon();
        let rsn_at = f.len() - rsn_ie(8).len();
        f.splice(rsn_at.., rsn_ie(8));
        assert_eq!(parse_beacon_or_probe(&f).unwrap().security, Security::Wpa3);

        // WPA: vendor IE, no RSN
        let mut hdr_fixed = parafin_beacon();
        hdr_fixed.truncate(36);
        hdr_fixed.extend_from_slice(&ie(IE_SSID, b"legacy"));
        hdr_fixed.extend_from_slice(&ie(IE_VENDOR, &[0x00, 0x50, 0xf2, 0x01, 0x01, 0x00]));
        assert_eq!(parse_beacon_or_probe(&hdr_fixed).unwrap().security, Security::Wpa);

        // WEP: privacy bit only
        let mut f = parafin_beacon();
        f.truncate(36);
        f.extend_from_slice(&ie(IE_SSID, b"oldnet"));
        assert_eq!(parse_beacon_or_probe(&f).unwrap().security, Security::Wep);

        // Open: clear privacy bit
        f[34] = 0x01;
        f[35] = 0x04;
        assert_eq!(parse_beacon_or_probe(&f).unwrap().security, Security::Open);
    }

    #[test]
    fn hidden_ssid_and_truncated_safe() {
        let mut f = parafin_beacon();
        // zero-length SSID IE → None (hidden)
        let ssid_at = 36;
        f.drain(ssid_at..ssid_at + 2 + 7);
        f.splice(ssid_at..ssid_at, vec![IE_SSID, 0]);
        let info = parse_beacon_or_probe(&f).unwrap();
        assert_eq!(info.ssid, None);
        assert_eq!(info.channel, Some(6));
        // truncation inside an IE: no panic, best-effort parse
        for cut in 0..f.len() {
            let _ = parse_beacon_or_probe(&f[..cut]);
            let _ = parse_probe_req(&f[..cut]);
            let _ = parse_deauth(&f[..cut]);
            let _ = data_endpoints(&f[..cut]);
            let _ = parse_eapol(&f[..cut]);
            let _ = parse_eapol_key(&f[..cut]);
        }
    }

    #[test]
    fn build_parse_deauth_roundtrip() {
        let f = build_deauth(&AP, &STA, 7);
        assert_eq!(f[0], 0xC0);
        assert_eq!(u16le(&f, 2), Some(314));
        assert_eq!(parse_deauth(&f), Some((AP, STA)));
        assert_eq!(u16le(&f, 24), Some(7)); // reason

        let d = build_disassoc(&AP, &STA, 8);
        assert_eq!(d[0], 0xA0);
        assert_eq!(parse_deauth(&d), Some((AP, STA)));
    }

    #[test]
    fn build_auth_and_assoc() {
        let a = build_auth_open(&AP, &STA, 42);
        assert_eq!(a[0], 0xB0);
        assert_eq!(u16le(&a, 2), Some(314));
        assert_eq!(mac_at(&a, 16), Some(AP)); // addr3 bssid = ap
        assert_eq!(u16le(&a, 24), Some(0)); // open system
        assert_eq!(u16le(&a, 26), Some(1)); // transaction 1
        assert_eq!(u16le(&a, 22), Some(42 << 4)); // seq number encoded

        let r = build_assoc_req(&AP, &STA, b"parafin");
        assert_eq!(r[0], 0x00);
        assert_eq!(r[28], IE_SSID);
        assert_eq!(r[29], 7);
        assert_eq!(&r[30..], b"parafin");
    }

    #[test]
    fn probe_req_parsed() {
        let mut f = hdr3(0x40, &MacAddr::BROADCAST, &STA, &MacAddr::BROADCAST, 0);
        f.extend_from_slice(&ie(IE_SSID, b"parafin"));
        let (sta, ssid) = parse_probe_req(&f).unwrap();
        assert_eq!(sta, STA);
        assert_eq!(ssid.as_deref(), Some("parafin"));

        // broadcast probe: zero-len SSID → None
        let mut b = hdr3(0x40, &MacAddr::BROADCAST, &STA, &MacAddr::BROADCAST, 0);
        b.extend_from_slice(&ie(IE_SSID, b""));
        assert_eq!(parse_probe_req(&b), Some((STA, None)));

        // beacon is not a probe request
        assert!(parse_probe_req(&parafin_beacon()).is_none());
    }

    /// Minimal EAPOL-Key frame with the given key_info (BE), filled otherwise.
    fn eapol_key(key_info: u16) -> Vec<u8> {
        let mut v = vec![2u8, 3, 0, 95]; // version 2, type KEY, body len
        v.push(2); // descriptor type: RSN
        v.extend_from_slice(&key_info.to_be_bytes());
        v.extend_from_slice(&[0; 16 + 8 - 2 - 2 - 1]); // key_len..replay start pad
        v.truncate(9);
        v.extend_from_slice(&1u64.to_be_bytes()); // replay counter
        v.extend_from_slice(&[0x11; 32]); // nonce
        v.extend_from_slice(&[0; 16 + 8 + 8]); // iv + rsc + id
        v.extend_from_slice(&[0x22; 16]); // mic
        v.extend_from_slice(&[0, 0]); // key_data_len
        v
    }

    #[test]
    fn eapol_key_fields_extracted() {
        let ki: u16 = 2 | (1 << 7); // version 2 + ack
        let e = eapol_key(ki);
        let k = parse_eapol_key(&e).unwrap();
        assert_eq!(k.key_info, ki);
        assert_eq!(k.key_ver, 2);
        assert!(k.key_ack);
        assert!(!k.key_mic);
        assert_eq!(k.replay_counter, 1);
        assert_eq!(k.nonce, [0x11; 32]);
        assert_eq!(k.mic, [0x22; 16]);
        assert_eq!(k.key_data.len(), 0);
        assert_eq!(k.raw, &e[..]);
    }

    #[test]
    fn four_way_flag_matrix() {
        const VER2: u16 = 2;
        const INSTALL: u16 = 1 << 6;
        const ACK: u16 = 1 << 7;
        const MIC: u16 = 1 << 8;
        const SECURE: u16 = 1 << 9;

        let msg = |ki: u16| {
            let e = eapol_key(ki);
            let k = parse_eapol_key(&e).unwrap();
            eapol_4way_msg(&k)
        };
        assert_eq!(msg(VER2 | ACK), 1);
        assert_eq!(msg(VER2 | MIC), 2);
        assert_eq!(msg(VER2 | ACK | MIC | INSTALL | SECURE), 3);
        assert_eq!(msg(VER2 | MIC | SECURE), 4);
        // not a key frame flag combo → 0
        assert_eq!(msg(VER2), 0);
    }

    #[test]
    fn data_frames_and_eapol_detection() {
        // AP → STA data frame (from_ds) carrying EAPOL
        let mut f = vec![0x08, 0x02];
        f.extend_from_slice(&[0; 2]); // duration
        f.extend_from_slice(&STA.0); // addr1
        f.extend_from_slice(&AP.0); // addr2
        f.extend_from_slice(&STA.0); // addr3 (DA)
        f.extend_from_slice(&[0; 2]); // seq
        f.extend_from_slice(&SNAP_EAPOL);
        f.extend_from_slice(&eapol_key(2 | (1 << 7))); // M1

        assert_eq!(data_endpoints(&f), Some((AP, STA)));
        let (bssid, ap_sender, eap) = parse_eapol(&f).unwrap();
        assert_eq!(bssid, AP);
        assert!(ap_sender);
        assert_eq!(eapol_4way_msg(&parse_eapol_key(eap).unwrap()), 1);

        // QoS data subtype: skip 2 extra header bytes
        let mut q = f.clone();
        q[0] = 0x88;
        q.splice(24..24, [0x00, 0x00]);
        let (bssid, ap_sender, eap) = parse_eapol(&q).unwrap();
        assert_eq!((bssid, ap_sender), (AP, true));
        assert_eq!(eapol_4way_msg(&parse_eapol_key(eap).unwrap()), 1);

        // STA → AP (to_ds): bssid = addr1
        let mut up = vec![0x08, 0x01];
        up.extend_from_slice(&[0; 2]);
        up.extend_from_slice(&AP.0); // addr1 = bssid
        up.extend_from_slice(&STA.0); // addr2 = sta
        up.extend_from_slice(&STA.0); // addr3 = DA
        up.extend_from_slice(&[0; 2]);
        up.extend_from_slice(&SNAP_EAPOL);
        up.extend_from_slice(&eapol_key(2 | (1 << 8))); // M2
        assert_eq!(data_endpoints(&up), Some((AP, STA)));
        let (bssid, ap_sender, eap) = parse_eapol(&up).unwrap();
        assert_eq!((bssid, ap_sender), (AP, false));
        assert_eq!(eapol_4way_msg(&parse_eapol_key(eap).unwrap()), 2);

        // WDS: addr4 present, payload shifted
        let mut wds = vec![0x08, 0x03];
        wds.extend_from_slice(&[0; 2]);
        wds.extend_from_slice(&AP.0); // addr1 RA
        wds.extend_from_slice(&AP.0); // addr2 TA
        wds.extend_from_slice(&STA.0); // addr3 DA
        wds.extend_from_slice(&[0; 2]);
        wds.extend_from_slice(&STA.0); // addr4 SA
        wds.extend_from_slice(&SNAP_EAPOL);
        wds.extend_from_slice(&eapol_key(2 | (1 << 7)));
        assert_eq!(data_endpoints(&wds), Some((AP, STA)));
        assert!(parse_eapol(&wds).is_some());

        // management frame → not data
        assert!(parse_eapol(&parafin_beacon()).is_none());
    }
}
