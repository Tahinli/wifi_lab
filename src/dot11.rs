//! 802.11 MAC frame parsing and building.
//!
//! Zero-copy where possible; all reads are bounds-checked through `get`.
//! Frames here never carry an FCS (the driver appends it on TX, and monitor
//! captures may or may not include one — parsers simply ignore trailing
//! bytes beyond what they need).

use crate::common::{Akm, MacAddr, Security};

/// LLC/SNAP header prefixing an EAPOL payload inside a data frame.
const SNAP_EAPOL: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e];

pub(crate) const IE_SSID: u8 = 0;
const IE_DS_PARAM: u8 = 3;
const IE_RSN: u8 = 48;
pub(crate) const IE_VENDOR: u8 = 221;

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
    /// AKM suites from the RSN/WPA IE; empty for open/WEP or unparsed frames.
    pub akms: Vec<Akm>,
}

/// Map an RSN AKM suite type byte to `Akm`.
fn akm_from_type(t: u8) -> Akm {
    match t {
        2 => Akm::Psk,
        8 => Akm::Sae,
        18 => Akm::Owe,
        4 => Akm::FtPsk,
        6 => Akm::PskSha256,
        1 => Akm::OneX,
        other => Akm::Other(other),
    }
}

/// Walk the AKM suite list of an RSN IE body, collecting mapped `Akm`s.
/// Layout: version(2) group(4) pairwise_cnt(2) pairwise[4n] akm_cnt(2) akm[4m].
fn rsn_akms(body: &[u8], out: &mut Vec<Akm>) {
    let Some(pair_cnt) = u16le(body, 6).map(|c| c as usize) else {
        return;
    };
    let mut o = 8usize + 4 * pair_cnt;
    let Some(akm_cnt) = u16le(body, o).map(|c| c as usize) else {
        return;
    };
    o += 2;
    for i in 0..akm_cnt {
        let Some(suite) = body.get(o + 4 * i..o + 4 * i + 4) else {
            break;
        };
        out.push(akm_from_type(suite[3]));
    }
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
    let mut akms = Vec::new();
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
            rsn_akms(body, &mut akms);
        }
        IE_VENDOR => {
            if body.len() >= 4 && body[..4] == WPA_OUI {
                has_wpa = true;
                // WPA1 vendor IE: only PSK key management exists.
                akms.push(Akm::Psk);
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

    // An AP advertising WPA (vendor IE) AND WPA2 (RSN IE, e.g. mixed or
    // transition mode) otherwise surfaces PSK twice. First-seen order wins.
    let mut uniq: Vec<Akm> = Vec::with_capacity(akms.len());
    for a in akms {
        if !uniq.contains(&a) {
            uniq.push(a);
        }
    }
    let akms = uniq;

    Some(MgmtInfo {
        bssid: mac_at(f, 16)?,
        transmitter: mac_at(f, 10)?,
        ssid,
        channel,
        security,
        akms,
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

/// Association/reassociation request → (station, bssid, ssid).
/// None for other/broken frames. SSID is None for hidden (`\0`-padded or
/// empty) networks.
pub fn parse_assoc_req(f: &[u8]) -> Option<(MacAddr, MacAddr, Option<String>)> {
    let fc = u16le(f, 0)?;
    let (ty, st) = type_subtype(fc);
    // subtype 0 = assoc request, 1 = reassoc request; mgmt type only.
    if ty != 0 || st > 1 {
        return None;
    }
    let bssid = mac_at(f, 4)?; // addr1
    let sta = mac_at(f, 10)?; // addr2
    // Fixed params: capability(2) + listen interval(2) at offset 24, so IEs
    // start at 28; reassoc adds current-AP MAC(6) → IEs start at 34.
    let ie_off = if st == 0 { 28 } else { 34 };
    let mut ssid = None;
    walk_ies(f, ie_off, |id, body| {
        if id == IE_SSID {
            // hidden networks send a zero or NUL-padded SSID
            let s: &[u8] = body;
            let meaningful = s.iter().take_while(|&&b| b != 0).count();
            if meaningful > 0 {
                ssid = Some(String::from_utf8_lossy(&s[..meaningful]).into_owned());
            }
        }
    });
    // ensure the fixed params fit (frames shorter than ie_off are bogus)
    if f.len() < ie_off {
        return None;
    }
    Some((sta, bssid, ssid))
}

// ---------------------------------------------------------------------------
// device correlation (pairing rotated/randomized MACs of one radio)
// ---------------------------------------------------------------------------

/// 12-bit per-transmitter sequence number (bytes 22-24, high nibble is the
/// fragment number). A device's sequence counter survives MAC rotation, so
/// near-continuity between two MACs' frames is a strong pairing witness.
pub fn seq_of(f: &[u8]) -> Option<u16> {
    Some(u16le(f, 22)? >> 4)
}

fn fnv_add(h: &mut u32, b: u8) {
    *h ^= b as u32;
    *h = h.wrapping_mul(0x0100_0193);
}

/// Ordered-IE device fingerprint (probe/assoc request frames): FNV-1a over
/// the (tag, len) sequence, plus full payloads of the rate tags and the
/// OUI+type tuple of vendor IEs. Stable per driver/firmware build and
/// independent of the station's (possibly randomized) MAC and of which
/// SSIDs it is probing. Different drivers of the same model usually share
/// it, so it is a *probable* witness, not identity — pair it with UUID-E or
/// sequence continuity for certainty.
pub fn ie_fingerprint(f: &[u8], ie_off: usize) -> Option<u32> {
    let mut h = 0x811c_9dc5u32;
    let mut n = 0u32;
    walk_ies(f, ie_off, |id, body| {
        fnv_add(&mut h, id);
        // SSID tag: content-agnostic. Directed and wildcard probes of the
        // same radio alternate freely and differ only in this length; the
        // probed-network signal comes from the group's SSID set instead.
        if id != IE_SSID {
            fnv_add(&mut h, body.len() as u8);
        }
        match id {
            // rates + extended rates: full payload is model-specific
            1 | 50 => body.iter().for_each(|&b| fnv_add(&mut h, b)),
            // vendor IE: OUI+type+len, not the (device-varying) payload
            IE_VENDOR if body.len() >= 4 => body[..4].iter().for_each(|&b| fnv_add(&mut h, b)),
            _ => {}
        }
        n += 1;
    });
    (n > 0).then_some(h)
}

/// WPS UUID-E (attribute 0x1047) from a WPS vendor IE, if present. A stable
/// per-device identifier leaked in probe requests by devices with WPS on —
/// an exact pairing witness across MAC rotation.
pub fn wps_uuid_e(f: &[u8], ie_off: usize) -> Option<[u8; 16]> {
    // WPS vendor IE: OUI 00:50:f2, type 0x04; attributes are BE (id, len).
    const WPS_OUI: [u8; 4] = [0x00, 0x50, 0xf2, 0x04];
    const ATTR_UUID_E: u16 = 0x1047;
    let mut out = None;
    walk_ies(f, ie_off, |id, body| {
        if id != IE_VENDOR || body.len() < 4 || body[..4] != WPS_OUI {
            return;
        }
        let mut cur = 4;
        while cur + 4 <= body.len() {
            let attr = u16::from_be_bytes([body[cur], body[cur + 1]]);
            let len = u16::from_be_bytes([body[cur + 2], body[cur + 3]]) as usize;
            let Some(val) = body.get(cur + 4..cur + 4 + len) else {
                break;
            };
            if attr == ATTR_UUID_E && len == 16 {
                out = Some(val.try_into().expect("len checked"));
            }
            cur += 4 + len;
        }
    });
    out
}

/// Device-correlation material parsed from a probe request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeIdent {
    pub sta: MacAddr,
    pub ssid: Option<String>,     // None for the wildcard probe
    pub fingerprint: u32,
    pub uuid: Option<[u8; 16]>,
}

/// Same, from an association/reassociation request (adds the target bssid).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssocIdent {
    pub sta: MacAddr,
    pub bssid: MacAddr,
    pub ssid: Option<String>,
    pub fingerprint: u32,
    pub uuid: Option<[u8; 16]>,
}

/// Probe request with device-correlation material; None for other frames or
/// probes with an empty/malformed IE chain (fingerprint impossible).
pub fn parse_probe_ident(f: &[u8]) -> Option<ProbeIdent> {
    let fc = u16le(f, 0)?;
    if type_subtype(fc) != (0, 4) {
        return None;
    }
    let sta = mac_at(f, 10)?;
    let fingerprint = ie_fingerprint(f, 24)?;
    let mut ssid = None;
    walk_ies(f, 24, |id, body| {
        if id == IE_SSID && !body.is_empty() {
            ssid = Some(String::from_utf8_lossy(body).into_owned());
        }
    });
    let uuid = wps_uuid_e(f, 24);
    Some(ProbeIdent { sta, ssid, fingerprint, uuid })
}

/// Assoc/reassoc request with device-correlation material; None for other
/// frames. SSID is None for hidden (empty/NUL-padded) networks.
pub fn parse_assoc_ident(f: &[u8]) -> Option<AssocIdent> {
    let fc = u16le(f, 0)?;
    let (ty, st) = type_subtype(fc);
    if ty != 0 || st > 1 {
        return None;
    }
    let ie_off = if st == 0 { 28 } else { 34 };
    if f.len() < ie_off {
        return None;
    }
    let bssid = mac_at(f, 4)?;
    let sta = mac_at(f, 10)?;
    let fingerprint = ie_fingerprint(f, ie_off)?;
    let mut ssid = None;
    walk_ies(f, ie_off, |id, body| {
        if id == IE_SSID {
            let meaningful = body.iter().take_while(|&&b| b != 0).count();
            if meaningful > 0 {
                ssid = Some(String::from_utf8_lossy(&body[..meaningful]).into_owned());
            }
        }
    });
    let uuid = wps_uuid_e(f, ie_off);
    Some(AssocIdent { sta, bssid, ssid, fingerprint, uuid })
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

/// Probe request sta → broadcast: empty `ssid` = wildcard (every AP on
/// the channel should answer with a probe response), otherwise directed.
/// Used by the injection canary: a response proves injected frames
/// actually radiate.
pub fn build_probe_req(ssid: &[u8], sa: &MacAddr) -> Vec<u8> {
    let mut v = hdr3(0x40, &MacAddr::BROADCAST, sa, &MacAddr::BROADCAST, 0);
    v.push(IE_SSID);
    v.push(ssid.len().min(32) as u8);
    v.extend_from_slice(&ssid[..ssid.len().min(32)]);
    v.extend_from_slice(&[0x01, 0x04, 0x82, 0x84, 0x8b, 0x96]); // supported rates
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

    /// RSN IE with several AKM suites listed in order.
    fn rsn_ie_multi(akm_types: &[u8]) -> Vec<u8> {
        let mut b = vec![
            0x01, 0x00, // version
            0x00, 0x0f, 0xac, 0x04, // group cipher CCMP
            0x01, 0x00, // pairwise count
            0x00, 0x0f, 0xac, 0x04, // pairwise CCMP
        ];
        b.extend_from_slice(&(akm_types.len() as u16).to_le_bytes());
        for &t in akm_types {
            b.extend_from_slice(&[0x00, 0x0f, 0xac, t]);
        }
        b.extend_from_slice(&[0x00, 0x00]); // rsn capabilities
        let b = b.split_off(0);
        ie(IE_RSN, &b)
    }

    /// Beacon like `parafin_beacon` but with the RSN IE replaced by `rsn`.
    fn beacon_with_rsn(rsn: Vec<u8>) -> Vec<u8> {
        let mut v = parafin_beacon();
        v.splice(v.len() - rsn_ie(2).len().., rsn);
        v
    }

    #[test]
    fn akm_list_parsed() {
        // WPA2/WPA3 transition: PSK + SAE both advertised.
        let f = beacon_with_rsn(rsn_ie_multi(&[2, 8]));
        let info = parse_beacon_or_probe(&f).expect("beacon parses");
        assert_eq!(info.akms, vec![Akm::Psk, Akm::Sae]);
        // security label logic untouched: SAE present → Wpa3
        assert_eq!(info.security, Security::Wpa3);

        // OWE (type 18)
        let f = beacon_with_rsn(rsn_ie_multi(&[18]));
        let info = parse_beacon_or_probe(&f).unwrap();
        assert_eq!(info.akms, vec![Akm::Owe]);
        // no SAE → Wpa2 label
        assert_eq!(info.security, Security::Wpa2);

        // unknown suite type → Other, PSK still mapped
        let f = beacon_with_rsn(rsn_ie_multi(&[2, 99]));
        let info = parse_beacon_or_probe(&f).unwrap();
        assert_eq!(info.akms, vec![Akm::Psk, Akm::Other(99)]);

        // plain WPA2-PSK beacon: single PSK entry
        let info = parse_beacon_or_probe(&parafin_beacon()).unwrap();
        assert_eq!(info.akms, vec![Akm::Psk]);

        // open network: no security IEs → empty akms
        let mut f = parafin_beacon();
        f.truncate(36);
        f.extend_from_slice(&ie(IE_SSID, b"cafe"));
        f[34] = 0x01; // clear privacy bit
        f[35] = 0x04;
        let info = parse_beacon_or_probe(&f).unwrap();
        assert_eq!(info.security, Security::Open);
        assert_eq!(info.akms, Vec::<Akm>::new());
    }

    #[test]
    fn wpa1_vendor_ie_yields_psk_akm() {
        let mut f = parafin_beacon();
        f.truncate(36);
        f.extend_from_slice(&ie(IE_SSID, b"legacy"));
        // WPA_OUI vendor IE: oui+type, then version(2) — content beyond the
        // OUI is not inspected, so the minimal fixture suffices.
        f.extend_from_slice(&ie(IE_VENDOR, &[0x00, 0x50, 0xf2, 0x01, 0x01, 0x00]));
        let info = parse_beacon_or_probe(&f).unwrap();
        assert_eq!(info.security, Security::Wpa);
        assert_eq!(info.akms, vec![Akm::Psk]);
    }

    #[test]
    fn akms_deduped_across_wpa_and_rsn_ies() {
        // Mixed WPA/WPA2 AP: RSN IE with PSK plus the WPA vendor IE — the
        // vendor arm must not surface a duplicate PSK.
        let mut f = beacon_with_rsn(rsn_ie_multi(&[2]));
        f.extend_from_slice(&ie(IE_VENDOR, &[0x00, 0x50, 0xf2, 0x01, 0x01, 0x00]));
        let info = parse_beacon_or_probe(&f).unwrap();
        assert_eq!(info.akms, vec![Akm::Psk], "no PSK+PSK duplication");
    }

    #[test]
    fn seq_number_extracted() {
        let mut f = parafin_beacon();
        // seq field at bytes 22-24: seq<<4 | frag
        f[22] = 0x30; // seq 3, frag 0
        f[23] = 0x02; // → 0x230 >> 4 = 0x23 = 35
        assert_eq!(seq_of(&f), Some(0x23));
        assert_eq!(seq_of(&f[..20]), None);
    }

    /// Probe builder mirroring the scanner tests' shape.
    fn probe_with(sta: &MacAddr, ssid: Option<&str>, ies: &[Vec<u8>], seq: u16) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&0x0040u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&MacAddr::BROADCAST.0);
        v.extend_from_slice(&sta.0);
        v.extend_from_slice(&MacAddr::BROADCAST.0);
        v.extend_from_slice(&(seq << 4).to_le_bytes());
        match ssid {
            Some(s) => v.extend_from_slice(&ie(IE_SSID, s.as_bytes())),
            None => v.extend_from_slice(&ie(IE_SSID, b"")),
        }
        for b in ies {
            v.extend_from_slice(b);
        }
        v
    }

    #[test]
    fn fingerprint_stable_directed_vs_wildcard() {
        // The same radio alternating directed/wildcard probes must hash
        // identically; a different IE chain must not.
        let rates = ie(1, &[0x82, 0x84, 0x8b, 0x96]);
        let f1 = probe_with(&STA, Some("parafin"), &[rates.clone()], 7);
        let f2 = probe_with(&STA, None, &[rates.clone()], 8);
        let i1 = parse_probe_ident(&f1).expect("parses");
        let i2 = parse_probe_ident(&f2).expect("parses");
        assert_eq!(i1.fingerprint, i2.fingerprint);
        assert_eq!(i1.ssid.as_deref(), Some("parafin"));
        assert_eq!(i2.ssid, None);

        let other = probe_with(&STA, None, &[ie(1, &[0x82, 0x84])], 9);
        let i3 = parse_probe_ident(&other).expect("parses");
        assert_ne!(i1.fingerprint, i3.fingerprint);

        // Off a probe frame entirely → None.
        assert!(parse_probe_ident(&parafin_beacon()).is_none());
    }

    #[test]
    fn wps_uuid_e_parsed_from_probe() {
        let uuid = [0xabu8; 16];
        let mut wps_body = vec![0x00, 0x50, 0xf2, 0x04];
        wps_body.extend_from_slice(&0x1047u16.to_be_bytes());
        wps_body.extend_from_slice(&16u16.to_be_bytes());
        wps_body.extend_from_slice(&uuid);
        let wps = ie(IE_VENDOR, &wps_body);
        let f = probe_with(&STA, None, &[wps], 7);
        let ident = parse_probe_ident(&f).expect("parses");
        assert_eq!(ident.uuid, Some(uuid));
        // Truncated attribute body → no uuid, no panic.
        let short = ie(IE_VENDOR, &[0x00, 0x50, 0xf2, 0x04, 0x10, 0x47, 0x00, 0x10, 0xaa, 0xbb]);
        let f = probe_with(&STA, None, &[short], 7);
        assert_eq!(parse_probe_ident(&f).unwrap().uuid, None);
    }

    #[test]
    fn assoc_ident_parsed() {
        let f = build_assoc_req(&AP, &STA, b"testap");
        let ident = parse_assoc_ident(&f).expect("assoc ident parses");
        assert_eq!(ident.sta, STA);
        assert_eq!(ident.bssid, AP);
        assert_eq!(ident.ssid.as_deref(), Some("testap"));
        assert_eq!(ident.uuid, None);
        assert!(parse_assoc_ident(&parafin_beacon()).is_none());
        for cut in 0..f.len() {
            let _ = parse_assoc_ident(&f[..cut]);
        }
    }

    #[test]
    fn assoc_req_parsed() {
        // assoc request: addr1=bssid(AP), addr2=sta, ssid "testap"
        let f = build_assoc_req(&AP, &STA, b"testap");
        let (sta, bssid, ssid) = parse_assoc_req(&f).expect("assoc-req parses");
        assert_eq!(sta, STA);
        assert_eq!(bssid, AP);
        assert_eq!(ssid.as_deref(), Some("testap"));

        // reassoc request (subtype 1): extra current-AP field before IEs
        let mut r = hdr3(0x10, &AP, &STA, &AP, 0);
        r.extend_from_slice(&0x0431u16.to_le_bytes()); // capability
        r.extend_from_slice(&10u16.to_le_bytes()); // listen interval
        r.extend_from_slice(&STA.0); // current AP (assoc) — arbitrary MAC here
        r.extend_from_slice(&ie(IE_SSID, b"home-net"));
        let (sta, bssid, ssid) = parse_assoc_req(&r).expect("reassoc-req parses");
        assert_eq!(sta, STA);
        assert_eq!(bssid, AP);
        assert_eq!(ssid.as_deref(), Some("home-net"));

        // empty SSID → None (hidden/wildcard attempt)
        let mut g = hdr3(0x00, &AP, &STA, &AP, 0);
        g.extend_from_slice(&0x0431u16.to_le_bytes());
        g.extend_from_slice(&10u16.to_le_bytes());
        g.extend_from_slice(&ie(IE_SSID, b""));
        let (_, _, ssid) = parse_assoc_req(&g).unwrap();
        assert_eq!(ssid, None);

        // NUL-padded SSID → None
        let mut h = hdr3(0x00, &AP, &STA, &AP, 0);
        h.extend_from_slice(&0x0431u16.to_le_bytes());
        h.extend_from_slice(&10u16.to_le_bytes());
        h.extend_from_slice(&ie(IE_SSID, &[0x00, 0x00, 0x00]));
        let (_, _, ssid) = parse_assoc_req(&h).unwrap();
        assert_eq!(ssid, None);

        // truncated frames: header cut anywhere → None or no panic
        for cut in 0..f.len() {
            let _ = parse_assoc_req(&f[..cut]);
        }
        // frame too short to hold the fixed params → None
        assert_eq!(parse_assoc_req(&f[..24]), None);

        // non-assoc frames rejected
        assert_eq!(parse_assoc_req(&parafin_beacon()), None);
        let pr = build_probe_req(b"x", &STA);
        assert_eq!(parse_assoc_req(&pr), None);
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
    }

    #[test]
    fn build_probe_req_roundtrips_wildcard_and_directed() {
        let wild = build_probe_req(&[], &STA);
        let (sta, ssid) = parse_probe_req(&wild).unwrap();
        assert_eq!(sta, STA);
        assert_eq!(ssid, None, "wildcard SSID (len 0) parses as None");
        let dir = build_probe_req(b"parafin", &STA);
        let (sta, ssid) = parse_probe_req(&dir).unwrap();
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
