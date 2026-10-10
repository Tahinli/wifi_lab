//! 4-way handshake tracker + hashcat-22000 export.
//!
//! A capture is crackable once we hold M1 (ANonce) and a matching M2
//! (SNonce + MIC) with a consistent replay counter. M3/M4 only inform
//! progress — they cannot substitute for the M2 pair.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossbeam_channel::Sender;

use crate::common::{Event, HandshakeCapture, MacAddr, PmkidCapture};
use crate::dot11::{EapolKey, eapol_4way_msg, parse_eapol, parse_eapol_key};
use crate::radiotap;
use crate::rawsock::RawSocket;

/// Per-(ap, sta) state older than this is dropped (replays are long dead).
const STATE_TTL: Duration = Duration::from_secs(120);

/// Partial 4-way collection for one (ap, sta) pair.
#[derive(Default)]
struct PairState {
    m1: Option<Msg>,
    m2: Option<Msg>,
    m3: bool,
    m4: bool,
    /// Last time any message for this pair arrived.
    touched: Option<Instant>,
    /// Set once HandshakeComplete has been emitted (don't re-fire).
    done: bool,
}

struct Msg {
    replay_counter: u64,
    nonce: [u8; 32],
    mic: [u8; 16],
    key_ver: u8,
    /// Full EAPOL frame starting at the version byte (M2 only needs it).
    raw: Vec<u8>,
}

impl PairState {
    fn mask(&self) -> u8 {
        let mut m = 0u8;
        if self.m1.is_some() {
            m |= 1;
        }
        if self.m2.is_some() {
            m |= 1 << 1;
        }
        if self.m3 {
            m |= 1 << 2;
        }
        if self.m4 {
            m |= 1 << 3;
        }
        m
    }
}

pub struct Tracker {
    pairs: HashMap<(MacAddr, MacAddr), PairState>,
}

impl Default for Tracker {
    fn default() -> Self {
        Self::new()
    }
}

impl Tracker {
    pub fn new() -> Self {
        Self {
            pairs: HashMap::new(),
        }
    }

    /// Feed a parsed EAPOL-Key frame observed between `ap` and `sta`, with
    /// the AP's current essid (empty/unknown essid → no capture possible;
    /// progress is still tracked lightly for consistent state cleanup).
    ///
    /// Emits [`Event::HandshakeProgress`] on each newly collected message and
    /// returns `Some(capture)` exactly once when an M1+M2 pair completes.
    pub fn ingest(
        &mut self,
        ap: MacAddr,
        sta: MacAddr,
        essid: &str,
        key: &EapolKey,
        tx: &Sender<Event>,
    ) -> Option<HandshakeCapture> {
        // Drop long-dead pairs on traffic (keeps the map bounded).
        self.reap();

        let msg_no = eapol_4way_msg(key);
        if msg_no == 0 {
            return None;
        }

        let st = self.pairs.entry((ap, sta)).or_default();
        st.touched = Some(Instant::now());
        let mut emit_progress = false;

        match msg_no {
            1 => {
                // M1: ANonce, no MIC. Keep the newest M1 (retransmissions
                // bump the replay counter).
                st.m1 = Some(Msg {
                    replay_counter: key.replay_counter,
                    nonce: key.nonce,
                    mic: key.mic,
                    key_ver: key.key_ver,
                    raw: key.raw.to_vec(),
                });
                emit_progress = true;
            }
            2 => {
                // M2: SNonce + MIC must be nonzero to be crackable.
                if key.mic.iter().any(|&b| b != 0) && key.nonce.iter().any(|&b| b != 0) {
                    st.m2 = Some(Msg {
                        replay_counter: key.replay_counter,
                        nonce: key.nonce,
                        mic: key.mic,
                        key_ver: key.key_ver,
                        raw: key.raw.to_vec(),
                    });
                    emit_progress = true;
                }
            }
            3 => {
                if !st.m3 {
                    st.m3 = true;
                    emit_progress = true;
                }
            }
            4 => {
                if !st.m4 {
                    st.m4 = true;
                    emit_progress = true;
                }
            }
            _ => {}
        }

        if emit_progress {
            let _ = tx.send(Event::HandshakeProgress {
                ap,
                client: sta,
                have: st.mask(),
            });
        }

        if st.done {
            return None;
        }
        let (Some(m1), Some(m2)) = (&st.m1, &st.m2) else {
            return None;
        };
        // Replay-counter consistency: rc(M2) == rc(M1); an M1 retransmission
        // seen after M2 may be exactly one behind (rc(M1) == rc(M2) - 1),
        // both refer to the same exchange.
        let rc_consistent = m1.replay_counter == m2.replay_counter
            || m1.replay_counter + 1 == m2.replay_counter;
        if !rc_consistent {
            return None;
        }
        if essid.is_empty() {
            return None; // cannot crack without the salt
        }

        st.done = true;
        Some(HandshakeCapture::new(
            ap,
            sta,
            essid.to_string(),
            m1.nonce,
            m2.nonce,
            m2.mic,
            m2.raw.clone(),
            m2.key_ver,
        ))
    }

    /// Drop pairs untouched for longer than the replay window.
    fn reap(&mut self) {
        let now = Instant::now();
        self.pairs.retain(|_, st| match st.touched {
            Some(t) => now.duration_since(t) <= STATE_TTL,
            None => false,
        });
    }
}

fn hex_push(out: &mut String, bytes: &[u8]) {
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
}

/// hashcat -m 22000 WPA-PBKDF2 line for a handshake (message-pair type 02):
/// `WPA*02*mic*mac_ap*mac_client*essid*anonce*eapol_m2*00`
/// (EAPOL carries the MIC not-zeroed; the `00` message-pair field marks the
/// pair replay-verified). The `WPA*` prefix is emitted for modern hashcat.
pub fn handshake_hc22000(h: &HandshakeCapture) -> String {
    let mut s = String::from("WPA*02*");
    hex_push(&mut s, h.mic());
    s.push('*');
    hex_push(&mut s, &h.ap.0);
    s.push('*');
    hex_push(&mut s, &h.client.0);
    s.push('*');
    hex_push(&mut s, h.essid.as_bytes());
    s.push('*');
    hex_push(&mut s, &h.anonce);
    s.push('*');
    hex_push(&mut s, &h.eapol_m2);
    s.push_str("*00");
    s
}

/// hashcat -m 22000 PMKID line (type 01):
/// `WPA*01*pmkid*mac_ap*mac_client*essid***`
pub fn pmkid_hc22000(p: &PmkidCapture) -> String {
    let mut s = String::from("WPA*01*");
    hex_push(&mut s, &p.pmkid);
    s.push('*');
    hex_push(&mut s, &p.ap.0);
    s.push('*');
    hex_push(&mut s, &p.client.0);
    s.push('*');
    hex_push(&mut s, p.essid.as_bytes());
    s.push_str("***");
    s
}

/// Frame poll cadence: how long one recv call may block before the stop
/// flag is re-checked (250 ms per the backend contract).
pub const CAPTURE_POLL_MS: u32 = 250;

/// Active 4-way capture loop against `ap`: receives frames from `sock`
/// (already bound to a monitor interface on the right channel), tracks
/// every EAPOL exchange involving `ap`, and emits
/// [`Event::HandshakeProgress`]/[`Event::HandshakeComplete`] through the
/// internal [`Tracker`]. Returns `Ok(flow)` once a crackable capture was
/// sent, the `stop` flag flipped, or nothing but timeouts arrived for a
/// long stretch — the caller reports whether a capture actually landed.
///
/// Additive helper consumed by `backend.rs`; the tracker above is
/// untouched.
pub fn capture_loop(
    sock: &RawSocket,
    targets: &[MacAddr],
    essid: &str,
    tx: &Sender<Event>,
    stop: &Arc<AtomicBool>,
) -> Result<bool> {
    sock.set_timeout(CAPTURE_POLL_MS)?;
    let _ = tx.send(Event::Log(format!(
        "handshake: listening for 4-way on {} ({essid})",
        if targets.len() == 1 {
            targets[0].to_string()
        } else {
            format!("{} bssids", targets.len())
        }
    )));

    let mut tracker = Tracker::new();
    let mut buf = vec![0u8; 4096];
    // ~4 minutes of dead air without a single EAPOL message → give up.
    let mut idle_deadline = Instant::now() + Duration::from_secs(240);

    // Diagnostics: a silent capture must be distinguishable from deaf radio
    // (0 frames) vs wrong AP (EAPOL on other BSSIDs) vs client simply not
    // reassociating (EAPOL on target but no 4-way yet) → periodic stats.
    let mut frames: u64 = 0;
    let mut eapol_other: u64 = 0;
    let mut last_stats = Instant::now();
    const STATS_EVERY: Duration = Duration::from_secs(30);

    loop {
        if stop.load(Ordering::Relaxed) {
            return Ok(false);
        }
        if Instant::now() >= idle_deadline {
            return Ok(false);
        }
        if last_stats.elapsed() >= STATS_EVERY {
            last_stats = Instant::now();
            let _ = tx.send(Event::Log(format!(
                "handshake: still listening — {frames} frames, {eapol_other} EAPOL on other BSSIDs"
            )));
        }
        let n = match sock.recv(&mut buf) {
            Ok(n) => n,
            Err(e)
                if [libc::EAGAIN, libc::EWOULDBLOCK, libc::ETIMEDOUT]
                    .contains(&e.raw_os_error().unwrap_or(0)) =>
            {
                continue;
            }
            Err(e) => return Err(e).context("handshake capture recv"),
        };
        let Some((_meta, frame)) = radiotap::strip(&buf[..n]) else {
            continue;
        };
        frames += 1;
        if frames == 1 {
            let _ = tx.send(Event::Log(
                "handshake: receiving frames (radio OK)".to_string(),
            ));
        }
        let Some((bssid, _ap_is_sender, eapol)) = parse_eapol(frame) else {
            continue;
        };
        if !targets.contains(&bssid) {
            eapol_other += 1;
            continue;
        }
        // Relevant traffic renews the idle window.
        idle_deadline = Instant::now() + Duration::from_secs(240);
        let sta = crate::dot11::data_endpoints(frame)
            .map(|(a, b)| if a == bssid { b } else { a })
            .unwrap_or(MacAddr::ZERO);
        if sta.is_zero() || sta.is_multicast() {
            continue;
        }
        let Some(key) = parse_eapol_key(eapol) else {
            continue;
        };
        // The FRAME's BSSID is the truth (dual-band: may differ from the
        // BSSID the user clicked).
        if let Some(cap) = tracker.ingest(bssid, sta, essid, &key, tx) {
            let _ = tx.send(Event::HandshakeComplete(Box::new(cap)));
            return Ok(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ap() -> MacAddr {
        "aa:bb:cc:dd:ee:ff".parse().unwrap()
    }

    fn sta() -> MacAddr {
        "11:22:33:44:55:66".parse().unwrap()
    }

    const KEY_VER2: u16 = 2;
    const INSTALL: u16 = 1 << 6;
    const ACK: u16 = 1 << 7;
    const MIC: u16 = 1 << 8;
    const SECURE: u16 = 1 << 9;

    /// Build a synthetic EAPOL-Key frame (eapol v2, type key, len 95).
    fn eapol_key(key_info: u16, rc: u64, nonce: [u8; 32], mic: [u8; 16]) -> Vec<u8> {
        let mut f = vec![2u8, 3, 0, 95]; // eapol hdr: v2, key, len=95 (desc)
        f.push(2); // descriptor type: RSN
        f.extend_from_slice(&key_info.to_be_bytes());
        f.extend_from_slice(&[0u8; 2]); // key length
        f.extend_from_slice(&rc.to_be_bytes());
        f.extend_from_slice(&nonce);
        f.extend_from_slice(&[0u8; 16]); // iv
        f.extend_from_slice(&[0u8; 8]); // rsc
        f.extend_from_slice(&[0u8; 8]); // id
        f.extend_from_slice(&mic);
        f.extend_from_slice(&[0u8; 2]); // key_data_len = 0
        f
    }

    fn parse(bytes: &[u8]) -> EapolKey<'_> {
        crate::dot11::parse_eapol_key(bytes).expect("well-formed eapol")
    }

    fn m1(rc: u64, anonce: [u8; 32]) -> Vec<u8> {
        eapol_key(KEY_VER2 | ACK, rc, anonce, [0u8; 16])
    }

    fn m2(rc: u64, snonce: [u8; 32], mic: [u8; 16]) -> Vec<u8> {
        eapol_key(KEY_VER2 | MIC, rc, snonce, mic)
    }

    fn m3(rc: u64, anonce: [u8; 32], mic: [u8; 16]) -> Vec<u8> {
        eapol_key(KEY_VER2 | ACK | MIC | INSTALL | SECURE, rc, anonce, mic)
    }

    fn m4(rc: u64, mic: [u8; 16]) -> Vec<u8> {
        eapol_key(KEY_VER2 | MIC | SECURE, rc, [0u8; 32], mic)
    }

    fn drain(rx: &crossbeam_channel::Receiver<Event>) -> Vec<Event> {
        let mut out = Vec::new();
        while let Ok(e) = rx.try_recv() {
            out.push(e);
        }
        out
    }

    #[test]
    fn m1_then_m2_yields_capture_and_progress() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut t = Tracker::new();
        let anonce = [7u8; 32];
        let snonce = [9u8; 32];
        let mic = [0xabu8; 16];

        assert!(t.ingest(ap(), sta(), "parafin", &parse(&m1(3, anonce)), &tx).is_none());
        let cap = t
            .ingest(ap(), sta(), "parafin", &parse(&m2(3, snonce, mic)), &tx)
            .expect("M1+M2 complete");
        assert_eq!(cap.ap, ap());
        assert_eq!(cap.client, sta());
        assert_eq!(cap.essid, "parafin");
        assert_eq!(cap.anonce, anonce);
        assert_eq!(cap.snonce, snonce);
        assert_eq!(cap.mic(), &mic);
        assert_eq!(cap.key_ver, 2);
        assert!(!cap.eapol_m2.is_empty());

        let evs = drain(&rx);
        assert!(matches!(&evs[0], Event::HandshakeProgress { have: 1, .. }));
        assert!(matches!(&evs[1], Event::HandshakeProgress { have: 0b0011, .. }));

        // Subsequent M3/M4 inform progress but don't re-emit a capture.
        assert!(
            t.ingest(ap(), sta(), "parafin", &parse(&m3(3, anonce, mic)), &tx)
                .is_none()
        );
        assert!(t.ingest(ap(), sta(), "parafin", &parse(&m4(4, mic)), &tx).is_none());
        let evs = drain(&rx);
        assert!(matches!(&evs[0], Event::HandshakeProgress { have: 0b0111, .. }));
        assert!(matches!(&evs[1], Event::HandshakeProgress { have: 0b1111, .. }));
    }

    #[test]
    fn m2_first_then_matching_m1_completes() {
        let (tx, _rx) = crossbeam_channel::unbounded();
        let mut t = Tracker::new();
        let mic = [1u8; 16];
        assert!(
            t.ingest(ap(), sta(), "parafin", &parse(&m2(5, [9u8; 32], mic)), &tx)
                .is_none()
        );
        // Exact rc match.
        let cap = t
            .ingest(ap(), sta(), "parafin", &parse(&m1(5, [7u8; 32])), &tx)
            .expect("late M1 pairs with buffered M2");
        assert_eq!(cap.snonce, [9u8; 32]);
    }

    #[test]
    fn m1_retransmit_one_behind_still_pairs() {
        let (tx, _rx) = crossbeam_channel::unbounded();
        let mut t = Tracker::new();
        let mic = [1u8; 16];
        t.ingest(ap(), sta(), "parafin", &parse(&m2(5, [9u8; 32], mic)), &tx);
        // retransmit tolerance: rc(M1) == rc(M2) - 1
        let cap = t
            .ingest(ap(), sta(), "parafin", &parse(&m1(4, [7u8; 32])), &tx)
            .expect("rc2-1 retransmit tolerated");
        assert_eq!(cap.anonce, [7u8; 32]);
    }

    #[test]
    fn rc_mismatch_blocks_capture() {
        let (tx, _rx) = crossbeam_channel::unbounded();
        let mut t = Tracker::new();
        let mic = [1u8; 16];
        t.ingest(ap(), sta(), "parafin", &parse(&m1(1, [7u8; 32])), &tx);
        // rc(M2)=5 is neither equal nor M1+1 → no capture.
        assert!(
            t.ingest(ap(), sta(), "parafin", &parse(&m2(5, [9u8; 32], mic)), &tx)
                .is_none()
        );
    }

    #[test]
    fn zero_mic_or_nonce_m2_ignored() {
        let (tx, _rx) = crossbeam_channel::unbounded();
        let mut t = Tracker::new();
        let anonce = [7u8; 32];
        t.ingest(ap(), sta(), "parafin", &parse(&m1(3, anonce)), &tx);
        // Zero MIC M2 (e.g. autogenerated junk) must not complete a capture.
        assert!(
            t.ingest(ap(), sta(), "parafin", &parse(&m2(3, [9u8; 32], [0u8; 16])), &tx)
                .is_none()
        );
        // Zero nonce (bogus) likewise.
        assert!(
            t.ingest(ap(), sta(), "parafin", &parse(&m2(3, [0u8; 32], [1u8; 16])), &tx)
                .is_none()
        );
    }

    #[test]
    fn empty_essid_skips_capture_but_keeps_state() {
        let (tx, _rx) = crossbeam_channel::unbounded();
        let mut t = Tracker::new();
        let mic = [1u8; 16];
        t.ingest(ap(), sta(), "", &parse(&m1(3, [7u8; 32])), &tx);
        assert!(t.ingest(ap(), sta(), "", &parse(&m2(3, [9u8; 32], mic)), &tx).is_none());
        // When the ESSID becomes known, the buffered pair can complete…
        // …but ingest needs a fresh message to re-trigger; feed an M3 (progress)
        // then a retransmitted M1 which re-pairs.
    }

    #[test]
    fn hc22000_handshake_shape() {
        let cap = HandshakeCapture::new(
            ap(),
            sta(),
            "parafin".into(),
            [7u8; 32],
            [9u8; 32],
            [0xabu8; 16],
            m2(3, [9u8; 32], [0xabu8; 16]),
            2,
        );
        let line = handshake_hc22000(&cap);
        assert!(line.starts_with("WPA*02*"));
        // Strip WPA* prefix → classic hc22000 fields; field 0 == "02".
        let bare = line.strip_prefix("WPA*").unwrap();
        assert_eq!(bare.split('*').next(), Some("02"));
        assert!(bare.contains("aabbccddeeff"));
        assert!(bare.contains("112233445566"));
        assert!(bare.contains(&"07".repeat(32))); // anonce
        // essid "parafin" hex
        assert!(bare.contains("7061726166696e"));
    }

    #[test]
    fn hc22000_pmkid_shape() {
        let cap = PmkidCapture {
            ap: ap(),
            client: sta(),
            essid: "parafin".into(),
            pmkid: [0x42u8; 16],
        };
        let line = pmkid_hc22000(&cap);
        assert_eq!(
            line,
            format!(
                "WPA*01*{}*aabbccddeeff*112233445566*7061726166696e***",
                "42".repeat(16)
            )
        );
    }

    #[test]
    fn hc22000_roundtrips_through_crypto_parser() {
        // Handshake: bare (WPA*-stripped) form must load via crypto's parser
        // and preserve every field.
        let cap = HandshakeCapture::new(
            ap(),
            sta(),
            "parafin".into(),
            [7u8; 32],
            [9u8; 32],
            [0xabu8; 16],
            m2(3, [9u8; 32], [0xabu8; 16]),
            2,
        );
        let line = handshake_hc22000(&cap);
        let bare = line.strip_prefix("WPA*").unwrap();
        let parsed = crate::crypto::parse_hc22000(bare)
            .expect("crypto parser must accept our export");
        match parsed {
            crate::crypto::CrackTarget::Handshake(h) => {
                assert_eq!(h.ap, cap.ap);
                assert_eq!(h.client, cap.client);
                assert_eq!(h.essid, cap.essid);
                assert_eq!(h.anonce, cap.anonce);
                assert_eq!(h.snonce, cap.snonce);
                assert_eq!(h.mic(), cap.mic());
                assert_eq!(h.eapol_m2, cap.eapol_m2);
                assert_eq!(h.key_ver, cap.key_ver);
            }
            _ => panic!("wrong target type"),
        }

        let pmkid_line = pmkid_hc22000(&PmkidCapture {
            ap: ap(),
            client: sta(),
            essid: "parafin".into(),
            pmkid: [0x42u8; 16],
        });
        let bare = pmkid_line.strip_prefix("WPA*").unwrap();
        let parsed = crate::crypto::parse_hc22000(bare)
            .expect("crypto parser must accept our pmkid export");
        match parsed {
            crate::crypto::CrackTarget::Pmkid(p) => {
                assert_eq!(p.ap, ap());
                assert_eq!(p.client, sta());
                assert_eq!(p.essid, "parafin");
                assert_eq!(p.pmkid, [0x42u8; 16]);
            }
            _ => panic!("wrong target type"),
        }
    }
}
