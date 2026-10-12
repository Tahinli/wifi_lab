//! Passive channel-hopping scanner: discovers APs (beacon/probe-response)
//! and client stations (probe-request + data frames), live-updating the UI
//! via [`Event`]s until `stop` flips true. Pure discovery — handshake
//! correlation happens in [`crate::handshake`].

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
// `Instant` is still used for dwell timing; timestamps going into shared
// types are `u64` millis (`crate::common::now_ms`) so they serialize.

use anyhow::{Context, Result};
use crossbeam_channel::Sender;

use crate::common::{AccessPoint, ClientInfo, Event, HOP_FREQS_ALL, MacAddr, now_ms};
use crate::radiotap::RxMeta;
use crate::rawsock::RawSocket;
use crate::{dot11, iface, radiotap};

/// APs go stale (ApLost) after this much silence (ms — `last_seen_ms`).
const AP_EXPIRE_MS: u64 = 30_000;
/// Clients go stale after this much silence (ms).
const CLIENT_EXPIRE_MS: u64 = 60_000;

pub struct ScannerConfig {
    pub ifname: String,
    /// Carrier frequencies (MHz) to hop; empty = [`HOP_FREQS_ALL`]
    /// (2.4 GHz, full TR-legal 5 GHz span, 6 GHz PSC).
    pub freqs: Vec<u16>,
    /// Dwell per channel.
    pub dwell_ms: u32,
    /// RSSI below this blocks creation of new AP/client entries (updates to
    /// already-known entries are always accepted).
    pub rssi_floor: i8,
}

/// Channel-frequency → channel number for the bands we hop.
fn freq_to_channel(freq_mhz: u16) -> Option<u8> {
    match freq_mhz {
        // 2.4 GHz: ch 1..14, 2407 + 5*ch (ch14 = 2484).
        2412..=2472 => Some(((freq_mhz - 2407) / 5) as u8),
        2484 => Some(14),
        // 5 GHz: ch = (freq - 5000) / 5.
        5000..=5900 => Some(((freq_mhz - 5000) / 5) as u8),
        // 6 GHz: ch = (freq - 5950) / 5 (collides numerically with 2.4 GHz;
        // display-only usage here).
        5945..=6425 => Some(((freq_mhz - 5950) / 5) as u8),
        _ => None,
    }
}

/// Stateful discovery engine — owned by `run`, unit-tested via `ingest`.
struct Scanner {
    aps: BTreeMap<MacAddr, AccessPoint>,
    clients: BTreeMap<MacAddr, ClientInfo>,
    rssi_floor: i8,
}

impl Scanner {
    fn new(rssi_floor: i8) -> Self {
        Self {
            aps: BTreeMap::new(),
            clients: BTreeMap::new(),
            rssi_floor,
        }
    }

    /// Feed one received frame. Radiotap metadata in `meta`, 802.11 bytes in
    /// `frame` (already stripped), clock in `now` ms since the process-local
    /// epoch ([`common::now_ms`], test-injectable).
    fn ingest(&mut self, meta: &RxMeta, frame: &[u8], now: u64, tx: &Sender<Event>) {
        // AP from beacon / probe-response.
        if let Some(m) = dot11::parse_beacon_or_probe(frame) {
            // Trust the DS-parameter IE; fall back to the radiotap carrier
            // frequency hint when the IE is absent.
            let channel = m
                .channel
                .or_else(|| freq_to_channel(meta.freq_mhz))
                .unwrap_or(0);
            let ssid = m.ssid.unwrap_or_default();
            match self.aps.get_mut(&m.bssid) {
                Some(ap) => {
                    let mut changed = false;
                    if meta.rssi_dbm != 0 && meta.rssi_dbm > ap.rssi_dbm {
                        ap.rssi_dbm = meta.rssi_dbm;
                        changed = true;
                    }
                    if !ssid.is_empty() && ap.ssid != ssid {
                        ap.ssid = ssid.clone();
                        changed = true;
                    }
                    if channel != 0 && ap.channel != channel {
                        ap.channel = channel;
                        changed = true;
                    }
                    if m.security != ap.security {
                        ap.security = m.security;
                        changed = true;
                    }
                    ap.beacons += 1;
                    ap.last_seen_ms = now;
                    if changed {
                        let _ = tx.send(Event::ApUpdated(ap.clone()));
                    }
                }
                None => {
                    if meta.rssi_dbm != 0 && meta.rssi_dbm < self.rssi_floor {
                        return; // weak signal: don't create the entry
                    }
                    let ap = AccessPoint {
                        bssid: m.bssid,
                        ssid,
                        channel,
                        security: m.security,
                        rssi_dbm: meta.rssi_dbm,
                        beacons: 1,
                        last_seen_ms: now,
                    };
                    self.aps.insert(m.bssid, ap.clone());
                    let _ = tx.send(Event::ApUpdated(ap));
                }
            }
            return;
        }

        // Client probing.
        if let Some((sta, _ssid)) = dot11::parse_probe_req(frame) {
            if sta.is_multicast() || sta.is_zero() {
                return;
            }
            self.note_client(sta, None, meta, now, tx);
            return;
        }

        // Clients talking data: learn station side; the bssid side refreshes
        // the AP liveness (channel/time) without bumping beacon count.
        if let Some((bssid, sta)) = dot11::data_endpoints(frame) {
            if !sta.is_multicast() && !sta.is_zero() {
                self.note_client(sta, Some(bssid), meta, now, tx);
            }
            if let Some(ap) = self.aps.get_mut(&bssid) {
                ap.last_seen_ms = now;
            }
        }
    }

    fn note_client(
        &mut self,
        sta: MacAddr,
        ap: Option<MacAddr>,
        meta: &RxMeta,
        now: u64,
        tx: &Sender<Event>,
    ) {
        match self.clients.get_mut(&sta) {
            Some(c) => {
                let mut changed = false;
                if meta.rssi_dbm != 0 && meta.rssi_dbm > c.rssi_dbm {
                    c.rssi_dbm = meta.rssi_dbm;
                    changed = true;
                }
                if let Some(b) = ap {
                    if c.ap != Some(b) {
                        c.ap = Some(b);
                        changed = true;
                    }
                }
                c.frames += 1;
                c.last_seen_ms = now;
                if changed {
                    let _ = tx.send(Event::ClientUpdated(c.clone()));
                }
            }
            None => {
                if meta.rssi_dbm != 0 && meta.rssi_dbm < self.rssi_floor {
                    return;
                }
                let c = ClientInfo {
                    mac: sta,
                    ap,
                    rssi_dbm: meta.rssi_dbm,
                    frames: 1,
                    last_seen_ms: now,
                };
                self.clients.insert(sta, c.clone());
                let _ = tx.send(Event::ClientUpdated(c));
            }
        }
    }

    /// Expire silent entries, emitting ApLost / (clients just drop out —
    /// contract has no ClientLost event; stale clients stop being updated).
    fn expire(&mut self, now: u64, tx: &Sender<Event>) {
        let gone: Vec<MacAddr> = self
            .aps
            .iter()
            .filter(|(_, ap)| now.saturating_sub(ap.last_seen_ms) > AP_EXPIRE_MS)
            .map(|(b, _)| *b)
            .collect();
        for b in gone {
            self.aps.remove(&b);
            let _ = tx.send(Event::ApLost(b));
        }
        self.clients
            .retain(|_, c| now.saturating_sub(c.last_seen_ms) <= CLIENT_EXPIRE_MS);
    }
}

/// Wall-clock counters for the 10 s `scan: …` diagnostic line — the evidence
/// channel distinguishing RX-silence from parser-drops when "only my own AP
/// shows up" is reported.
#[derive(Default)]
struct ScanStats {
    /// Frames returned by `RawSocket::recv` (radiotap included, unparsed).
    raw_frames_received: u64,
    /// Frames whose radiotap header parsed (`radiotap::strip` returned Some).
    radiotap_strip_ok: u64,
    /// 802.11 payload parsed as SOME mgmt frame (beacon/probe-req/deauth /
    /// probe-response family recognised by dot11).
    mgmt_80211_parsed: u64,
    /// Beacons/probe-responses that ingested an AP row (created or already
    /// known — i.e. recognised AP-producing frames).
    beacons_ap_ingested: u64,
    /// Frames with beacon/probe-response FC byte, REGARDLESS of whether the
    /// IE walk later succeeded — the parser-independent RX witness.
    beacon_fc_rx: u64,
    /// addr3 histogram of beacon_fc frames: answers "are other BSSIDs even
    /// reaching the card" without trusting any parser.
    bssid_hist: std::collections::BTreeMap<crate::common::MacAddr, u64>,
}

/// Blocking channel-hop passive scan on an interface the caller already put
/// into monitor mode. Returns when `stop` flips true.
pub fn run(cfg: ScannerConfig, tx: Sender<Event>, stop: Arc<AtomicBool>) -> Result<()> {
    let sock = RawSocket::open(&cfg.ifname)
        .with_context(|| format!("opening {} for scan", cfg.ifname))?;
    sock.set_timeout(cfg.dwell_ms).context("set_timeout")?;

    let freqs: Vec<u16> = if cfg.freqs.is_empty() {
        HOP_FREQS_ALL.to_vec()
    } else {
        cfg.freqs.clone()
    };
    let _ = tx.send(Event::Log(format!(
        "scanner: {} freqs, {} ms dwell on {}",
        freqs.len(),
        cfg.dwell_ms,
        cfg.ifname
    )));

    let mut scanner = Scanner::new(cfg.rssi_floor);
    let mut buf = vec![0u8; 4096];
    let mut ch_idx = 0usize;
    let mut stats = ScanStats::default();
    let mut last_stats_log = Instant::now();

    while !stop.load(Ordering::Relaxed) {
        let freq = freqs[ch_idx];
        // Display channel number (2.4/5 GHz exact; 6 GHz reported as its
        // own channel number — cosmetic only).
        let cur_ch = freq_to_channel(freq).map(|c| c as i32).unwrap_or(-1);
        ch_idx = (ch_idx + 1) % freqs.len();
        if let Err(e) = iface::set_freq(&cfg.ifname, freq) {
            let _ = tx.send(Event::Log(format!(
                "scanner: hop to {freq} MHz failed: {e:#}"
            )));
        }

        // Drain frames until the dwell elapses (recv timeout bounds it).
        let dwell_start = Instant::now();
        loop {
            match sock.recv(&mut buf) {
                Ok(n) => {
                    stats.raw_frames_received += 1;
                    let now = now_ms();
                    if let Some((meta, frame)) = radiotap::strip(&buf[..n]) {
                        stats.radiotap_strip_ok += 1;
                        // Parser-independent witness: beacon (0x80) and
                        // probe-response (0x50) frames carry the transmitter
                        // BSSID at addr3 (bytes 16..22) before any IE parse.
                        if frame.len() >= 24 && (frame[0] == 0x80 || frame[0] == 0x50) {
                            stats.beacon_fc_rx += 1;
                            let mut mac = [0u8; 6];
                            mac.copy_from_slice(&frame[16..22]);
                            *stats
                                .bssid_hist
                                .entry(crate::common::MacAddr(mac))
                                .or_insert(0) += 1;
                        }
                        if dot11::parse_beacon_or_probe(frame).is_some() {
                            stats.mgmt_80211_parsed += 1;
                            stats.beacons_ap_ingested += 1;
                        } else if dot11::parse_probe_req(frame).is_some()
                            || dot11::parse_deauth(frame).is_some()
                        {
                            stats.mgmt_80211_parsed += 1;
                        }
                        scanner.ingest(&meta, frame, now, &tx);
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break; // dwell over (set_timeout)
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    let _ = tx.send(Event::Error(format!("scanner recv: {e}")));
                    break;
                }
            }
            if dwell_start.elapsed() >= Duration::from_millis(cfg.dwell_ms as u64) * 4 {
                break; // safety net if timeout doesn't fire
            }
            if stop.load(Ordering::Relaxed) {
                break;
            }
        }

        // 10 s wall-time diagnostic heartbeat: distinguishes RX-silence
        // (rx==0) from radiotap/parser drops (rx>0 but beacons==0) when a
        // report says "only my own AP shows up".
        if last_stats_log.elapsed() >= Duration::from_secs(10) {
            last_stats_log = Instant::now();
            let top: String = {
                let mut v: Vec<(crate::common::MacAddr, u64)> =
                    stats.bssid_hist.iter().map(|(m, c)| (*m, *c)).collect();
                v.sort_unstable_by(|a, b| b.1.cmp(&a.1));
                v.truncate(4);
                v.iter()
                    .map(|(m, c)| format!("{m}({c})"))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let _ = tx.send(Event::Log(format!(
                "scan: rx={} strip={} beaconfc={} beacons={} aps={} ch={} top=[{}]",
                stats.raw_frames_received,
                stats.radiotap_strip_ok,
                stats.beacon_fc_rx,
                stats.beacons_ap_ingested,
                scanner.aps.len(),
                cur_ch,
                top
            )));
        }

        scanner.expire(now_ms(), &tx);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ap() -> MacAddr {
        "aa:bb:cc:dd:ee:ff".parse().unwrap()
    }

    fn sta() -> MacAddr {
        // Unicast (I/G bit clear) — 0x11 would be multicast and filtered.
        "12:22:33:44:55:66".parse().unwrap()
    }

    /// Hand-rolled beacon: radiotap-stripped 802.11 for `dot11` — FC 0x0080,
    /// addr1 broadcast, addr2/addr3 bssid, 12 fixed bytes, SSID + DS IEs.
    fn beacon_frame(bssid: &MacAddr, ssid: &str, channel: u8) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&0x0080u16.to_le_bytes()); // FC beacon
        f.extend_from_slice(&0u16.to_le_bytes()); // duration
        f.extend_from_slice(&MacAddr::BROADCAST.0); // addr1
        f.extend_from_slice(&bssid.0); // addr2 transmitter
        f.extend_from_slice(&bssid.0); // addr3 bssid
        f.extend_from_slice(&0u16.to_le_bytes()); // seq
        f.extend_from_slice(&[0u8; 8]); // timestamp
        f.extend_from_slice(&100u16.to_le_bytes()); // beacon interval
        f.extend_from_slice(&0x0431u16.to_le_bytes()); // capability (privacy)
        f.push(0); // SSID IE
        f.push(ssid.len() as u8);
        f.extend_from_slice(ssid.as_bytes());
        f.push(3); // DS param IE
        f.push(1);
        f.push(channel);
        f
    }

    /// Probe request (FC 0x0040) from `sta`, broadcast dest, given SSID.
    fn probe_req_frame(sta: &MacAddr, ssid: Option<&str>) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&0x0040u16.to_le_bytes());
        f.extend_from_slice(&0u16.to_le_bytes());
        f.extend_from_slice(&MacAddr::BROADCAST.0);
        f.extend_from_slice(&sta.0);
        f.extend_from_slice(&MacAddr::BROADCAST.0);
        f.extend_from_slice(&0u16.to_le_bytes());
        let s = ssid.unwrap_or("");
        f.push(0);
        f.push(s.len() as u8);
        f.extend_from_slice(s.as_bytes());
        f
    }

    /// Data frame sta → ap (ToDS): addr1=bssid, addr2=sta, addr3=da.
    fn data_frame_tods(bssid: &MacAddr, sta: &MacAddr) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&0x0108u16.to_le_bytes()); // data, ToDS
        f.extend_from_slice(&0u16.to_le_bytes());
        f.extend_from_slice(&bssid.0); // addr1 = bssid
        f.extend_from_slice(&sta.0); // addr2 = sta
        f.extend_from_slice(&[0u8; 6]); // addr3 = da
        f.extend_from_slice(&0u16.to_le_bytes());
        f.extend_from_slice(&[0u8; 8]); // llc/payload filler
        f
    }

    fn meta(rssi: i8, freq: u16) -> RxMeta {
        RxMeta {
            rssi_dbm: rssi,
            freq_mhz: freq,
        }
    }

    #[test]
    fn beacon_attached_creates_ap_with_ssid_and_channel() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut sc = Scanner::new(-85);
        let now: u64 = 0;
        sc.ingest(&meta(-42, 0), &beacon_frame(&ap(), "parafin", 6), now, &tx);
        match rx.try_recv() {
            Ok(Event::ApUpdated(a)) => {
                assert_eq!(a.bssid, ap());
                assert_eq!(a.ssid, "parafin");
                assert_eq!(a.channel, 6);
                assert_eq!(a.rssi_dbm, -42);
            }
            other => panic!("expected ApUpdated, got {other:?}"),
        }
    }

    #[test]
    fn beacon_uses_freq_hint_when_no_ds_ie() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut sc = Scanner::new(-85);
        let now: u64 = 0;
        let mut f = beacon_frame(&ap(), "parafin", 6);
        f.truncate(f.len() - 3); // drop DS IE
        sc.ingest(&meta(-40, 2437), &f, now, &tx);
        match rx.try_recv() {
            Ok(Event::ApUpdated(a)) => assert_eq!(a.channel, 6),
            other => panic!("expected ApUpdated, got {other:?}"),
        }
    }

    #[test]
    fn weak_beacon_not_created_but_update_accepted_later() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut sc = Scanner::new(-85);
        let now: u64 = 0;
        // -90 < floor: no event, no entry.
        sc.ingest(&meta(-90, 0), &beacon_frame(&ap(), "parafin", 6), now, &tx);
        assert!(rx.try_recv().is_err());
        assert!(sc.aps.is_empty());
        // Once created (hit stronger frame), later weak updates are accepted:
        // beacon counter still advances even though no event is emitted.
        sc.ingest(&meta(-60, 0), &beacon_frame(&ap(), "parafin", 6), now, &tx);
        assert!(rx.try_recv().is_ok());
        sc.ingest(&meta(-90, 0), &beacon_frame(&ap(), "parafin", 6), now, &tx);
        assert_eq!(sc.aps[&ap()].beacons, 2);
    }

    #[test]
    fn rssi_improvement_emits_update_worsening_does_not() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut sc = Scanner::new(-85);
        let now: u64 = 0;
        sc.ingest(&meta(-70, 0), &beacon_frame(&ap(), "parafin", 6), now, &tx);
        let _ = rx.try_recv(); // creation
        sc.ingest(&meta(-75, 0), &beacon_frame(&ap(), "parafin", 6), now, &tx);
        assert!(rx.try_recv().is_err()); // worse: silent
        sc.ingest(&meta(-50, 0), &beacon_frame(&ap(), "parafin", 6), now, &tx);
        match rx.try_recv() {
            Ok(Event::ApUpdated(a)) => assert_eq!(a.rssi_dbm, -50),
            other => panic!("expected ApUpdated improvement, got {other:?}"),
        }
    }

    #[test]
    fn probe_req_creates_client_and_data_freshens() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut sc = Scanner::new(-85);
        let now: u64 = 0;
        sc.ingest(&meta(-55, 0), &probe_req_frame(&sta(), Some("parafin")), now, &tx);
        match rx.try_recv() {
            Ok(Event::ClientUpdated(c)) => {
                assert_eq!(c.mac, sta());
                assert_eq!(c.ap, None);
            }
            other => panic!("expected ClientUpdated, got {other:?}"),
        }
        sc.ingest(&meta(-55, 0), &data_frame_tods(&ap(), &sta()), now, &tx);
        match rx.try_recv() {
            Ok(Event::ClientUpdated(c)) => assert_eq!(c.ap, Some(ap())),
            other => panic!("expected ClientUpdated with ap, got {other:?}"),
        }
        assert_eq!(sc.clients[&sta()].frames, 2);
    }

    #[test]
    fn multicast_ta_is_ignored() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut sc = Scanner::new(-85);
        let now: u64 = 0;
        let mcast = MacAddr([0x33, 0x33, 0, 0, 0, 1]);
        sc.ingest(&meta(-40, 0), &probe_req_frame(&mcast, None), now, &tx);
        assert!(rx.try_recv().is_err());
        assert!(sc.clients.is_empty());
    }

    #[test]
    fn aging_emits_ap_lost_and_drops_clients() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut sc = Scanner::new(-85);
        let t0: u64 = 1_000;
        sc.ingest(&meta(-40, 0), &beacon_frame(&ap(), "parafin", 6), t0, &tx);
        sc.ingest(&meta(-40, 0), &probe_req_frame(&sta(), None), t0, &tx);
        let _ = rx.try_recv();
        let _ = rx.try_recv();

        // 31 s later: AP expired, client still alive.
        let t1 = t0 + 31_000;
        sc.expire(t1, &tx);
        match rx.try_recv() {
            Ok(Event::ApLost(b)) => assert_eq!(b, ap()),
            other => panic!("expected ApLost, got {other:?}"),
        }
        assert!(sc.clients.contains_key(&sta()));

        // 61 s: client gone too.
        sc.expire(t0 + 61_000, &tx);
        assert!(sc.clients.is_empty());
    }

    #[test]
    fn freq_map_sanity() {
        assert_eq!(freq_to_channel(2412), Some(1));
        assert_eq!(freq_to_channel(2437), Some(6));
        assert_eq!(freq_to_channel(2472), Some(13));
        assert_eq!(freq_to_channel(2484), Some(14));
        assert_eq!(freq_to_channel(5180), Some(36));
        assert_eq!(freq_to_channel(5825), Some(165));
        assert_eq!(freq_to_channel(0), None);
    }
}
