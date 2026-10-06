//! Passive channel-hopping scanner: discovers APs (beacon/probe-response)
//! and client stations (probe-request + data frames), live-updating the UI
//! via [`Event`]s until `stop` flips true. Pure discovery — handshake
//! correlation happens in [`crate::handshake`].

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
// `Instant` is still used for dwell timing; timestamps going into shared
// types are `u64` millis (`crate::common::now_ms`) so they serialize.

use anyhow::{Context, Result};
use crossbeam_channel::Sender;

use crate::common::{
    AccessPoint, ChannelStat, ClientInfo, Event, HOP_FREQS_ALL, IdentConfidence, MacAddr,
    ProbeInfo, now_ms,
};
use crate::pcapout::PcapWriter;
use crate::radiotap::RxMeta;
use crate::rawsock::RawSocket;
use crate::{dot11, iface, radiotap};

/// APs go stale (ApLost) after this much silence (ms — `last_seen_ms`).
const AP_EXPIRE_MS: u64 = 30_000;
/// Clients go stale after this much silence (ms).
const CLIENT_EXPIRE_MS: u64 = 60_000;
/// Probe requests from the same (client, ssid) pair are re-emitted at
/// most this often — keeps the probe panel from drowning in retries.
const PROBE_DEDUP_MS: u64 = 60_000;
/// Sliding window for the foreign-deauth storm detector (ms).
const DEAUTH_WINDOW_MS: u64 = 10_000;
/// Deauths inside the window triggering a [`Event::DeauthAlert`].
const DEAUTH_ALERT_THRESHOLD: u32 = 10;
/// Per-pair cooldown after an alert fired (ms).
const DEAUTH_ALERT_COOLDOWN_MS: u64 = 30_000;
/// Max retained timestamps per (src, dst) pair (hard memory cap; the
/// window prune keeps it small in practice).
const DEAUTH_HIST_CAP: usize = 32;

// ---------------------------------------------------------------------------
// device identity groups (MAC-randomization pairing)
// ---------------------------------------------------------------------------

/// Pairing state for a single station MAC inside a group.
struct MacSeen {
    last_seen_ms: u64,
    last_seq: Option<u16>,
    /// Confidence assigned when THIS MAC joined (or first created) the
    /// group — assignment-time semantics; later frames only refresh times.
    conf: IdentConfidence,
}

/// One correlated physical radio: the set of MACs we have witnessed on it,
/// plus correlation keys (ordered-IE fingerprints it sent, SSIDs it probed
/// for, its WPS UUID).
struct IdGroup {
    id: u64,
    macs: HashMap<MacAddr, MacSeen>,
    fps: HashSet<u32>,
    /// SSIDs any member probed for (capped — a paranoia bound, not a rule).
    ssids: HashSet<String>,
    uuid: Option<[u8; 16]>,
}

/// Correlation book: pairs rotated/randomized MACs that belong to one
/// physical radio. Witnesses, strongest first: WPS UUID-E (the device
/// names itself), then shared ordered-IE fingerprint upgraded by a
/// per-frame witness — a shared probed SSID or uninterrupted 12-bit
/// sequence numbers across the rotation (seq continuity almost never
/// happens by chance: 1/4096 per direct successor pair).
struct GroupBook {
    groups: Vec<IdGroup>,
    mac_to_group: HashMap<MacAddr, usize>,
    fp_to_groups: HashMap<u32, Vec<usize>>,
    next_id: u64,
}

/// Group bookkeeping retention: group members and keys outlive the client
/// row by this long so a rotated MAC that appears *after* the old row
/// expired still lands in the same group. 15 min covers the typical
/// rotation cadence (iOS ~24 h per-network, Android on-screen ~10 min during
/// scanning bursts).
const GROUP_TTL_MS: u64 = 15 * 60 * 1000;

impl GroupBook {
    fn new() -> Self {
        Self {
            groups: Vec::new(),
            mac_to_group: HashMap::new(),
            fp_to_groups: HashMap::new(),
            next_id: 1,
        }
    }

    /// `(group id, assignment confidence)` for an already-assigned MAC.
    fn id_of(&self, mac: &MacAddr) -> Option<(u64, IdentConfidence)> {
        let &gi = self.mac_to_group.get(mac)?;
        let m = self.groups[gi].macs.get(mac)?;
        Some((self.groups[gi].id, m.conf))
    }

    /// Record one frame's worth of correlation material for `sta`.
    /// Returns `Some((group, confidence))` only when the MAC's group
    /// assignment was newly decided (first assignment or re-assignment
    /// after expiry) — callers emit [`Event::ClientIdent`] on Some.
    fn note(
        &mut self,
        sta: MacAddr,
        fp: u32,
        uuid: Option<[u8; 16]>,
        ssid: Option<&str>,
        seq: Option<u16>,
        now: u64,
    ) -> Option<(u64, IdentConfidence)> {
        if let Some(&gi) = self.mac_to_group.get(&sta) {
            let g = &mut self.groups[gi];
            if let Some(m) = g.macs.get_mut(&sta) {
                m.last_seen_ms = now;
                m.last_seq = seq.or(m.last_seq);
            }
            g.fps.insert(fp);
            if let Some(s) = ssid {
                if !s.is_empty() && g.ssids.len() < 64 {
                    g.ssids.insert(s.to_string());
                }
            }
            return None;
        }

        // UUID-E is a certain witness on its own: match it even when the
        // radio's IE chain changed so much the fingerprint misses (new
        // driver/firmware between rotations).
        let mut best: Option<(usize, IdentConfidence)> = uuid.and_then(|u| {
            self.groups
                .iter()
                .position(|g| g.uuid == Some(u) && !g.macs.contains_key(&sta))
                .map(|gi| (gi, IdentConfidence::Exact))
        });

        if best.is_none() {
            let mut hits: Vec<usize> = self.fp_to_groups.get(&fp).cloned().unwrap_or_default();
            hits.retain(|&gi| gi < self.groups.len());
            hits.sort_unstable();
            hits.dedup();
            for gi in hits {
                let g = &self.groups[gi];
                let fresh = g.macs.values().max_by_key(|m| m.last_seen_ms);
                let ssid_match =
                    ssid.is_some_and(|s| !s.is_empty() && g.ssids.contains(s));
                let seq_continues = seq
                    .zip(fresh.and_then(|m| m.last_seq))
                    .is_some_and(|(a, b)| {
                        let d = a.wrapping_sub(b);
                        d >= 1 && d <= 32
                    });
                let conf = if ssid_match || seq_continues {
                    IdentConfidence::Strong
                } else {
                    IdentConfidence::Probable
                };
                if best.is_none_or(|(_, c)| conf > c) {
                    best = Some((gi, conf));
                }
            }
        }

        let (gi, conf) = match best {
            Some(x) => x,
            None => {
                self.groups.push(IdGroup {
                    id: self.next_id,
                    macs: HashMap::new(),
                    fps: HashSet::new(),
                    ssids: HashSet::new(),
                    uuid: None,
                });
                self.next_id += 1;
                (self.groups.len() - 1, IdentConfidence::Probable)
            }
        };

        let g = &mut self.groups[gi];
        g.macs.insert(sta, MacSeen { last_seen_ms: now, last_seq: seq, conf });
        g.fps.insert(fp);
        if uuid.is_some() {
            g.uuid = uuid;
        }
        if let Some(s) = ssid {
            if !s.is_empty() && g.ssids.len() < 64 {
                g.ssids.insert(s.to_string());
            }
        }
        self.mac_to_group.insert(sta, gi);
        self.fp_to_groups.entry(fp).or_default().push(gi);
        Some((self.groups[gi].id, conf))
    }

    /// Reap members — and whole empty groups — past the pairing TTL.
    fn expire(&mut self, now: u64) {
        for g in self.groups.iter_mut() {
            g.macs.retain(|m, seen| {
                let live = now.saturating_sub(seen.last_seen_ms) <= GROUP_TTL_MS;
                if !live {
                    self.mac_to_group.remove(m);
                }
                live
            });
        }
        // Keep memory bounded against one-off probe storms: a group whose
        // members all reaped gives up its keys too.
        self.groups.retain(|g| !g.macs.is_empty());
        // Rebuild the secondary indexes so integer group positions stay
        // valid after retain-compaction.
        self.mac_to_group.clear();
        self.fp_to_groups.clear();
        for (gi, g) in self.groups.iter().enumerate() {
            for m in g.macs.keys() {
                self.mac_to_group.insert(*m, gi);
            }
            for fp in &g.fps {
                self.fp_to_groups.entry(*fp).or_default().push(gi);
            }
        }
    }
}

/// Push `now` onto `counts`, prune stamps older than the 10 s window, and
/// report `Some(n)` when the window holds ≥ [`DEAUTH_ALERT_THRESHOLD`]
/// stamps. Pure — unit-tested directly.
pub(crate) fn deauth_alert(counts: &mut VecDeque<u64>, now: u64) -> Option<u32> {
    counts.push_back(now);
    while counts.len() > DEAUTH_HIST_CAP {
        counts.pop_front();
    }
    while let Some(&t) = counts.front() {
        if now.saturating_sub(t) > DEAUTH_WINDOW_MS {
            counts.pop_front();
        } else {
            break;
        }
    }
    (counts.len() >= DEAUTH_ALERT_THRESHOLD as usize).then_some(counts.len() as u32)
}

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
    /// Channel arbitration with attack workers ([`iface::ChannelPin`]):
    /// nonzero → dwell on the pinned frequency instead of hopping.
    pub pin: Arc<iface::ChannelPin>,
    /// Own MAC of the monitor interface — deauth frames sourced from it
    /// are ours and must not trip the foreign-deauth detector.
    pub own_mac: MacAddr,
    /// BSSIDs we are deauthenticating on behalf of the user right now
    /// (our blasts use the AP as transmitter) — suppressed like `own_mac`.
    pub deauth_suppress: Arc<Mutex<HashSet<MacAddr>>>,
    /// Shared pcap spool writer (raw frames WITH radiotap header are
    /// appended in the recv loop). `None` = no spooling.
    pub spool: Option<Arc<Mutex<PcapWriter>>>,
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
    /// Own monitor-interface MAC + user-triggered deauth BSSIDs: frames
    /// sourced from these are suppressed in the storm detector.
    own_mac: MacAddr,
    deauth_suppress: Arc<Mutex<HashSet<MacAddr>>>,
    /// (client, probed-ssid) → last emit; 60 s suppression of repeats.
    probe_dedup: HashMap<(MacAddr, Option<String>), u64>,
    /// (deauth src, dst) → ms stamps inside the sliding window.
    deauth_hist: HashMap<(MacAddr, MacAddr), VecDeque<u64>>,
    /// (src, dst) → cooldown-until ms after a fired alert.
    alert_cooldown: HashMap<(MacAddr, MacAddr), u64>,
    /// MAC-randomization pairing: correlated device groups built from
    /// probe/assoc frames.
    groups: GroupBook,
}

impl Scanner {
    fn new(
        rssi_floor: i8,
        own_mac: MacAddr,
        deauth_suppress: Arc<Mutex<HashSet<MacAddr>>>,
    ) -> Self {
        Self {
            aps: BTreeMap::new(),
            clients: BTreeMap::new(),
            rssi_floor,
            own_mac,
            deauth_suppress,
            probe_dedup: HashMap::new(),
            deauth_hist: HashMap::new(),
            alert_cooldown: HashMap::new(),
            groups: GroupBook::new(),
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
                    if m.akms != ap.akms {
                        ap.akms = m.akms.clone();
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
                        akms: m.akms.clone(),
                    };
                    self.aps.insert(m.bssid, ap.clone());
                    let _ = tx.send(Event::ApUpdated(ap));
                }
            }
            return;
        }

        // Client probing.
        if let Some(ident) = dot11::parse_probe_ident(frame) {
            let sta = ident.sta;
            if sta.is_multicast() || sta.is_zero() {
                return;
            }
            // Probe panel: one event per (client, ssid) per 60 s — retries
            // from reconnect-happy phones would flood the UI otherwise.
            let key = (sta, ident.ssid.clone());
            let fresh = match self.probe_dedup.get(&key) {
                Some(&last) => now.saturating_sub(last) > PROBE_DEDUP_MS,
                None => true,
            };
            if fresh {
                self.probe_dedup.insert(key, now);
                let _ = tx.send(Event::ProbeObserved(ProbeInfo {
                    client: sta,
                    ssid: ident.ssid.clone(),
                    rssi_dbm: meta.rssi_dbm,
                    at_ms: now,
                }));
            }
            // Pairing first: the creation event from `note_client` then
            // already carries the group id (no follow-up stamp needed).
            self.note_ident(
                sta,
                ident.fingerprint,
                ident.uuid,
                ident.ssid.as_deref(),
                dot11::seq_of(frame),
                now,
                tx,
            );
            self.note_client(sta, None, meta, now, tx);
            return;
        }

        // Association/reassociation request: the station names the SSID it
        // joins — the only on-air witness that reveals a hidden AP's SSID.
        if let Some(ident) = dot11::parse_assoc_ident(frame) {
            let sta = ident.sta;
            if !sta.is_multicast() && !sta.is_zero() {
                // Pairing first: the creation event then already carries
                // the group id.
                self.note_ident(
                    sta,
                    ident.fingerprint,
                    ident.uuid,
                    ident.ssid.as_deref(),
                    dot11::seq_of(frame),
                    now,
                    tx,
                );
                self.note_client(sta, Some(ident.bssid), meta, now, tx);
            }
            if let Some(ssid) = ident.ssid
                && let Some(ap) = self.aps.get_mut(&ident.bssid)
                && ap.ssid.is_empty()
            {
                ap.ssid = ssid;
                ap.last_seen_ms = now;
                let _ = tx.send(Event::ApUpdated(ap.clone()));
            }
            return;
        }

        // Deauth/disassoc: flag the affected station disconnected so the UI
        // separates it now instead of waiting for 60 s of silence to expire
        // the row. Either side can be the station: AP → client (target) or
        // client-initiated (transmitter). Frames between unknown parties are
        // noise — we only flip state on stations we already track.
        if let Some((from, target)) = dot11::parse_deauth(frame) {
            self.track_foreign_deauth(from, target, now, tx);
            let sta = if !target.is_multicast() && !target.is_zero() {
                self.clients.contains_key(&target).then_some(target)
            } else {
                None
            }
            .or_else(|| {
                (!from.is_multicast() && !from.is_zero())
                    .then(|| self.clients.contains_key(&from).then_some(from))
                    .flatten()
            });
            if let Some(sta) = sta
                && let Some(c) = self.clients.get_mut(&sta)
                && c.connected
            {
                // State change only — repeated deauths against an already
                // flagged station are silent (no event storm).
                c.connected = false;
                let _ = tx.send(Event::ClientUpdated(c.clone()));
            }
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

    /// Foreign-deauth storm detector: ≥10 deauths/disassocs from one
    /// (src, dst) pair inside 10 s → one [`Event::DeauthAlert`], then a 30 s
    /// per-pair cooldown. Frames WE transmitted (monitor MAC as source, or
    /// an AP we're user-deauthing — our blasts carry its BSSID as addr2)
    /// never count.
    fn track_foreign_deauth(
        &mut self,
        from: MacAddr,
        target: MacAddr,
        now: u64,
        tx: &Sender<Event>,
    ) {
        if from == self.own_mac
            || self
                .deauth_suppress
                .lock()
                .map(|s| s.contains(&from))
                .unwrap_or(false)
        {
            return;
        }
        let key = (from, target);
        if self
            .alert_cooldown
            .get(&key)
            .is_some_and(|&until| now < until)
        {
            return;
        }
        let counts = self.deauth_hist.entry(key).or_default();
        if let Some(n) = deauth_alert(counts, now) {
            self.alert_cooldown
                .insert(key, now + DEAUTH_ALERT_COOLDOWN_MS);
            let _ = tx.send(Event::DeauthAlert {
                source: from,
                target,
                count: n,
            });
        }
    }

    /// MAC-randomization pairing: fold one frame's correlation material
    /// into the group book; emit [`Event::ClientIdent`] exactly once per
    /// pairing decision (first assignment or re-entry after expiry).
    fn note_ident(
        &mut self,
        sta: MacAddr,
        fp: u32,
        uuid: Option<[u8; 16]>,
        ssid: Option<&str>,
        seq: Option<u16>,
        now: u64,
        tx: &Sender<Event>,
    ) {
        let Some((group, confidence)) = self.groups.note(sta, fp, uuid, ssid, seq, now) else {
            return;
        };
        let _ = tx.send(Event::ClientIdent {
            mac: sta,
            group,
            confidence,
        });
        // If the station row already exists, stamp it so the ID column
        // reflects the pairing immediately (UI also overlays from its own
        // ident map — belt and suspenders for event-order observers).
        if let Some(c) = self.clients.get_mut(&sta) {
            c.ident_group = Some(group);
            c.ident_conf = Some(confidence);
            let _ = tx.send(Event::ClientUpdated(c.clone()));
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
                // Any frame from the station proves liveness: clear the
                // deauth-flagged disconnect (the flip rides the normal
                // `changed` emit below — no separate storm).
                if !c.connected {
                    c.connected = true;
                    changed = true;
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
                let ident = self.groups.id_of(&sta);
                let c = ClientInfo {
                    mac: sta,
                    ap,
                    rssi_dbm: meta.rssi_dbm,
                    frames: 1,
                    last_seen_ms: now,
                    connected: true,
                    ident_group: ident.map(|(g, _)| g),
                    ident_conf: ident.map(|(_, c)| c),
                };
                self.clients.insert(sta, c.clone());
                let _ = tx.send(Event::ClientUpdated(c));
            }
        }
    }

    /// Expire silent entries, emitting ApLost / ClientLost so the UI drops
    /// the rows too (stale clients must not accumulate on screen).
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
        let gone: Vec<MacAddr> = self
            .clients
            .iter()
            .filter(|(_, c)| now.saturating_sub(c.last_seen_ms) > CLIENT_EXPIRE_MS)
            .map(|(m, _)| *m)
            .collect();
        for m in gone {
            self.clients.remove(&m);
            let _ = tx.send(Event::ClientLost(m));
        }
        // Reap detector/dedup state alongside the row expiry so long
        // scans don't accumulate dead keys.
        self.probe_dedup
            .retain(|_, &mut last| now.saturating_sub(last) <= PROBE_DEDUP_MS);
        self.deauth_hist.retain(|_, q| {
            while let Some(&t) = q.front() {
                if now.saturating_sub(t) > DEAUTH_WINDOW_MS {
                    q.pop_front();
                } else {
                    break;
                }
            }
            !q.is_empty()
        });
        self.alert_cooldown.retain(|_, &mut until| now < until);
        self.groups.expire(now);
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

    let mut scanner = Scanner::new(cfg.rssi_floor, cfg.own_mac, cfg.deauth_suppress.clone());
    let mut buf = vec![0u8; 4096];
    let mut ch_idx = 0usize;
    let mut stats = ScanStats::default();
    let mut last_stats_log = Instant::now();
    // Cumulative per-channel counters → Event::ChannelStats every 2 s.
    let mut chan_hist: BTreeMap<u8, (u64, u64)> = BTreeMap::new();
    let mut last_chan_emit = Instant::now();
    // Spool error latch: 3 consecutive append failures → one log, then
    // the spool is dropped silently for the rest of the scan.
    let mut spool_failures: u32 = 0;
    let mut spool_enabled = cfg.spool.is_some();
    // Last frequency actually tuned — suppresses re-asserting the same
    // channel every dwell (iw spam) while the pin is steady.
    let mut last_set: u16 = 0;

    while !stop.load(Ordering::Relaxed) {
        // Channel arbitration: a nonzero pin (capture hold or deauth
        // override) wins over the hop plan for this cycle. While pinned
        // the hop index stands still — we resume the plan on release.
        let pinned = cfg.pin.get();
        let freq = if pinned != 0 {
            pinned
        } else {
            let f = freqs[ch_idx];
            ch_idx = (ch_idx + 1) % freqs.len();
            f
        };
        // Display channel number (2.4/5 GHz exact; 6 GHz reported as its
        // own channel number — cosmetic only).
        let cur_ch = freq_to_channel(freq).map(|c| c as i32).unwrap_or(-1);
        if freq != last_set {
            match iface::set_freq(&cfg.ifname, freq) {
                Ok(()) => last_set = freq,
                Err(e) => {
                    let _ = tx.send(Event::Log(format!(
                        "scanner: tune to {freq} MHz failed: {e:#}"
                    )));
                }
            }
        }

        // Drain frames until the dwell elapses (recv timeout bounds it).
        let dwell_start = Instant::now();
        loop {
            match sock.recv(&mut buf) {
                Ok(n) => {
                    stats.raw_frames_received += 1;
                    let now = now_ms();
                    // Pcap spool: the RAW frame straight off the socket,
                    // radiotap header included (linktype 127).
                    if spool_enabled && let Some(w) = &cfg.spool {
                        match w.lock() {
                            Ok(mut w) => match w.append(&buf[..n]) {
                                Ok(()) => spool_failures = 0,
                                Err(e) => {
                                    spool_failures += 1;
                                    if spool_failures >= 3 {
                                        spool_enabled = false;
                                        let _ = tx.send(Event::Log(format!(
                                            "pcap spool disabled: {e}"
                                        )));
                                    }
                                }
                            },
                            Err(e) => {
                                spool_failures += 1;
                                if spool_failures >= 3 {
                                    spool_enabled = false;
                                    let _ = tx.send(Event::Log(format!(
                                        "pcap spool disabled: {e}"
                                    )));
                                }
                            }
                        }
                    }
                    if let Some((meta, frame)) = radiotap::strip(&buf[..n]) {
                        stats.radiotap_strip_ok += 1;
                        // Per-channel attribution: trust the radiotap
                        // carrier frequency; fall back to the channel we
                        // last tuned to (radiotap freq is occasionally 0).
                        let ch = freq_to_channel(meta.freq_mhz)
                            .or_else(|| freq_to_channel(last_set));
                        let is_beacon_fc =
                            frame.len() >= 24 && (frame[0] == 0x80 || frame[0] == 0x50);
                        if let Some(ch) = ch {
                            let e = chan_hist.entry(ch).or_insert((0, 0));
                            e.0 += 1;
                            if is_beacon_fc {
                                e.1 += 1;
                            }
                        }
                        // Parser-independent witness: beacon (0x80) and
                        // probe-response (0x50) frames carry the transmitter
                        // BSSID at addr3 (bytes 16..22) before any IE parse.
                        if is_beacon_fc {
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

        // 2 s per-channel cumulative snapshot for the channel-activity UI.
        if last_chan_emit.elapsed() >= Duration::from_secs(2) {
            last_chan_emit = Instant::now();
            let snap: Vec<ChannelStat> = chan_hist
                .iter()
                .map(|(&channel, &(frames, beacons))| ChannelStat {
                    channel,
                    frames,
                    beacons,
                })
                .collect();
            let _ = tx.send(Event::ChannelStats(snap));
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

    /// Scanner under test: no suppression, unknown own MAC.
    fn test_scanner() -> Scanner {
        Scanner::new(
            -85,
            MacAddr::ZERO,
            Arc::new(Mutex::new(HashSet::new())),
        )
    }

    // -- frames with a caller-picked sequence number (pairing tests) ------

    fn ie_bytes(id: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![id, body.len() as u8];
        v.extend_from_slice(body);
        v
    }

    /// Probe request with full control over IEs and sequence number.
    fn probe_req_ies(sta: &MacAddr, ssid: Option<&str>, ies: &[Vec<u8>], seq: u16) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&0x0040u16.to_le_bytes()); // FC: probe request
        v.extend_from_slice(&0u16.to_le_bytes()); // duration
        v.extend_from_slice(&MacAddr::BROADCAST.0); // addr1
        v.extend_from_slice(&sta.0); // addr2
        v.extend_from_slice(&MacAddr::BROADCAST.0); // addr3
        v.extend_from_slice(&(seq << 4).to_le_bytes()); // seq<<4 | frag 0
        match ssid {
            Some(s) => v.extend_from_slice(&ie_bytes(dot11::IE_SSID, s.as_bytes())),
            None => v.extend_from_slice(&ie_bytes(dot11::IE_SSID, b"")),
        }
        for body in ies {
            v.extend_from_slice(body);
        }
        v
    }

    fn probe_seq(sta: &MacAddr, ssid: Option<&str>, seq: u16) -> Vec<u8> {
        let ies = [ie_bytes(1, &[0x82, 0x84, 0x8b, 0x96]), ie_bytes(50, &[0x0c, 0x12])];
        probe_req_ies(sta, ssid, &ies, seq)
    }

    /// Minimal WPS UUID-E attribute in a vendor IE.
    fn wps_uuid_ie(uuid: &[u8; 16]) -> Vec<u8> {
        let mut body = vec![0x00, 0x50, 0xf2, 0x04];
        body.extend_from_slice(&0x1047u16.to_be_bytes());
        body.extend_from_slice(&16u16.to_be_bytes());
        body.extend_from_slice(uuid);
        ie_bytes(dot11::IE_VENDOR, &body)
    }

    #[test]
    fn beacon_attached_creates_ap_with_ssid_and_channel() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut sc = test_scanner();
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
        let mut sc = test_scanner();
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
        let mut sc = test_scanner();
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
        let mut sc = test_scanner();
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
        let mut sc = test_scanner();
        let now: u64 = 0;
        sc.ingest(&meta(-55, 0), &probe_req_frame(&sta(), Some("parafin")), now, &tx);
        // Novel probe → ProbeObserved first, then the pairing decision,
        // then the client creation carrying the group id already.
        match rx.try_recv() {
            Ok(Event::ProbeObserved(p)) => {
                assert_eq!(p.client, sta());
                assert_eq!(p.ssid.as_deref(), Some("parafin"));
                assert_eq!(p.rssi_dbm, -55);
            }
            other => panic!("expected ProbeObserved, got {other:?}"),
        }
        match rx.try_recv() {
            Ok(Event::ClientIdent { mac, group, confidence }) => {
                assert_eq!(mac, sta());
                assert_eq!(confidence, IdentConfidence::Probable);
                let _ = group;
            }
            other => panic!("expected ClientIdent, got {other:?}"),
        }
        match rx.try_recv() {
            Ok(Event::ClientUpdated(c)) => {
                assert_eq!(c.mac, sta());
                assert_eq!(c.ap, None);
                assert_eq!(c.ident_group, Some(1), "creation carries the group id");
            }
            other => panic!("expected ClientUpdated, got {other:?}"),
        }
        // A repeat of the SAME probe inside 60 s is deduped — no
        // ProbeObserved (the client liveness refresh is silent here since
        // neither RSSI nor ap changed).
        sc.ingest(&meta(-55, 0), &probe_req_frame(&sta(), Some("parafin")), now, &tx);
        assert!(rx.try_recv().is_err());
        // A different SSID from the same client is a fresh observation.
        sc.ingest(&meta(-55, 0), &probe_req_frame(&sta(), None), now, &tx);
        match rx.try_recv() {
            Ok(Event::ProbeObserved(p)) => assert_eq!(p.ssid, None),
            other => panic!("expected ProbeObserved(wildcard), got {other:?}"),
        }
        sc.ingest(&meta(-55, 0), &data_frame_tods(&ap(), &sta()), now, &tx);
        match rx.try_recv() {
            Ok(Event::ClientUpdated(c)) => assert_eq!(c.ap, Some(ap())),
            other => panic!("expected ClientUpdated with ap, got {other:?}"),
        }
        assert_eq!(sc.clients[&sta()].frames, 4);
    }

    #[test]
    fn deauth_flags_client_disconnected_exactly_once() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut sc = test_scanner();
        let now: u64 = 0;
        sc.ingest(&meta(-55, 0), &probe_req_frame(&sta(), Some("parafin")), now, &tx);
        let _ = rx.try_recv(); // ProbeObserved
        let _ = rx.try_recv(); // ClientIdent (pairing decision)
        let _ = rx.try_recv(); // creation event
        assert!(sc.clients[&sta()].connected);

        // AP → client deauth: state flips, one update event.
        let f = dot11::build_deauth(&ap(), &sta(), 7);
        sc.ingest(&meta(-55, 0), &f, now, &tx);
        match rx.try_recv() {
            Ok(Event::ClientUpdated(c)) => {
                assert_eq!(c.mac, sta());
                assert!(!c.connected);
            }
            other => panic!("expected ClientUpdated(disconnected), got {other:?}"),
        }
        assert!(!sc.clients[&sta()].connected);

        // Repeated deauths against an already-flagged station: silent.
        sc.ingest(&meta(-55, 0), &f, now, &tx);
        sc.ingest(&meta(-55, 0), &f, now, &tx);
        assert!(rx.try_recv().is_err());
        assert!(!sc.clients[&sta()].connected);
    }

    #[test]
    fn client_frame_after_deauth_reconnects_it() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut sc = test_scanner();
        let now: u64 = 0;
        sc.ingest(&meta(-55, 0), &probe_req_frame(&sta(), Some("parafin")), now, &tx);
        let _ = rx.try_recv(); // ProbeObserved
        let _ = rx.try_recv(); // ClientIdent (pairing decision)
        let _ = rx.try_recv(); // creation
        sc.ingest(&meta(-50, 0), &dot11::build_deauth(&ap(), &sta(), 7), now, &tx);
        let _ = rx.try_recv(); // disconnect flip
        assert!(!sc.clients[&sta()].connected);

        // Station talks again: connected flips back true and the update
        // event fires.
        sc.ingest(&meta(-55, 0), &data_frame_tods(&ap(), &sta()), now, &tx);
        match rx.try_recv() {
            Ok(Event::ClientUpdated(c)) => {
                assert_eq!(c.mac, sta());
                assert!(c.connected);
            }
            other => panic!("expected ClientUpdated(reconnected), got {other:?}"),
        }
        assert!(sc.clients[&sta()].connected);
    }

    #[test]
    fn client_initiated_disassoc_flags_disconnect() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut sc = test_scanner();
        let now: u64 = 0;
        sc.ingest(&meta(-55, 0), &probe_req_frame(&sta(), None), now, &tx);
        let _ = rx.try_recv(); // ProbeObserved
        let _ = rx.try_recv(); // ClientIdent (pairing decision)
        let _ = rx.try_recv(); // creation

        // Disassoc (FC 0x00a0) sent BY the station: addr2 = transmitter.
        let mut f = Vec::new();
        f.extend_from_slice(&0x00a0u16.to_le_bytes());
        f.extend_from_slice(&0u16.to_le_bytes());
        f.extend_from_slice(&ap().0); // addr1 = ap
        f.extend_from_slice(&sta().0); // addr2 = client transmitter
        f.extend_from_slice(&ap().0); // addr3 = bssid
        f.extend_from_slice(&0u16.to_le_bytes()); // seq
        f.extend_from_slice(&8u16.to_le_bytes()); // reason: leaving
        sc.ingest(&meta(-55, 0), &f, now, &tx);
        match rx.try_recv() {
            Ok(Event::ClientUpdated(c)) => assert!(!c.connected),
            other => panic!("expected ClientUpdated(disconnected), got {other:?}"),
        }
        assert!(!sc.clients[&sta()].connected);
    }

    #[test]
    fn deauth_not_touching_a_known_client_is_ignored() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut sc = test_scanner();
        let now: u64 = 0;
        sc.ingest(&meta(-55, 0), &probe_req_frame(&sta(), None), now, &tx);
        let _ = rx.try_recv(); // ProbeObserved
        let _ = rx.try_recv(); // ClientIdent (pairing decision)
        let _ = rx.try_recv(); // creation

        // Unknown target: neither side tracked.
        let other: MacAddr = "de:ad:be:ef:00:01".parse().unwrap();
        sc.ingest(&meta(-50, 0), &dot11::build_deauth(&ap(), &other, 7), now, &tx);
        assert!(rx.try_recv().is_err());
        assert!(sc.clients[&sta()].connected);

        // Broadcast deauth from a tracked AP: broadcast is not a client
        // row, and (unless the AP is a client) nothing flips.
        sc.ingest(
            &meta(-50, 0),
            &dot11::build_deauth(&ap(), &MacAddr::BROADCAST, 7),
            now,
            &tx,
        );
        assert!(rx.try_recv().is_err());
        assert!(sc.clients[&sta()].connected);
    }

    #[test]
    fn multicast_ta_is_ignored() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut sc = test_scanner();
        let now: u64 = 0;
        let mcast = MacAddr([0x33, 0x33, 0, 0, 0, 1]);
        sc.ingest(&meta(-40, 0), &probe_req_frame(&mcast, None), now, &tx);
        assert!(rx.try_recv().is_err());
        assert!(sc.clients.is_empty());
    }

    #[test]
    fn aging_emits_ap_lost_and_drops_clients() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut sc = test_scanner();
        let t0: u64 = 1_000;
        sc.ingest(&meta(-40, 0), &beacon_frame(&ap(), "parafin", 6), t0, &tx);
        sc.ingest(&meta(-40, 0), &probe_req_frame(&sta(), None), t0, &tx);
        let _ = rx.try_recv(); // ApUpdated
        let _ = rx.try_recv(); // ProbeObserved
        let _ = rx.try_recv(); // ClientIdent (pairing decision)
        let _ = rx.try_recv(); // ClientUpdated

        // 31 s later: AP expired, client still alive.
        let t1 = t0 + 31_000;
        sc.expire(t1, &tx);
        match rx.try_recv() {
            Ok(Event::ApLost(b)) => assert_eq!(b, ap()),
            other => panic!("expected ApLost, got {other:?}"),
        }
        assert!(sc.clients.contains_key(&sta()));

        // 61 s: client gone too, with a ClientLost for the UI.
        sc.expire(t0 + 61_000, &tx);
        assert!(sc.clients.is_empty());
        match rx.try_recv() {
            Ok(Event::ClientLost(m)) => assert_eq!(m, sta()),
            other => panic!("expected ClientLost, got {other:?}"),
        }
    }

    #[test]
    fn deauth_alert_window_threshold() {
        let mut counts = VecDeque::new();
        // 9 stamps inside the window → no alert.
        for i in 0..9 {
            assert_eq!(deauth_alert(&mut counts, 1_000 + i * 100), None);
        }
        // The 10th inside 10 s trips it.
        assert_eq!(deauth_alert(&mut counts, 2_000), Some(10));
        // Stamps older than 10 s are pruned: now = 20_000 drops them all.
        assert_eq!(deauth_alert(&mut counts, 20_000), None);
        assert_eq!(counts.len(), 1);
    }

    #[test]
    fn deauth_storm_emits_alert_once_per_cooldown() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut sc = test_scanner();
        let now: u64 = 100_000;
        let evil: MacAddr = "66:77:88:99:aa:bb".parse().unwrap();
        // 9 deauths → silent; 10th → one alert.
        for i in 0..9u64 {
            sc.ingest(
                &meta(-40, 0),
                &dot11::build_deauth(&evil, &sta(), 7),
                now + i,
                &tx,
            );
        }
        assert!(rx.try_recv().is_err());
        sc.ingest(&meta(-40, 0), &dot11::build_deauth(&evil, &sta(), 7), now + 9, &tx);
        match rx.try_recv() {
            Ok(Event::DeauthAlert {
                source,
                target,
                count,
            }) => {
                assert_eq!(source, evil);
                assert_eq!(target, sta());
                assert_eq!(count, 10);
            }
            other => panic!("expected DeauthAlert, got {other:?}"),
        }
        // Cooldown: further deauths inside 30 s stay silent.
        for i in 0..15u64 {
            sc.ingest(
                &meta(-40, 0),
                &dot11::build_deauth(&evil, &sta(), 7),
                now + 100 + i,
                &tx,
            );
        }
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn own_deauth_sources_are_suppressed() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let own: MacAddr = "02:11:22:33:44:55".parse().unwrap();
        let suppress: Arc<Mutex<HashSet<MacAddr>>> = Arc::new(Mutex::new(HashSet::new()));
        suppress.lock().unwrap().insert(ap());
        let mut sc = Scanner::new(-85, own, suppress);
        let now: u64 = 100_000;
        // Blasts from our monitor MAC and from the user-deauthed AP both
        // stay silent even past the threshold.
        for i in 0..20u64 {
            sc.ingest(&meta(-40, 0), &dot11::build_deauth(&own, &sta(), 7), now + i, &tx);
            sc.ingest(&meta(-40, 0), &dot11::build_deauth(&ap(), &sta(), 7), now + i, &tx);
        }
        assert!(rx.try_recv().is_err());
    }

    /// Hidden-SSID beacon (zero-len SSID IE) followed by an assoc request
    /// naming the real SSID: the AP row gains the name.
    #[test]
    fn assoc_req_reveals_hidden_ssid() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut sc = test_scanner();
        let now: u64 = 0;
        // Beacon with empty SSID.
        sc.ingest(&meta(-45, 0), &beacon_frame(&ap(), "", 6), now, &tx);
        match rx.try_recv() {
            Ok(Event::ApUpdated(a)) => assert_eq!(a.ssid, ""),
            other => panic!("expected ApUpdated(hidden), got {other:?}"),
        }
        // Assoc request: FC 0x0000, addr1=bssid, addr2=sta, fixed params,
        // SSID IE with the real name.
        let mut f = Vec::new();
        f.extend_from_slice(&0x0000u16.to_le_bytes());
        f.extend_from_slice(&0u16.to_le_bytes());
        f.extend_from_slice(&ap().0); // addr1 = bssid
        f.extend_from_slice(&sta().0); // addr2 = station
        f.extend_from_slice(&ap().0); // addr3 = bssid
        f.extend_from_slice(&0u16.to_le_bytes()); // seq
        f.extend_from_slice(&0u16.to_le_bytes()); // capability
        f.extend_from_slice(&10u16.to_le_bytes()); // listen interval
        f.push(0); // SSID IE
        f.push(7);
        f.extend_from_slice(b"parafin");
        sc.ingest(&meta(-50, 0), &f, now, &tx);
        // Pairing decision first, then client creation, then the ApUpdated
        // revealing the ssid.
        match rx.try_recv() {
            Ok(Event::ClientIdent { mac, .. }) => assert_eq!(mac, sta()),
            other => panic!("expected ClientIdent, got {other:?}"),
        }
        match rx.try_recv() {
            Ok(Event::ClientUpdated(c)) => assert_eq!(c.ap, Some(ap())),
            other => panic!("expected ClientUpdated, got {other:?}"),
        }
        match rx.try_recv() {
            Ok(Event::ApUpdated(a)) => {
                assert_eq!(a.bssid, ap());
                assert_eq!(a.ssid, "parafin");
            }
            other => panic!("expected ApUpdated(revealed), got {other:?}"),
        }
        assert_eq!(sc.aps[&ap()].ssid, "parafin");
    }

    // -- MAC-randomization pairing ---------------------------------------

    /// Pop events up to and including the next ClientIdent (probe-panel
    /// and client-row events are ingestion noise for pairing tests).
    fn expect_ident(
        rx: &crossbeam_channel::Receiver<Event>,
    ) -> (MacAddr, u64, IdentConfidence) {
        loop {
            match rx.try_recv() {
                Ok(Event::ClientIdent { mac, group, confidence }) => {
                    return (mac, group, confidence);
                }
                Ok(_) => continue,
                Err(e) => panic!("expected ClientIdent, got {e:?}"),
            }
        }
    }

    fn drain(rx: &crossbeam_channel::Receiver<Event>) {
        while rx.try_recv().is_ok() {}
    }

    #[test]
    fn pairing_shared_ssid_pairs_rotated_macs() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut sc = test_scanner();
        let now: u64 = 0;
        let m1: MacAddr = "02:aa:aa:aa:aa:01".parse().unwrap();
        let m2: MacAddr = "06:bb:bb:bb:bb:02".parse().unwrap();

        sc.ingest(&meta(-50, 0), &probe_seq(&m1, Some("parafin"), 7), now, &tx);
        let (mac, g1, conf) = expect_ident(&rx);
        assert_eq!(mac, m1);
        assert_eq!(conf, IdentConfidence::Probable);
        sc.ingest(&meta(-48, 0), &probe_seq(&m2, Some("parafin"), 8), now + 1, &tx);
        let (mac, g2, conf) = expect_ident(&rx);
        // Same IE chain + same probed SSID = same radio, strong witness.
        assert_eq!(mac, m2);
        assert_eq!(g2, g1, "rotated MAC lands in the same group");
        assert_eq!(conf, IdentConfidence::Strong);
        // Second frame from m1: no new pairing events.
        sc.ingest(&meta(-49, 0), &probe_seq(&m1, None, 9), now + 2, &tx);
        drain(&rx);
        assert!(rx.try_recv().is_err());
        assert!(sc.groups.id_of(&m1).is_some() && sc.groups.id_of(&m2).is_some());
    }

    #[test]
    fn pairing_seq_continuity_witness() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut sc = test_scanner();
        let now: u64 = 0;
        let m1: MacAddr = "02:aa:aa:aa:aa:01".parse().unwrap();
        let m2: MacAddr = "06:cc:cc:cc:cc:03".parse().unwrap();

        sc.ingest(&meta(-50, 0), &probe_seq(&m1, None, 100), now, &tx);
        let _ = expect_ident(&rx);
        // Wildcard probes (no shared SSID), but the sequence counter
        // continues uninterrupted across the rotation.
        sc.ingest(&meta(-50, 0), &probe_seq(&m2, None, 101), now + 1, &tx);
        let (_, _, conf) = expect_ident(&rx);
        assert_eq!(conf, IdentConfidence::Strong);
        // A gap beyond the window is NOT continuity: downgrade.
        let m3: MacAddr = "0e:dd:dd:dd:dd:04".parse().unwrap();
        sc.ingest(&meta(-50, 0), &probe_seq(&m3, None, 200), now + 2, &tx);
        // m3 shares the fingerprint with the group's members, but seq 200
        // vs last 101 is 99 away → probable only.
        let (_, _, conf) = expect_ident(&rx);
        assert_eq!(conf, IdentConfidence::Probable);
    }

    #[test]
    fn pairing_uuid_e_is_exact() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut sc = test_scanner();
        let now: u64 = 0;
        let m1: MacAddr = "02:aa:aa:aa:aa:01".parse().unwrap();
        let m2: MacAddr = "06:ee:ee:ee:ee:05".parse().unwrap();
        let uuid = [0xABu8; 16];

        let f1 = probe_req_ies(&m1, Some("parafin"), &[wps_uuid_ie(&uuid)], 7);
        sc.ingest(&meta(-50, 0), &f1, now, &tx);
        let _ = expect_ident(&rx);
        let f2 = probe_req_ies(&m2, None, &[wps_uuid_ie(&uuid)], 9);
        sc.ingest(&meta(-50, 0), &f2, now + 1, &tx);
        let (mac, g2, conf) = expect_ident(&rx);
        assert_eq!(mac, m2);
        assert_eq!(conf, IdentConfidence::Exact, "UUID-E is a certain witness");
        // Same UUID but a COMPLETELY different IE chain (firmware update
        // between rotations, fingerprint unusable) still pairs.
        let m3: MacAddr = "0a:dd:dd:dd:dd:07".parse().unwrap();
        let f3 = probe_req_ies(
            &m3,
            None,
            &[ie_bytes(3, &[1u8]), wps_uuid_ie(&uuid)],
            40,
        );
        sc.ingest(&meta(-50, 0), &f3, now + 2, &tx);
        let (mac, g3, conf) = expect_ident(&rx);
        assert_eq!(mac, m3);
        assert_eq!(g3, g2, "UUID-E pairs across a fingerprint break");
        assert_eq!(conf, IdentConfidence::Exact);
    }

    #[test]
    fn pairing_different_fingerprints_stay_separate() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut sc = test_scanner();
        let now: u64 = 0;
        let m1: MacAddr = "02:aa:aa:aa:aa:01".parse().unwrap();
        let m2: MacAddr = "06:bb:bb:bb:bb:02".parse().unwrap();

        sc.ingest(&meta(-50, 0), &probe_seq(&m1, Some("parafin"), 7), now, &tx);
        let (_, g1, _) = expect_ident(&rx);
        // Same probed SSID, DIFFERENT IE chain → different device class.
        let other = probe_req_ies(
            &m2,
            Some("parafin"),
            &[ie_bytes(1, &[0x82, 0x84]), ie_bytes(3, &[6u8])],
            8,
        );
        sc.ingest(&meta(-50, 0), &other, now + 1, &tx);
        let (_, g2, _) = expect_ident(&rx);
        assert_ne!(g1, g2, "fingerprint mismatch keeps radios separate");
    }

    #[test]
    fn pairing_groups_outlive_client_rows() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut sc = test_scanner();
        let t0: u64 = 100_000;
        let m1: MacAddr = "02:aa:aa:aa:aa:01".parse().unwrap();
        let m2: MacAddr = "06:ff:ff:ff:ff:06".parse().unwrap();

        sc.ingest(&meta(-50, 0), &probe_seq(&m1, Some("parafin"), 7), t0, &tx);
        let (_, g1, _) = expect_ident(&rx);
        // Client row expires (60 s), but the group lives for minutes.
        sc.expire(t0 + 61_000, &tx);
        drain(&rx);
        // The rotated MAC appears late and still pairs (shared SSID).
        sc.ingest(&meta(-46, 0), &probe_seq(&m2, Some("parafin"), 8), t0 + 65_000, &tx);
        let (_, g2, conf) = expect_ident(&rx);
        assert_eq!(g1, g2, "group identity survives the client-row TTL");
        assert_eq!(conf, IdentConfidence::Strong);
        // Full TTL (15 min) expiry destroys the group.
        sc.ingest(&meta(-50, 0), &probe_seq(&m2, None, 9), t0 + 65_000, &tx);
        sc.expire(t0 + 65_000 + GROUP_TTL_MS + 1, &tx);
        assert!(sc.groups.id_of(&m1).is_none());
        assert!(sc.groups.id_of(&m2).is_none());
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
