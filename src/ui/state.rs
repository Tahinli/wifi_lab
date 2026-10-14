//! Application state: the UI-side home for everything arriving over the
//! service event channel (mock thread or privileged-service reader).

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use crate::common::{
    AccessPoint, ChannelStat, ClientInfo, Event, HandshakeCapture, IdentConfidence, MacAddr,
    PmkidCapture, ProbeInfo, Security,
};
use crate::crypto::CrackTarget;

/// Ring capacity of the on-screen log.
pub const LOG_CAP: usize = 500;

/// Live status of the (currently simulated) handshake cracker.
#[derive(Default)]
pub struct CrackerState {
    /// Human description of the selected capture (see [`AppState::capture_descs`]).
    pub target: Option<String>,
    pub wordlist: Option<String>,
    pub running: bool,
    /// Guesses per second.
    pub hps: f64,
    /// Candidates tried so far.
    pub tried: u64,
    /// Recovered password, once found.
    pub found: Option<String>,
    /// Rainbow-table build job in flight (RainbowProgress feeds the
    /// counters, RainbowBuilt clears the flag).
    pub rainbow_building: bool,
    /// PMKs written by the running build job.
    pub rainbow_done: u64,
    /// Build job throughput.
    pub rainbow_hps: f64,
    /// Worst-case candidate total of the running crack (wordlist lines /
    /// brute-force space / table entries), when countable.
    pub total: Option<u64>,
    /// Worst-case size of the table being built (wordlist lines).
    pub rainbow_total: Option<u64>,
    /// The currently running attack, tracked so the UI can persist a
    /// resume session ([`crate::store::CrackSession`]) without the
    /// worker's cooperation. Cleared when the run settles.
    pub active_attack: Option<crate::attack::Attack>,
    /// A saved, interrupted run matched against a loaded capture —
    /// shown as a resume banner on the cracker page.
    pub resume: Option<ResumeInfo>,
}

/// Saved-run banner payload (mirror of [`crate::store::CrackSession`]
/// resolved to the capture's current description).
#[derive(Clone)]
pub struct ResumeInfo {
    /// Dropdown description of the capture this run belongs to.
    pub target_desc: String,
    /// Attack definition at the saved candidate offset.
    pub attack: crate::attack::Attack,
    /// Candidates already tried when the run was saved.
    pub done: u64,
    /// Worst-case total of the saved run, when countable.
    pub total: Option<u64>,
}

/// Everything the window renders. Updated exclusively by
/// [`AppState::apply`] so a real service can reuse the reduction logic.
pub struct AppState {
    /// Whether the interface is (pretending to be) capturing in monitor mode.
    pub iface_running: bool,
    pub ifname: String,
    pub aps: BTreeMap<MacAddr, AccessPoint>,
    pub clients: BTreeMap<MacAddr, ClientInfo>,
    /// User-assigned names by MAC (APs and clients share one namespace;
    /// a MAC is unique). Persisted to `~/wifilab/labels.json`
    /// ([`crate::store`]); UI-side only.
    pub labels: BTreeMap<MacAddr, String>,
    pub handshakes: Vec<HandshakeCapture>,
    pub pmkids: Vec<PmkidCapture>,
    /// [`capture_descs`]-aligned crack targets: `capture_targets()[i]` is
    /// the [`CrackTarget`] described by `capture_descs()[i]`, so the
    /// cracker starts a run without re-parsing an hc22000 line.
    capture_targets: Vec<CrackTarget>,
    pub log: VecDeque<String>,
    pub cracker: CrackerState,
    /// Last per-channel frame/beacon counters snapshot
    /// ([`Event::ChannelStats`]).
    pub channel_stats: Vec<ChannelStat>,
    /// Observed probe requests, newest last.
    pub probes: VecDeque<ProbeInfo>,
    /// Recent RSSI samples per MAC (APs and clients keyed by their own
    /// MAC) — the Networks page renders these as sparklines.
    pub rssi_hist: HashMap<MacAddr, VecDeque<i8>>,
    /// Normalized (trim, lowercase) SSIDs observed on more than one BSSID
    /// with differing security — possible rogue APs.
    pub rogue_ssids: HashSet<String>,
    /// One-shot rogue-AP alert message; taken by the app drain into a toast.
    pub rogue_alert: Option<String>,
    /// One-shot deauth-storm alert message; taken by the app drain into a
    /// toast.
    pub deauth_alert: Option<String>,
    /// Last benchmark throughput (H/s); `None` = no GPU / not run yet.
    pub bench_gpu: Option<f64>,
    pub bench_cpu: Option<f64>,
    /// MAC-randomization pairing ([`Event::ClientIdent`]): device-group id +
    /// confidence per correlated MAC. Outlives the client row (groups keep
    /// their members while any one of them is live).
    pub idents: HashMap<MacAddr, (u64, IdentConfidence)>,
    /// Reverse view per group: set of currently-known member MACs (live
    /// rows + remembered) — the Networks page shows "N MACs" per device.
    pub ident_groups: HashMap<u64, HashSet<MacAddr>>,
    /// One-shot pairing alert ("device rotated MAC, paired into group #N");
    /// taken by the app drain into a toast.
    pub ident_alert: Option<String>,
    /// SSID (normalized) → BSSID → security seen, backing `rogue_ssids`.
    seen_ssids: BTreeMap<String, BTreeMap<MacAddr, Security>>,
    /// ChannelStats time-series, one entry per snapshot, oldest first
    /// (~3 min at the scanner's 2 s cadence) — the Networks page renders
    /// it as a scrolling per-channel activity timeline.
    pub chan_timeline: VecDeque<Vec<ChannelStat>>,
    /// Crack H/s samples, one per [`Event::CrackProgress`] of the current
    /// run (cleared at run start) — the Cracker page renders it as a
    /// throughput curve.
    pub hps_hist: VecDeque<f64>,
}

/// Cap on [`AppState::probes`] (oldest dropped first).
const PROBE_CAP: usize = 2000;

/// RSSI samples kept per MAC in [`AppState::rssi_hist`].
const RSSI_CAP: usize = 60;

/// ChannelStats snapshots kept in [`AppState::chan_timeline`].
const CHAN_TL_CAP: usize = 90;

/// H/s samples kept in [`AppState::hps_hist`].
const HPS_CAP: usize = 240;

impl AppState {
    pub fn new(ifname: &str) -> Self {
        AppState {
            iface_running: false,
            ifname: ifname.to_string(),
            aps: BTreeMap::new(),
            clients: BTreeMap::new(),
            labels: BTreeMap::new(),
            handshakes: Vec::new(),
            pmkids: Vec::new(),
            capture_targets: Vec::new(),
            log: VecDeque::with_capacity(LOG_CAP),
            cracker: CrackerState::default(),
            channel_stats: Vec::new(),
            probes: VecDeque::with_capacity(64),
            rssi_hist: HashMap::new(),
            rogue_ssids: HashSet::new(),
            rogue_alert: None,
            deauth_alert: None,
            bench_gpu: None,
            bench_cpu: None,
            idents: HashMap::new(),
            ident_groups: HashMap::new(),
            ident_alert: None,
            seen_ssids: BTreeMap::new(),
            chan_timeline: VecDeque::with_capacity(CHAN_TL_CAP + 1),
            hps_hist: VecDeque::with_capacity(HPS_CAP + 1),
        }
    }

    /// Append one RSSI sample for `mac` (APs and clients keyed by their
    /// own MAC), capping the per-MAC history.
    fn note_rssi(&mut self, mac: MacAddr, rssi_dbm: i8) {
        let hist = self.rssi_hist.entry(mac).or_default();
        if hist.len() == RSSI_CAP {
            hist.pop_front();
        }
        hist.push_back(rssi_dbm);
    }

    /// Normalize an SSID for rogue comparison (trim + lowercase).
    fn norm_ssid(ssid: &str) -> String {
        ssid.trim().to_lowercase()
    }

    /// Crack target described by `capture_descs()[i]` (cloned — the cracker
    /// worker takes ownership).
    pub fn crack_target_at(&self, i: usize) -> Option<CrackTarget> {
        self.capture_targets.get(i).cloned()
    }

    /// The same capture as a [`crate::store::StoredCapture`] (resume
    /// session identity), `capture_descs()`-aligned like
    /// [`AppState::crack_target_at`]: handshakes first, then PMKIDs.
    pub fn stored_capture_at(&self, i: usize) -> Option<crate::store::StoredCapture> {
        if i < self.handshakes.len() {
            return Some(crate::store::StoredCapture::Handshake(self.handshakes[i].clone()));
        }
        self.pmkids
            .get(i - self.handshakes.len())
            .map(|p| crate::store::StoredCapture::Pmkid(p.clone()))
    }

    pub fn push_log(&mut self, line: impl Into<String>) {
        if self.log.len() == LOG_CAP {
            self.log.pop_front();
        }
        self.log.push_back(line.into());
    }

    /// Reduce one service event into state. Returns `true` when the set of
    /// crackable captures changed (callers rebuild dependent widgets).
    pub fn apply(&mut self, event: Event) -> bool {
        let changed = self.reduce(event);
        self.sweep_stale_clients();
        changed
    }

    /// Backstop mirror of the scanner's 60 s client-expiry: rows learned
    /// before a scanner restart (the restart wipes the scanner's internal
    /// map, so no ClientLost can ever come for them) would linger as "up"
    /// forever without this. Clock-offset between the service and UI
    /// epochs (both `now_ms`, different process-local zero points) is a
    /// few seconds at most — negligible against a 60 s threshold.
    fn sweep_stale_clients(&mut self) {
        const UI_CLIENT_EXPIRE_MS: u64 = 60_000;
        let now = crate::common::now_ms();
        let swept: Vec<MacAddr> = self
            .clients
            .iter()
            .filter(|(_, c)| now.saturating_sub(c.last_seen_ms) > UI_CLIENT_EXPIRE_MS)
            .map(|(m, _)| *m)
            .collect();
        for m in swept {
            self.clients.remove(&m);
            self.forget_ident(&m);
        }
    }

    /// Drop a MAC's pairing record (client row gone).
    fn forget_ident(&mut self, mac: &MacAddr) {
        if let Some((gid, _)) = self.idents.remove(mac) {
            if let Some(set) = self.ident_groups.get_mut(&gid) {
                set.remove(mac);
                if set.is_empty() {
                    self.ident_groups.remove(&gid);
                }
            }
        }
    }

    fn reduce(&mut self, event: Event) -> bool {
        match event {
            Event::ApUpdated(ap) => {
                self.note_rssi(ap.bssid, ap.rssi_dbm);
                // Rogue detection: the same non-empty SSID advertised by a
                // *different* BSSID with *different* security settings is
                // the classic evil-twin smell (same security on multi-AP
                // deployments is normal).
                let norm = Self::norm_ssid(&ap.ssid);
                if !norm.is_empty() {
                    let entry = self.seen_ssids.entry(norm.clone()).or_default();
                    if !self.rogue_ssids.contains(&norm) {
                        let conflict = entry
                            .iter()
                            .find(|(b, sec)| **b != ap.bssid && **sec != ap.security);
                        if let Some((known, sec1)) = conflict {
                            self.rogue_ssids.insert(norm.clone());
                            self.rogue_alert = Some(format!(
                                "possible rogue AP: \"{}\" on {} ({}) vs {} ({})",
                                norm,
                                known,
                                sec1.label(),
                                ap.bssid,
                                ap.security.label()
                            ));
                        }
                    }
                    entry.insert(ap.bssid, ap.security);
                }
                self.aps.insert(ap.bssid, ap);
                false
            }
            Event::ApLost(bssid) => {
                self.aps.remove(&bssid);
                false
            }
            Event::ClientUpdated(mut client) => {
                self.note_rssi(client.mac, client.rssi_dbm);
                // Overlay the known pairing (the wire fields may lag or be
                // absent for clients learned before this process knew the
                // group).
                if let Some(&(gid, conf)) = self.idents.get(&client.mac) {
                    client.ident_group = Some(gid);
                    client.ident_conf = Some(conf);
                }
                self.clients.insert(client.mac, client);
                false
            }
            Event::ClientLost(mac) => {
                self.clients.remove(&mac);
                self.forget_ident(&mac);
                false
            }
            Event::ClientIdent { mac, group, confidence } => {
                let rotated = self
                    .ident_groups
                    .get(&group)
                    .is_some_and(|ms| ms.iter().any(|m| *m != mac));
                self.idents.insert(mac, (group, confidence));
                self.ident_groups.entry(group).or_default().insert(mac);
                // Message names the whole rotation set — the actionable fact
                // is "these N MACs are one radio".
                let n = self.ident_groups.get(&group).map_or(1, |ms| ms.len());
                let msg = format!(
                    "device paired: {mac} → group #{group} ({n} MAC{}) [{}]",
                    if n == 1 { "" } else { "s" },
                    confidence.label()
                );
                self.push_log(msg.clone());
                if rotated {
                    self.ident_alert = Some(msg);
                }
                // Live row gets the badge immediately.
                if let Some(c) = self.clients.get_mut(&mac) {
                    c.ident_group = Some(group);
                    c.ident_conf = Some(confidence);
                }
                false
            }
            Event::HandshakeProgress { ap, client, have } => {
                self.push_log(format!(
                    "4-way {ap} → {client}: {}/4 messages",
                    have.count_ones()
                ));
                false
            }
            Event::HandshakeComplete(cap) => {
                self.push_log(format!(
                    "handshake captured: {} ({} ⇄ {})",
                    cap.essid, cap.ap, cap.client
                ));
                self.capture_targets
                    .push(CrackTarget::Handshake(cap.as_ref().clone()));
                self.handshakes.push(*cap);
                true
            }
            Event::PmkidCaptured(cap) => {
                self.push_log(format!("PMKID captured: {} ({})", cap.essid, cap.ap));
                self.capture_targets
                    .push(CrackTarget::Pmkid(cap.clone()));
                self.pmkids.push(cap);
                true
            }
            Event::DeauthSent { ap, target, count } => {
                self.push_log(format!("deauth: {count} frames → {target} (AP {ap})"));
                false
            }
            Event::CrackProgress { done, hps, total } => {
                if self.cracker.running {
                    self.cracker.tried = done;
                    self.cracker.hps = hps;
                    self.cracker.total = total;
                    if self.hps_hist.len() == HPS_CAP {
                        self.hps_hist.pop_front();
                    }
                    self.hps_hist.push_back(hps);
                }
                false
            }
            Event::CrackFound { password } => {
                self.push_log(format!("PASSWORD FOUND: {password}"));
                self.cracker.found = Some(password);
                false
            }
            Event::CrackStopped { found } => {
                self.push_log(format!(
                    "cracker: run ended ({})",
                    if found { "password recovered" } else { "stopped/exhausted" }
                ));
                self.cracker.running = false;
                true // force dependent-widget refresh so the cracker page updates promptly
            }
            Event::RainbowProgress { done, hps, total } => {
                if self.cracker.rainbow_building {
                    self.cracker.rainbow_done = done;
                    self.cracker.rainbow_hps = hps;
                    self.cracker.rainbow_total = total;
                }
                false
            }
            Event::RainbowBuilt { path, entries } => {
                self.push_log(format!("rainbow: table finished: {path} ({entries} PMKs)"));
                self.cracker.rainbow_building = false;
                false
            }
            Event::Log(line) => {
                self.push_log(line);
                false
            }
            Event::Error(line) => {
                self.push_log(format!("ERROR: {line}"));
                false
            }
            Event::ChannelStats(stats) => {
                if self.chan_timeline.len() == CHAN_TL_CAP {
                    self.chan_timeline.pop_front();
                }
                self.chan_timeline.push_back(stats.clone());
                self.channel_stats = stats;
                false
            }
            Event::ProbeObserved(probe) => {
                self.note_rssi(probe.client, probe.rssi_dbm);
                if self.probes.len() == PROBE_CAP {
                    self.probes.pop_front();
                }
                self.probes.push_back(probe);
                false
            }
            Event::BenchmarkDone { gpu_hps, cpu_hps } => {
                self.bench_gpu = gpu_hps;
                self.bench_cpu = Some(cpu_hps);
                self.push_log(format!(
                    "benchmark: gpu {} H/s, cpu {} H/s",
                    gpu_hps.map(|h| h.to_string()).unwrap_or_else(|| "none".to_string()),
                    cpu_hps
                ));
                false
            }
            Event::DeauthAlert { source, target, count } => {
                let msg = format!("DEAUTH STORM: {source} → {target} x{count}");
                self.push_log(msg.clone());
                self.deauth_alert = Some(msg);
                false
            }
            Event::CaptureImported(cap) => {
                match cap {
                    crate::common::ImportedCapture::Handshake(h) => {
                        self.push_log(format!(
                            "imported handshake: {} ({} ⇄ {})",
                            h.essid, h.ap, h.client
                        ));
                        self.capture_targets
                            .push(CrackTarget::Handshake(h.as_ref().clone()));
                        self.handshakes.push(*h);
                    }
                    crate::common::ImportedCapture::Pmkid(p) => {
                        self.push_log(format!("imported PMKID: {} ({})", p.essid, p.ap));
                        self.capture_targets.push(CrackTarget::Pmkid(p.clone()));
                        self.pmkids.push(p);
                    }
                }
                true
            }
        }
    }

    /// Stable, unique descriptions of every crackable capture — the cracker's
    /// target dropdown is fed with these (index prefix keeps duplicates
    /// apart).
    pub fn capture_descs(&self) -> Vec<String> {
        let mut out = Vec::with_capacity(self.handshakes.len() + self.pmkids.len());
        for (i, hs) in self.handshakes.iter().enumerate() {
            out.push(format!(
                "#{:02} HS {} {} ⇄ {} kv{}",
                i + 1,
                hs.essid,
                hs.ap,
                hs.client,
                hs.key_ver
            ));
        }
        for (i, pm) in self.pmkids.iter().enumerate() {
            out.push(format!("#{:02} PMKID {} {}", i + 1, pm.essid, pm.ap));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat(ch: u8, frames: u64) -> ChannelStat {
        ChannelStat { channel: ch, frames, beacons: 0 }
    }

    #[test]
    fn channel_timeline_keeps_snapshots_and_caps() {
        let mut s = AppState::new("wlan0");
        for i in 0..(CHAN_TL_CAP + 5) {
            s.apply(Event::ChannelStats(vec![stat(1, i as u64 + 1)]));
        }
        assert_eq!(s.chan_timeline.len(), CHAN_TL_CAP);
        // Oldest dropped: the first surviving snapshot is frames=6.
        assert_eq!(s.chan_timeline.front().unwrap()[0].frames, 6);
        assert_eq!(s.channel_stats[0].frames, (CHAN_TL_CAP + 5) as u64);
    }

    #[test]
    fn hps_history_advances_only_while_running() {
        let mut s = AppState::new("wlan0");
        s.apply(Event::CrackProgress { done: 10, hps: 100.0, total: None });
        assert!(s.hps_hist.is_empty(), "stopped run must not feed the curve");
        s.cracker.running = true;
        s.apply(Event::CrackProgress { done: 20, hps: 200.0, total: Some(50) });
        s.apply(Event::CrackProgress { done: 30, hps: 300.0, total: Some(50) });
        assert_eq!(
            s.hps_hist.iter().copied().collect::<Vec<_>>(),
            vec![200.0, 300.0]
        );
        assert_eq!(s.cracker.tried, 30);
        assert_eq!(s.cracker.total, Some(50));
    }
}
