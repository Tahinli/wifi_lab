//! Application state: the UI-side home for everything arriving over the
//! backend event channel. Backend swap-in keeps this type untouched.

use std::collections::{BTreeMap, VecDeque};

use crate::common::{AccessPoint, ClientInfo, Event, HandshakeCapture, MacAddr, PmkidCapture};
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
}

/// Everything the window renders. Updated exclusively by
/// [`AppState::apply`] so a real backend can reuse the reduction logic.
pub struct AppState {
    /// Whether the interface is (pretending to be) capturing in monitor mode.
    pub iface_running: bool,
    pub ifname: String,
    pub aps: BTreeMap<MacAddr, AccessPoint>,
    pub clients: BTreeMap<MacAddr, ClientInfo>,
    pub handshakes: Vec<HandshakeCapture>,
    pub pmkids: Vec<PmkidCapture>,
    /// [`capture_descs`]-aligned crack targets: `capture_targets()[i]` is
    /// the [`CrackTarget`] described by `capture_descs()[i]`, so the
    /// cracker starts a run without re-parsing an hc22000 line.
    capture_targets: Vec<CrackTarget>,
    pub log: VecDeque<String>,
    pub cracker: CrackerState,
}

impl AppState {
    pub fn new(ifname: &str) -> Self {
        AppState {
            iface_running: false,
            ifname: ifname.to_string(),
            aps: BTreeMap::new(),
            clients: BTreeMap::new(),
            handshakes: Vec::new(),
            pmkids: Vec::new(),
            capture_targets: Vec::new(),
            log: VecDeque::with_capacity(LOG_CAP),
            cracker: CrackerState::default(),
        }
    }

    /// Crack target described by `capture_descs()[i]` (cloned — the cracker
    /// worker takes ownership).
    pub fn crack_target_at(&self, i: usize) -> Option<CrackTarget> {
        self.capture_targets.get(i).cloned()
    }

    pub fn push_log(&mut self, line: impl Into<String>) {
        if self.log.len() == LOG_CAP {
            self.log.pop_front();
        }
        self.log.push_back(line.into());
    }

    /// Reduce one backend event into state. Returns `true` when the set of
    /// crackable captures changed (callers rebuild dependent widgets).
    pub fn apply(&mut self, event: Event) -> bool {
        match event {
            Event::ApUpdated(ap) => {
                self.aps.insert(ap.bssid, ap);
                false
            }
            Event::ApLost(bssid) => {
                self.aps.remove(&bssid);
                false
            }
            Event::ClientUpdated(client) => {
                self.clients.insert(client.mac, client);
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
            Event::CrackProgress { done, hps } => {
                if self.cracker.running {
                    self.cracker.tried = done;
                    self.cracker.hps = hps;
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
            Event::Log(line) => {
                self.push_log(line);
                false
            }
            Event::Error(line) => {
                self.push_log(format!("ERROR: {line}"));
                false
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
