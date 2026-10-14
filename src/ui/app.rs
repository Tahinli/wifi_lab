//! Root view: nav rail, header bar (interface picker, privilege badge,
//! monitor/capture toggle), page content, status line, and the background
//! task that polls the service event channel.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, Sender};
use gpui::{
    App, AppContext, Context, Entity, FocusHandle, FontWeight, InteractiveElement, IntoElement,
    ParentElement, Render, SharedString, StatefulInteractiveElement, Styled, Window, div,
    prelude::FluentBuilder, px,
};
use gpuikit::elements::badge::badge;
use gpuikit::elements::button::button;
use gpuikit::elements::select::{SelectState, select};
use gpuikit::elements::table::SortDescriptor;
use gpuikit::elements::toast::ToastExt;
use gpuikit::input::InputState;
use gpuikit::layout::{h_stack, v_stack};
use gpuikit::theme::{ActiveTheme, Themeable};
use gpuikit::traits::disableable::Disableable;

use crate::common::{AccessPoint, Cmd, Event, MacAddr};
use crate::service::ServiceClient;
use crate::ui::{attacks, cracker, log as log_view, networks, state::AppState};

/// How often the UI drains the service event channel.
const EVENT_POLL: Duration = Duration::from_millis(100);

/// Left nav destinations.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Networks,
    Attacks,
    Cracker,
    Log,
}

impl Page {
    const ALL: [Page; 4] = [Page::Networks, Page::Attacks, Page::Cracker, Page::Log];

    fn label(self) -> &'static str {
        match self {
            Page::Networks => "Networks",
            Page::Attacks => "Attacks",
            Page::Cracker => "Cracker",
            Page::Log => "Log",
        }
    }

    /// Startup page override (`WIFILAB_PAGE=attacks`) — dev/visual-verification
    /// hook; unknown values fall through to Networks.
    fn from_name(name: &str) -> Option<Page> {
        Page::ALL
            .iter()
            .copied()
            .find(|p| p.label().eq_ignore_ascii_case(name))
    }
}

pub struct AppRoot {
    pub state: AppState,
    /// Service event channel (mock thread or service reader thread).
    pub rx: Receiver<Event>,
    /// UI-triggered actions are injected into the same pipeline.
    pub tx: Sender<Event>,
    pub page: Page,
    /// UI-process privilege ([`crate::iface::is_root`]); the header badge
    /// combines this with `service` presence to show the SERVICE's
    /// privilege state — any running service is root (direct spawn or
    /// pkexec).
    pub is_root: bool,
    /// Privileged radio service client (owns the child process). `None`
    /// in mock mode or before the first "Start capture". Kept across
    /// stop/start cycles. NOT involved in cracking — crack jobs are
    /// UI-process threads tracked via [`AppRoot::crack_stop`].
    pub service: Option<ServiceClient>,
    /// Mock data mode (`--mock` / `WIFILAB_MOCK=1`): never touches devices.
    pub is_mock: bool,
    /// Target BSSID picked on the Networks page (AP row or client row).
    pub selected: Option<MacAddr>,
    /// Last-known AP row for [`AppRoot::selected`], snapshotted at click
    /// time and refreshed whenever the live record updates. The Attacks
    /// page builds its target card from this even when the live row is
    /// momentarily absent (host-capture mode never re-scans: a target
    /// picked before the lock may have no AP row at all).
    pub selected_ap: Option<AccessPoint>,
    /// Client station picked on the Networks page; deauth targets it
    /// instead of the broadcast address when set (AP stays `selected`).
    pub selected_client: Option<MacAddr>,
    /// Message bitmask (see [`Event::HandshakeProgress`]) per in-flight
    /// 4-way capture, keyed by (AP, client).
    pub hs_progress: BTreeMap<(MacAddr, MacAddr), u8>,
    /// "Spinner shown" flags for attack buttons awaiting results.
    pub attacking_handshake: bool,
    pub attacking_pmkid: bool,
    /// Channels the scanner is parked on for attacks (restricted StartScan
    /// plan; several entries cover dual-band targets). `None` = full hop
    /// list. Blanket spectrum-wide hopping makes capture/PMKID/deauth
    /// mostly deaf and blind to one band.
    pub parked_channels: Option<Vec<u8>>,
    /// Crack run in flight; cleared when CrackStopped arrives.
    pub crack_inflight: bool,
    /// Stop flag of the running crack job (UI-process thread, see
    /// [`crate::attack`]); flipped by Stop and on window close.
    pub crack_stop: Option<Arc<AtomicBool>>,
    /// Stop flag of the running rainbow-table build job.
    pub rainbow_stop: Option<Arc<AtomicBool>>,
    /// Throttle for resume-session writes (see [`AppRoot::maybe_save_crack_session`]).
    pub last_session_save: Instant,
    /// Toasts queued by the event loop (no Window there) — shown on the
    /// next render pass. Capped (oldest dropped) so a burst of alerts
    /// can't bury the window.
    pub pending_toast: std::collections::VecDeque<SharedString>,
    /// NetworkManager seen active when capture started (fights channels).
    pub nm_active: bool,
    /// Used to invalidate stale cracker simulation ticks after Stop/re-Start.
    pub crack_epoch: u64,
    pub ap_sort: Option<SortDescriptor>,
    pub client_sort: Option<SortDescriptor>,
    pub focus_handle: FocusHandle,
    pub iface_select: Entity<SelectState<String>>,
    pub target_select: Entity<SelectState<String>>,
    pub wordlist_input: Entity<InputState>,
    /// Cracker attack-mode picker ([`crate::attack::Attack`]: wordlist /
    /// bruteforce / rainbow).
    pub attack_select: Entity<SelectState<String>>,
    /// Selected attack mode value ("wordlist" | "bruteforce" | "rainbow").
    pub attack_mode: String,
    /// Bruteforce preset chips ([`crate::attack::charset`]): unioned with
    /// the custom field into the effective charset.
    pub cs_lower: bool,
    pub cs_upper: bool,
    pub cs_digits: bool,
    pub cs_special: bool,
    /// Bruteforce mode inputs: charset and min/max word length.
    pub charset_input: Entity<InputState>,
    pub len_min_input: Entity<InputState>,
    pub len_max_input: Entity<InputState>,
    /// Rainbow mode: PMK table path; the build job writes it, the run
    /// reads it.
    pub rainbow_input: Entity<InputState>,
    pub deauth_input: Entity<InputState>,
    /// Networks-page label editor; the labels themselves live in
    /// `state.labels` ([`crate::store`]).
    pub label_input: Entity<InputState>,
    /// Log page body: read-only multiline input so log text is
    /// mouse-selectable / Ctrl-C-copyable (plain text widgets aren't).
    pub log_input: Entity<InputState>,
    /// Rules-attack mode: hashcat-style rule file path.
    pub rules_input: Entity<InputState>,
    /// Crack-time estimator candidate (how strong might the password be).
    pub strength_input: Entity<InputState>,
    /// Hybrid mode: appended-suffix length bounds.
    pub hyb_min_input: Entity<InputState>,
    pub hyb_max_input: Entity<InputState>,
    /// Bruteforce charset ordering: most-common characters first.
    pub freq_order: bool,
    /// A throughput benchmark run is in flight.
    pub bench_running: bool,
    /// A capture-file import is in flight.
    pub import_busy: bool,
    /// Target count behind the "Deauth all clients (N)" button label
    /// (0 = hidden); computed during attack-page render prep.
    pub deauth_all_targets: usize,
    /// Saved cracking presets + recent wordlists (~/wifilab/profiles.json).
    pub profiles: crate::store::Profiles,
}

impl AppRoot {
    pub fn new(
        window: &mut Window,
        cx: &mut Context<Self>,
        tx: Sender<Event>,
        rx: Receiver<Event>,
        is_mock: bool,
        ifaces: Vec<String>,
        selected_iface: String,
    ) -> Self {
        let view = cx.entity();

        let iface_select = cx.new(|_cx| {
            SelectState::new(
                select(
                    "iface-select",
                    "Interface",
                    ifaces
                        .iter()
                        .map(|i| (i.clone(), i.clone()))
                        .collect::<Vec<_>>(),
                )
                .selected(selected_iface.clone())
                .on_change({
                    let view = view.clone();
                    move |ifname, _window, cx| {
                        view.update(cx, |app, cx| {
                            app.state.ifname = ifname.clone();
                            app.state.push_log(format!("iface: selected {ifname}"));
                            cx.notify();
                        });
                    }
                }),
            )
        });

        let wordlist_input = cx.new(InputState::new_singleline);
        wordlist_input.update(cx, |input, cx| {
            input.set_content("/usr/share/wordlists/rockyou.txt", cx);
        });

        let deauth_input = cx.new(InputState::new_singleline);
        deauth_input.update(cx, |input, cx| {
            input.set_content("16", cx);
        });

        let label_input = cx.new(InputState::new_singleline);
        let log_input = cx.new(|cx| InputState::new_multiline(cx).read_only(true));

        let attack_select = cx.new(|_cx| {
            SelectState::new(
                select(
                    "cracker-attack",
                    "Attack",
                    vec![
                        ("wordlist".to_string(), "wordlist".to_string()),
                        ("rules".to_string(), "rules".to_string()),
                        ("hybrid".to_string(), "hybrid".to_string()),
                        ("bruteforce".to_string(), "bruteforce".to_string()),
                        ("rainbow".to_string(), "rainbow".to_string()),
                    ],
                )
                .selected("wordlist".to_string())
                .on_change({
                    let view = view.clone();
                    move |mode, _window, cx| {
                        view.update(cx, |app, cx| {
                            app.attack_mode = mode;
                            cx.notify();
                        });
                    }
                }),
            )
        });
        let charset_input = cx.new(InputState::new_singleline);
        let len_min_input = cx.new(InputState::new_singleline);
        len_min_input.update(cx, |input, cx| input.set_content("8", cx));
        let len_max_input = cx.new(InputState::new_singleline);
        len_max_input.update(cx, |input, cx| input.set_content("10", cx));
        let rainbow_input = cx.new(InputState::new_singleline);
        let rules_input = cx.new(InputState::new_singleline);
        rules_input.update(cx, |input, cx| {
            input.set_content("/path/to/rules (e.g. best64.rule)", cx);
        });
        let strength_input = cx.new(InputState::new_singleline);
        let hyb_min_input = cx.new(InputState::new_singleline);
        hyb_min_input.update(cx, |input, cx| input.set_content("1", cx));
        let hyb_max_input = cx.new(InputState::new_singleline);
        hyb_max_input.update(cx, |input, cx| input.set_content("2", cx));

        let mut this = AppRoot {
            state: AppState::new(&selected_iface),
            rx,
            tx,
            page: std::env::var("WIFILAB_PAGE")
                .ok()
                .and_then(|p| Page::from_name(&p))
                .unwrap_or(Page::Networks),
            is_root: crate::iface::is_root(),
            service: None,
            is_mock,
            selected: None,
            selected_ap: None,
            selected_client: None,
            hs_progress: BTreeMap::new(),
            attacking_handshake: false,
            attacking_pmkid: false,
            parked_channels: None,
            crack_inflight: false,
            crack_stop: None,
            rainbow_stop: None,
            last_session_save: Instant::now(),
            pending_toast: std::collections::VecDeque::new(),
            nm_active: false,
            crack_epoch: 0,
            ap_sort: None,
            client_sort: None,
            focus_handle: cx.focus_handle(),
            iface_select,
            target_select: cx.new(|_cx| {
                let empty: Vec<(String, String)> = Vec::new();
                SelectState::new(select("cracker-target", "Crack target", empty))
            }),
            wordlist_input,
            attack_select,
            attack_mode: "wordlist".to_string(),
            cs_lower: false,
            cs_upper: false,
            cs_digits: true,
            cs_special: false,
            charset_input,
            len_min_input,
            len_max_input,
            rainbow_input,
            deauth_input,
            label_input,
            log_input,
            rules_input,
            strength_input,
            hyb_min_input,
            hyb_max_input,
            freq_order: true,
            bench_running: false,
            import_busy: false,
            deauth_all_targets: 0,
            profiles: match crate::store::load_profiles() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("profiles: load failed, starting empty: {e:#}");
                    crate::store::Profiles::default()
                }
            },
        };
        match crate::store::load() {
            Ok(labels) => {
                let n = labels.len();
                this.state.labels = labels;
                this.state
                    .push_log(format!("labels: {n} loaded from ~/wifilab/labels.json"));
            }
            Err(e) => this
                .state
                .push_log(format!("labels: load failed, starting empty: {e:#}")),
        }
        // Restore previous captures so the cracker can keep working across
        // restarts without re-running attacks.
        match crate::store::load_captures() {
            Ok(caps) => {
                let n = caps.len();
                for cap in caps {
                    match cap {
                        crate::store::StoredCapture::Handshake(h) => {
                            this.state.apply(Event::HandshakeComplete(Box::new(h)));
                        }
                        crate::store::StoredCapture::Pmkid(p) => {
                            this.state.apply(Event::PmkidCaptured(p));
                        }
                    }
                }
                if n > 0 {
                    this.state
                        .push_log(format!("captures: {n} restored from ~/wifilab/captures.jsonl"));
                }
            }
            Err(e) => this
                .state
                .push_log(format!("captures: restore failed: {e:#}")),
        }
        this.rebuild_target_select(cx);
        if !is_mock {
            this.restore_crack_session();
        }
        this.state.push_log(if is_mock {
            "wifilab UI started (mock backend)".to_string()
        } else {
            format!(
                "wifilab UI started (REAL backend, iface {selected_iface}) — Start capture spawns the privileged service (polkit) and brings up monitor mode"
            )
        });

        cx.on_release(|this, _cx| {
            // Window closed → root view released → stop UI-process jobs
            // (crack + rainbow build) and shut the service down (it stops
            // workers, restores managed mode, exits).
            for flag in [this.crack_stop.take(), this.rainbow_stop.take()]
                .into_iter()
                .flatten()
            {
                flag.store(true, Ordering::Relaxed);
            }
            if let Some(svc) = this.service.take() {
                svc.shutdown();
            }
        })
        .detach();

        if !this.is_root && !this.is_mock {
            cx.toast("not root — polkit will ask for authentication when you start capture")
                .show(window, cx);
        }

        // Poll the service event channel: wait on the background executor,
        // then reduce everything queued into state on the main thread. The
        // service reader thread never touches gpui types.
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(EVENT_POLL).await;
                match this.update(cx, |app, cx| app.drain_events(cx)) {
                    Ok(()) => {}
                    // Entity gone (window closed) — stop polling.
                    Err(_) => break,
                }
            }
        })
        .detach();

        window.focus(&this.focus_handle, cx);
        this
    }

    /// Header "Start/Stop capture" behaviour.
    ///
    /// Real mode: lazily spawn the privileged service (polkit-elevated
    /// when needed) which switches the interface to monitor mode and runs
    /// the scanner; Stop only ends the scan session — the service stays
    /// alive for the cracker page and later scans. Mock mode: pure UI
    /// flips (the mock generator runs independently).
    pub fn toggle_monitor(&mut self, cx: &mut Context<Self>) {
        if self.is_mock {
            self.state.iface_running = !self.state.iface_running;
            let on = self.state.iface_running;
            self.state.push_log(format!(
                "iface {}: monitor mode {} (mock)",
                self.state.ifname,
                if on { "on" } else { "off" }
            ));
            cx.notify();
            return;
        }
        if self.state.iface_running {
            // STOP: end the scan session but KEEP the service alive — the
            // cracker needs it, and a later Start reuses it.
            if let Some(svc) = &self.service {
                self.state
                    .push_log("ui: stopping capture, service restores managed mode…");
                svc.stop_scan();
            }
            // Stopping also kills every attack worker — un-spin buttons.
            self.state.iface_running = false;
            self.parked_channels = None;
            self.attacking_handshake = false;
            self.attacking_pmkid = false;
            cx.notify();
        } else {
            // NetworkManager fight: pin-to-connected-channel makes ONLY the
            // associated network (e.g. parafin) visible during the hop.
            if crate::iface::networkmanager_active() {
                self.nm_active = true;
                self.state.push_log(
                    "ui: WARNING NetworkManager is active — it pins the card to the connected \
                     network's channel; you will likely see ONLY that SSID. Use \"Stop NM\" in the header."
                        .to_string(),
                );
                self.queue_toast(
                    "NetworkManager is active — only your connected network may be visible; stop it from the header",
                );
            }
            let ifname = self.state.ifname.clone();
            if let Some(svc) = &self.service {
                // Service already up (from an earlier session): just ask
                // for a fresh scan session.
                svc.cmd(&Cmd::StartScan {
                    ifname: ifname.clone(),
                    channels: None,
                    spool: Some(crate::store::data_dir().join("spool.pcap")),
                    fresh_spool: true,
                });
                self.state.iface_running = true;
                self.parked_channels = None;
                self.state
                    .push_log(format!("ui: capture started on {ifname}"));
                cx.notify();
                return;
            }
            match ServiceClient::start(&ifname, self.tx.clone()) {
                Ok(svc) => {
                    self.service = Some(svc);
                    self.state.iface_running = true;
                    self.state
                        .push_log(format!("ui: capture started on {ifname}"));
                }
                Err(e) => {
                    self.state
                        .push_log(format!("ERROR: start capture on {ifname}: {e:#}"));
                    self.queue_toast(format!("start capture failed: {e:#}"));
                }
            }
            cx.notify();
        }
    }

    /// Stop NetworkManager via the privileged service so it stops pinning
    /// the radio to the connected network's channel.
    pub fn stop_nm(&mut self, cx: &mut Context<Self>) {
        match &self.service {
            Some(svc) => {
                svc.cmd(&Cmd::StopNetworkManager);
                self.state
                    .push_log("ui: asking service to stop NetworkManager…");
            }
            None => {
                self.state.push_log(
                    "ui: NM stop needs the privileged service — Start capture first".to_string(),
                );
            }
        }
        cx.notify();
    }

    /// Queue a toast for the next render pass (the event loop has no
    /// Window). Capped at 3 — oldest dropped first.
    pub fn queue_toast(&mut self, msg: impl Into<SharedString>) {
        if self.pending_toast.len() == 3 {
            self.pending_toast.pop_front();
        }
        self.pending_toast.push_back(msg.into());
    }

    /// Drain every queued event, track handshake progress, refresh widgets
    /// derived from the capture set.
    fn drain_events(&mut self, cx: &mut Context<Self>) {
        let mut changed = false;
        let mut captures_changed = false;
        while let Ok(event) = self.rx.try_recv() {
            changed = true;
            match &event {
                Event::HandshakeProgress { ap, client, have } => {
                    self.hs_progress.insert((*ap, *client), *have);
                }
                Event::HandshakeComplete(cap) => {
                    self.hs_progress.remove(&(cap.ap, cap.client));
                    self.attacking_handshake = false;
                    if let Err(e) = crate::store::append_capture(
                        &crate::store::StoredCapture::Handshake(cap.as_ref().clone()),
                    ) {
                        self.state.push_log(format!("capture save FAILED: {e:#}"));
                    }
                }
                Event::PmkidCaptured(cap) => {
                    self.attacking_pmkid = false;
                    if let Err(e) = crate::store::append_capture(
                        &crate::store::StoredCapture::Pmkid(cap.clone()),
                    ) {
                        self.state.push_log(format!("capture save FAILED: {e:#}"));
                    }
                }
                // Service child died (EOF seen by the reader thread):
                // un-flip every running flag and drop the client so the
                // next Start spawns a fresh, alive service.
                Event::Error(line) if line == "service terminated" => {
                    self.attacking_handshake = false;
                    self.attacking_pmkid = false;
                    self.state.iface_running = false;
                    self.crack_inflight = false;
                    if let Some(svc) = self.service.take() {
                        svc.shutdown(); // reaps the corpse, restores iface
                    }
                }
                // Any worker error, or a terminal log from an attack
                // worker (prefixed by the service; scanner logs are
                // excluded), un-spins attack buttons so the UI is never
                // stuck "working…".
                Event::Error(_) => {
                    self.attacking_handshake = false;
                    self.attacking_pmkid = false;
                }
                // Terminal attack-worker log lines un-spin the buttons.
                // NOT a generic prefix match: "handshake: listening for
                // 4-way…" fires right at worker start and would instantly
                // kill the spinner while the worker runs.
                Event::Log(line)
                    if line.starts_with("handshake: capture ended")
                        || line.starts_with("pmkid: no PMKID") =>
                {
                    self.attacking_handshake = false;
                    self.attacking_pmkid = false;
                }
                // Service-side NM result: `nm: stopped` / `nm: stop failed …`.
                Event::Log(line) if line.starts_with("nm:") => {
                    if line == "nm: stopped" {
                        self.nm_active = false;
                        self.queue_toast(
                            "NetworkManager stopped — all networks become visible as the hopper cycles",
                        );
                    }
                }
                Event::CrackProgress { .. } => {
                    self.maybe_save_crack_session();
                }
                Event::CrackStopped { found } => {
                    self.crack_inflight = false;
                    self.crack_stop = None;
                    self.finalize_crack_session(*found);
                }
                Event::RainbowBuilt { .. } => {
                    self.rainbow_stop = None;
                }
                Event::CrackFound { password } => {
                    self.queue_toast(format!("password recovered: {password}"));
                    // Best-effort desktop notification; headless/no-D-Bus
                    // just drops the error.
                    let _ = notify_rust::Notification::new()
                        .summary("wifilab: password found")
                        .body(&format!("password recovered: {password}"))
                        .show();
                }
                Event::CaptureImported(cap) => {
                    let stored = match cap {
                        crate::common::ImportedCapture::Handshake(h) => {
                            crate::store::StoredCapture::Handshake(h.as_ref().clone())
                        }
                        crate::common::ImportedCapture::Pmkid(p) => {
                            crate::store::StoredCapture::Pmkid(p.clone())
                        }
                    };
                    if let Err(e) = crate::store::append_capture(&stored) {
                        self.state
                            .push_log(format!("import: capture save FAILED: {e:#}"));
                    }
                }
                Event::BenchmarkDone { .. } => {
                    self.bench_running = false;
                }
                _ => {}
            }
            captures_changed |= self.state.apply(event);
            if let Some(m) = self.state.deauth_alert.take() {
                self.queue_toast(m);
            }
            if let Some(m) = self.state.rogue_alert.take() {
                self.queue_toast(m);
            }
            if let Some(m) = self.state.ident_alert.take() {
                self.queue_toast(m);
            }
        }
        // Keep the target snapshot in lockstep with the live AP row (a
        // click-time-only snapshot goes stale: channel jumps, beacon
        // counts, security updates). Also self-heals after service
        // restarts, when only the live row exists.
        if let Some(live) = self
            .selected
            .and_then(|b| self.state.aps.get(&b).cloned())
        {
            self.selected_ap = Some(live);
        }
        // Mock-only convenience: pre-select the first heard AP so the
        // Attacks page shows its target card without a manual click —
        // invaluable for headless UI verification. Never in real mode.
        if self.is_mock && self.selected.is_none() {
            if let Some((&b, _)) = self.state.aps.first_key_value() {
                self.selected = Some(b);
                self.selected_ap = self.state.aps.get(&b).cloned();
            }
        }
        if captures_changed {
            self.rebuild_target_select(cx);
        }
        if changed {
            cx.notify();
        }
    }

    /// Persist the interrupted crack run (resume file), throttled to one
    /// write per 2 s of progress events. UI-thread only (called from the
    /// event drain).
    fn maybe_save_crack_session(&mut self) {
        if self.last_session_save.elapsed() < Duration::from_secs(2) {
            return;
        }
        self.last_session_save = Instant::now();
        self.save_crack_session();
    }

    /// Write the current run to ~/wifilab/crack-session.json. No-op when
    /// nothing resumable is in flight (mock runs never persist).
    fn save_crack_session(&mut self) {
        let (Some(attack), Some(desc)) = (
            self.state.cracker.active_attack.clone(),
            self.state.cracker.target.clone(),
        ) else {
            return;
        };
        let done = self.state.cracker.tried;
        if done == 0 {
            return;
        }
        let Some(idx) = self
            .state
            .capture_descs()
            .iter()
            .position(|d| *d == desc)
        else {
            return;
        };
        let Some(capture) = self.state.stored_capture_at(idx) else {
            return;
        };
        let total = self.state.cracker.total;
        let session = crate::store::CrackSession { capture, attack, done, total };
        if let Err(e) = crate::store::save_session(&session) {
            self.state.push_log(format!("cracker: session save failed: {e:#}"));
            return;
        }
        // The just-saved run is resumable right now (same session or the
        // next start): keep the banner in sync.
        self.state.cracker.resume = Some(crate::ui::state::ResumeInfo {
            target_desc: desc,
            attack: session.attack,
            done,
            total,
        });
    }

    /// Settle the session file when a run ends: found/exhausted → delete
    /// (nothing left to resume); stopped mid-way → final save + banner.
    fn finalize_crack_session(&mut self, found: bool) {
        let done = self.state.cracker.tried;
        let total = self.state.cracker.total;
        let exhausted = !found && total.is_some_and(|t| done >= t);
        if found || exhausted {
            if let Err(e) = crate::store::clear_session() {
                self.state.push_log(format!("cracker: session clear failed: {e:#}"));
            }
            self.state.cracker.resume = None;
        } else if self.state.cracker.active_attack.is_some() {
            // User-stopped (or worker-ended) with room left: persist the
            // position — this is the whole point of the feature.
            self.last_session_save = Instant::now();
            self.save_crack_session();
        }
        self.state.cracker.active_attack = None;
    }

    /// Match a saved session against the loaded captures on startup:
    /// a match arms the resume banner on the cracker page.
    fn restore_crack_session(&mut self) {
        let session = match crate::store::load_session() {
            Ok(Some(s)) => s,
            Ok(None) => return,
            Err(e) => {
                self.state
                    .push_log(format!("cracker: saved session unreadable: {e:#}"));
                return;
            }
        };
        let descs = self.state.capture_descs();
        let hit = descs.iter().enumerate().find(|(i, _)| {
            self.state.stored_capture_at(*i).as_ref() == Some(&session.capture)
        });
        match hit.map(|(_, d)| d) {
            Some(d) => {
                let done = session.done;
                self.state.cracker.resume = Some(crate::ui::state::ResumeInfo {
                    target_desc: d.clone(),
                    attack: session.attack,
                    done,
                    total: session.total,
                });
                self.state
                    .push_log(format!("cracker: resumable saved run restored ({d}, {done} tried)"));
            }
            None => self
                .state
                .push_log("cracker: saved session ignored — its capture is gone".to_string()),
        }
    }

    /// The cracker target dropdown mirrors `state.capture_descs()`; rebuild
    /// it whenever a handshake/PMKID arrives, keeping the current choice if
    /// it still exists. With no captures the select is disabled so its
    /// (empty) popup cannot open.
    pub fn rebuild_target_select(&mut self, cx: &mut Context<Self>) {
        let descs = self.state.capture_descs();
        let keep = self
            .state
            .cracker
            .target
            .take()
            .filter(|cur| descs.contains(cur));
        let view = cx.entity();
        let mut builder = select(
            "cracker-target",
            "Crack target",
            descs.iter().map(|d| (d.clone(), d.clone())).collect::<Vec<_>>(),
        )
        .placeholder(if descs.is_empty() {
            "no captures yet — capture a handshake or PMKID first"
        } else {
            "Select a capture…"
        })
        .disabled(descs.is_empty())
        .on_change(move |value, _window, cx| {
            view.update(cx, |app, cx| {
                app.state.cracker.target = Some(value);
                cx.notify();
            });
        });
        if let Some(cur) = keep {
            builder = builder.selected(cur.clone());
            self.state.cracker.target = Some(cur);
        }
        self.target_select = cx.new(|_cx| SelectState::new(builder));
    }

    fn nav_item(
        &self,
        page: Page,
        view: &Entity<AppRoot>,
        cx: &App,
    ) -> gpui::Stateful<gpui::Div> {
        let theme = cx.theme().clone();
        let active = self.page == page;
        let view = view.clone();
        div()
            .id(ElementKey::Nav(page as u8).id())
            .px_3()
            .py_2()
            .rounded_md()
            .cursor_pointer()
            .when(active, |el| el.bg(theme.accent_bg()))
            .when(!active, |el| {
                let hover = theme.accent_bg().alpha(0.35);
                el.hover(move |style| style.bg(hover))
            })
            .text_sm()
            .child(page.label())
            .on_click(move |_, _window, cx| {
                view.update(cx, |app, cx| {
                    app.page = page;
                    cx.notify();
                });
            })
    }

    fn header(&self, view: &Entity<AppRoot>, cx: &App) -> gpui::Div {
        let theme = cx.theme().clone();
        let running = self.state.iface_running;

        // Status of the SERVICE process (the thing that actually touches
        // the radio): any running service is root — spawned directly when
        // the UI is root, via pkexec (root by definition) otherwise.
        let privilege = if self.is_mock {
            badge("not root (mock)").secondary()
        } else if self.service.is_some() {
            badge("service: root").secondary()
        } else if self.is_root {
            badge("ui: root · service not started").secondary()
        } else {
            badge("ui: user · service not started").secondary()
        };

        let toggle = button(
            "monitor-toggle",
            if running {
                "Stop capture"
            } else if self.is_mock {
                "Start capture (mock)"
            } else {
                "Start capture (monitor)"
            },
        )
        // Stopping capture (or starting a new one) while a crack streams
        // would kill the crack job: radio access is exclusive.
        .disabled(!self.is_mock && self.crack_inflight)
        .on_click({
            let view = view.clone();
            move |_, _window, cx| {
                view.update(cx, |app, cx| app.toggle_monitor(cx));
            }
        });

        let nm_badge = (self.nm_active && !self.is_mock)
            .then(|| badge("NM active — channels pinned").destructive());
        let nm_btn = (self.nm_active && !self.is_mock).then(|| {
            button("stop-nm", "Stop NM").on_click({
                let view = view.clone();
                move |_, _window, cx| {
                    view.update(cx, |app, cx| app.stop_nm(cx));
                }
            })
        });

        h_stack()
            .w_full()
            .px_4()
            .py_2()
            .gap_3()
            .items_center()
            .border_b_1()
            .border_color(theme.border())
            .bg(theme.surface())
            .child(div().text_lg().font_weight(FontWeight::BOLD).child("wifilab"))
            .child(privilege)
            .child(div().w(px(220.)).child(self.iface_select.clone()))
            .children(nm_badge)
            .children(nm_btn)
            .child(toggle)
            .child(div().flex_1())
            .child(
                div()
                    .text_xs()
                    .text_color(theme.fg_muted())
                    .child(SharedString::from(format!(
                        "channel hopper active · {}",
                        self.state.ifname
                    ))),
            )
    }

    fn status_line(&self, cx: &App) -> gpui::Div {
        let theme = cx.theme().clone();
        div()
            .w_full()
            .px_4()
            .py_1()
            .border_t_1()
            .border_color(theme.border())
            .bg(theme.surface())
            .text_xs()
            .text_color(theme.fg_muted())
            .child(format!(
                "{} APs · {} clients · {} handshakes · {} PMKIDs · {} · capture {} · {}",
                self.state.aps.len(),
                self.state.clients.len(),
                self.state.handshakes.len(),
                self.state.pmkids.len(),
                self.state.ifname,
                if self.state.iface_running {
                    "running"
                } else {
                    "stopped"
                },
                if self.is_mock { "MOCK DATA" } else { "LIVE" }
            ))
    }
}

/// Stable element ids that aren't string keys.
enum ElementKey {
    Nav(u8),
}

impl ElementKey {
    fn id(self) -> SharedString {
        match self {
            ElementKey::Nav(n) => SharedString::from(format!("nav-{n}")),
        }
    }
}

impl Render for AppRoot {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        let view = cx.entity();

        // Flush toasts queued by the event-drain loop (which has no Window).
        while let Some(msg) = self.pending_toast.pop_front() {
            cx.toast(msg).show(_window, cx);
        }

        let nav = v_stack()
            .w(px(170.))
            .h_full()
            .gap_1()
            .p_2()
            .border_r_1()
            .border_color(theme.border())
            .bg(theme.surface_secondary())
            .children(
                Page::ALL
                    .into_iter()
                    .map(|page| self.nav_item(page, &view, cx)),
            );

        let content = match self.page {
            Page::Networks => networks::render(self, &view, _window, cx),
            Page::Attacks => attacks::render(self, &view, _window, cx),
            Page::Cracker => cracker::render(self, &view, _window, cx),
            Page::Log => log_view::render(self, &view, _window, cx),
        };

        div()
            .flex()
            .size_full()
            .bg(theme.bg())
            .text_color(theme.fg())
            .child(nav)
            .child(
                v_stack()
                    .flex_1()
                    .h_full()
                    .min_w_0()
                    .child(self.header(&view, cx))
                    .child(div().flex_1().min_h_0().child(content))
                    .child(self.status_line(cx)),
            )
            // Toast overlay lives at the root so it floats over any page.
            .child(cx.toast_manager().clone())
    }
}
