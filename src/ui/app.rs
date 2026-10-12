//! Root view: nav rail, header bar (interface picker, privilege badge,
//! monitor/capture toggle), page content, status line, and the background
//! task that polls the backend event channel.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

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

use crate::backend::Backend;
use crate::common::{Event, MacAddr};
use crate::ui::{attacks, cracker, log as log_view, networks, state::AppState};

/// How often the UI drains the backend event channel.
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
}

pub struct AppRoot {
    pub state: AppState,
    /// Backend event channel (mock thread today, real backend later).
    pub rx: Receiver<Event>,
    /// UI-triggered actions are injected into the same pipeline.
    pub tx: Sender<Event>,
    pub page: Page,
    /// Privilege indicator; real value from [`crate::iface::is_root`].
    pub is_root: bool,
    /// Real radio/attack/cracker orchestrator. `None` in mock mode or
    /// before the first "Start capture".
    pub backend: Option<Backend>,
    /// Mock data mode (`--mock` / `WIFILAB_MOCK=1`): never touches devices.
    pub is_mock: bool,
    /// Target BSSID picked on the Networks page (AP row or client row).
    pub selected: Option<MacAddr>,
    /// Client station picked on the Networks page; deauth targets it
    /// instead of the broadcast address when set (AP stays `selected`).
    pub selected_client: Option<MacAddr>,
    /// Message bitmask (see [`Event::HandshakeProgress`]) per in-flight
    /// 4-way capture, keyed by (AP, client).
    pub hs_progress: BTreeMap<(MacAddr, MacAddr), u8>,
    /// "Spinner shown" flags for attack buttons awaiting results.
    pub attacking_handshake: bool,
    pub attacking_pmkid: bool,
    /// Crack run in flight; cleared when CrackStopped arrives.
    pub crack_inflight: bool,
    /// Toast queued by the event loop (no Window there) — shown on the
    /// next render pass.
    pub pending_toast: Option<SharedString>,
    /// Elevate-via-polkit handshake: Some while a pkexec re-exec is in
    /// flight. 0 = waiting on the polkit dialog, 1 = elevated instance
    /// launched (quit this one), 2 = declined/failed (message was logged).
    pub elevation: Option<Arc<AtomicU8>>,
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
    pub deauth_input: Entity<InputState>,
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

        let mut this = AppRoot {
            state: AppState::new(&selected_iface),
            rx,
            tx,
            page: Page::Networks,
            is_root: crate::iface::is_root(),
            backend: None,
            is_mock,
            selected: None,
            selected_client: None,
            hs_progress: BTreeMap::new(),
            attacking_handshake: false,
            attacking_pmkid: false,
            crack_inflight: false,
            pending_toast: None,
            elevation: None,
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
            deauth_input,
        };
        this.rebuild_target_select(cx);
        this.state.push_log(if is_mock {
            "wifilab UI started (mock backend)".to_string()
        } else {
            format!(
                "wifilab UI started (REAL backend, iface {selected_iface}) — Start capture to bring up monitor mode"
            )
        });

        cx.on_release(|this, _cx| {
            // Window closed → root view released → stop every worker and
            // restore the interface to managed mode.
            if let Some(be) = this.backend.take() {
                be.shutdown();
            }
        })
        .detach();

        if !this.is_root && !this.is_mock {
            if crate::iface::pkexec_available() {
                cx.toast("not root — click \"Elevate via polkit\" in the header to gain privileges")
                    .show(window, cx);
            } else {
                cx.toast("not root and polkit (pkexec) unavailable — monitor mode and injection will fail")
                    .show(window, cx);
            }
        }

        // Poll the backend event channel: wait on the background executor,
        // then reduce everything queued into state on the main thread. The
        // backend threads never touch gpui types.
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
    /// Real mode: lazily create the [`Backend`] (monitor-mode switch +
    /// scanner thread) on the channel-selected interface; Stop shuts it
    /// down and restores managed mode. Mock mode: pure UI flips (the mock
    /// generator runs independently).
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
            // STOP: release the radio but KEEP the Backend alive — the
            // cracker needs it (cracking has no radio use). `stop_radio`
            // restores managed mode and joins the radio workers only.
            if let Some(be) = &self.backend {
                self.state.push_log("ui: stopping capture, restoring managed mode…");
                cx.notify();
                be.stop_radio();
                self.state
                    .push_log("ui: capture stopped, interface restored (cracker stays available)");
            }
            self.state.iface_running = false;
            cx.notify();
        } else {
            if !self.is_root {
                self.state.push_log(
                    "ui: capture REFUSED — no root privileges. Elevate via polkit first.".to_string(),
                );
                self.pending_toast = Some(
                    "ELEVATION REQUIRED: click \"Elevate via polkit\" in the header before starting capture".into(),
                );
                cx.notify();
                return;
            }
            // NetworkManager fight: pin-to-connected-channel makes ONLY the
            // associated network (e.g. parafin) visible during the hop.
            if crate::iface::networkmanager_active() {
                self.nm_active = true;
                self.state.push_log(
                    "ui: WARNING NetworkManager is active — it pins the card to the connected \
                     network's channel; you will likely see ONLY that SSID. Use \"Stop NM\" in the header."
                        .to_string(),
                );
                self.pending_toast = Some(
                    "NetworkManager is active — only your connected network may be visible; stop it from the header".into(),
                );
            }
            // A Backend kept alive for the cracker from a previous capture
            // would tear down our new monitor mode in its `Drop` (it
            // restores managed mode). Drop it BEFORE the fresh
            // `start_scan` switches the interface up in monitor mode.
            self.backend = None;
            let ifname = self.state.ifname.clone();
            match Backend::start_scan(&ifname, self.tx.clone()) {
                Ok(be) => {
                    self.backend = Some(be);
                    self.state.iface_running = true;
                    self.state
                        .push_log(format!("ui: capture started on {ifname}"));
                }
                Err(e) => {
                    self.state
                        .push_log(format!("ERROR: start capture on {ifname}: {e:#}"));
                }
            }
            cx.notify();
        }
    }

    /// Stop NetworkManager (root) so it stops pinning the radio to the
    /// connected network's channel.
    pub fn stop_nm(&mut self, cx: &mut Context<Self>) {
        match crate::iface::stop_networkmanager() {
            Ok(()) => {
                self.nm_active = false;
                self.state.push_log(
                    "ui: NetworkManager stopped — channel hopping is now exclusive; restart it later with `systemctl start NetworkManager`"
                        .to_string(),
                );
                self.pending_toast =
                    Some("NetworkManager stopped — all networks become visible as the hopper cycles".into());
            }
            Err(e) => {
                self.state
                    .push_log(format!("ERROR stopping NetworkManager: {e:#}"));
            }
        }
        cx.notify();
    }

    /// Re-exec this app as root via polkit (pkexec). The polkit dialog is
    /// fully OS-driven; on success the elevated instance opens its own
    /// window and this one closes itself.
    pub fn elevate(&mut self, cx: &mut Context<Self>) {
        if self.is_root || self.is_mock || self.elevation.is_some() {
            return;
        }
        if self.backend.is_some() {
            self.state.push_log("ui: stop capture before elevating");
            cx.notify();
            return;
        }
        let flag = Arc::new(AtomicU8::new(0));
        self.elevation = Some(flag.clone());
        let ifname = self.state.ifname.clone();
        let tx = self.tx.clone();
        self.state.push_log(format!(
            "ui: requesting administrative privileges via polkit (restarting elevated on {ifname})…"
        ));
        cx.notify();
        std::thread::spawn(move || {
            match crate::iface::relaunch_elevated(&["--iface", ifname.as_str()]) {
                Ok(st) if st.success() => flag.store(1, Ordering::SeqCst),
                Ok(st) => {
                    flag.store(2, Ordering::SeqCst);
                    let _ = tx.send(Event::Log(format!(
                        "ui: elevation dialog dismissed or failed (pkexec exit {st})"
                    )));
                }
                Err(e) => {
                    flag.store(2, Ordering::SeqCst);
                    let _ = tx.send(Event::Error(format!("polkit elevation failed: {e:#}")));
                }
            }
        });
    }

    /// Drain every queued event, track handshake progress, refresh widgets
    /// derived from the capture set.
    fn drain_events(&mut self, cx: &mut Context<Self>) {
        // Elevation handshake: success → the new elevated window is up,
        // close this one; failure → allow retry (message already queued).
        if let Some(flag) = &self.elevation {
            match flag.load(Ordering::SeqCst) {
                1 => {
                    self.state
                        .push_log("ui: elevated instance started — closing this window");
                    self.elevation = None;
                    cx.quit();
                    return;
                }
                2 => self.elevation = None,
                _ => {}
            }
        }
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
                }
                Event::PmkidCaptured(_) => {
                    self.attacking_pmkid = false;
                }
                // Any worker error, or a terminal log from an attack
                // worker (prefixed by backend.rs; scanner logs are
                // excluded), un-spins attack buttons so the UI is never
                // stuck "working…".
                Event::Error(_) => {
                    self.attacking_handshake = false;
                    self.attacking_pmkid = false;
                }
                Event::Log(line)
                    if ["handshake:", "pmkid:"]
                        .iter()
                        .any(|p| line.starts_with(p)) =>
                {
                    self.attacking_handshake = false;
                    self.attacking_pmkid = false;
                }
                Event::CrackStopped { .. } => {
                    self.crack_inflight = false;
                }
                Event::CrackFound { password } => {
                    self.pending_toast =
                        Some(format!("password recovered: {password}").into());
                }
                _ => {}
            }
            captures_changed |= self.state.apply(event);
        }
        if captures_changed {
            self.rebuild_target_select(cx);
        }
        if changed {
            cx.notify();
        }
    }

    /// The cracker target dropdown mirrors `state.capture_descs()`; rebuild
    /// it whenever a handshake/PMKID arrives, keeping the current choice if
    /// it still exists.
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
        .placeholder("Select a capture…")
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

        let privilege = if self.is_root {
            badge("root").secondary()
        } else if self.is_mock {
            badge("not root (mock)").secondary()
        } else {
            badge("not root — elevate to attack").destructive()
        };

        let elevate_btn = (!self.is_root && !self.is_mock && crate::iface::pkexec_available())
            .then(|| {
                let waiting = self.elevation.is_some();
                button(
                    "elevate-btn",
                    if waiting {
                        "waiting for polkit…"
                    } else {
                        "Elevate via polkit"
                    },
                )
                .disabled(waiting)
                .on_click({
                    let view = view.clone();
                    move |_, _window, cx| {
                        view.update(cx, |app, cx| app.elevate(cx));
                    }
                })
            });

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
        let nm_btn = (self.nm_active && self.is_root && !self.is_mock).then(|| {
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
            .children(elevate_btn)
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
        if let Some(msg) = self.pending_toast.take() {
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
