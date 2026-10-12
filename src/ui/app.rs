//! Root view: nav rail, header bar (interface picker, privilege badge,
//! monitor/capture toggle), page content, status line, and the background
//! task that polls the service event channel.

use std::collections::BTreeMap;
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

use crate::common::{Cmd, Event, MacAddr};
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
}

pub struct AppRoot {
    pub state: AppState,
    /// Service event channel (mock thread or service reader thread).
    pub rx: Receiver<Event>,
    /// UI-triggered actions are injected into the same pipeline.
    pub tx: Sender<Event>,
    pub page: Page,
    /// Privilege indicator; real value from [`crate::iface::is_root`].
    /// Informational only — the UI never needs root itself; the service
    /// elevates via polkit when it spawns.
    pub is_root: bool,
    /// Privileged radio service client (owns the child process + the
    /// UI-side cracker stop flag). `None` in mock mode or before the
    /// first "Start capture". Kept across stop/start cycles.
    pub service: Option<ServiceClient>,
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
            service: None,
            is_mock,
            selected: None,
            selected_client: None,
            hs_progress: BTreeMap::new(),
            attacking_handshake: false,
            attacking_pmkid: false,
            crack_inflight: false,
            pending_toast: None,
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
                "wifilab UI started (REAL backend, iface {selected_iface}) — Start capture spawns the privileged service (polkit) and brings up monitor mode"
            )
        });

        cx.on_release(|this, _cx| {
            // Window closed → root view released → shut the service down
            // (it stops workers, restores managed mode, exits) and stop
            // any UI-side crack job.
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
            self.state.iface_running = false;
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
                self.pending_toast = Some(
                    "NetworkManager is active — only your connected network may be visible; stop it from the header".into(),
                );
            }
            let ifname = self.state.ifname.clone();
            if let Some(svc) = &self.service {
                // Service already up (from an earlier session): just ask
                // for a fresh scan session.
                svc.cmd(&Cmd::StartScan {
                    ifname: ifname.clone(),
                });
                self.state.iface_running = true;
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
                    self.pending_toast =
                        Some(format!("start capture failed: {e:#}").into());
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
                }
                Event::PmkidCaptured(_) => {
                    self.attacking_pmkid = false;
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
                Event::Log(line)
                    if ["handshake:", "pmkid:"]
                        .iter()
                        .any(|p| line.starts_with(p)) =>
                {
                    self.attacking_handshake = false;
                    self.attacking_pmkid = false;
                }
                // Service-side NM result: `nm: stopped` / `nm: stop failed …`.
                Event::Log(line) if line.starts_with("nm:") => {
                    if line == "nm: stopped" {
                        self.nm_active = false;
                        self.pending_toast = Some(
                            "NetworkManager stopped — all networks become visible as the hopper cycles"
                                .into(),
                        );
                    }
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
            badge("user (service will elevate)").secondary()
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
