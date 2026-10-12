//! Cracker page: target dropdown (fed by captures), wordlist field, backend
//! label, Start/Stop, live throughput/progress, found-password banner.
//!
//! Until the real wgpu cracker lands, Start runs a deterministic simulation
//! on a gpui background task so every control here is live.

use std::time::Duration;

use gpui::{
    Context, Entity, IntoElement, ParentElement, Styled, Window, div, prelude::FluentBuilder, px,
};
use gpuikit::elements::button::button;
use gpuikit::elements::loading_indicator::loading_indicator;
use gpuikit::elements::progress::progress;
use gpuikit::elements::text_field::text_field;
use gpuikit::elements::typography::{h3, small, text};
use gpuikit::layout::{h_stack, v_stack};
use gpuikit::theme::{ActiveTheme, Themeable};

use crate::common::Event;
use crate::ui::app::AppRoot;

/// Mock run length: this many "candidates" before the password turns up.
const WORDLIST_TOTAL: u64 = 1_000_000;
/// Mock GPU throughput (guesses/second).
const MOCK_HPS: f64 = 1_250_000.0;
const MOCK_PASSWORD: &str = "parafin2024!";
/// Label for the backend column: real runs detect GPU-vs-CPU inside the
/// worker and log it ("cracker: GPU backend: … / CPU fallback").
const fn backend_label(is_mock: bool) -> &'static str {
    if is_mock {
        "GPU (wgpu) · mock"
    } else {
        "auto: GPU (wgpu) → CPU"
    }
}

fn fmt_hps(hps: f64) -> String {
    if hps >= 1.0e6 {
        format!("{:.2} MH/s", hps / 1.0e6)
    } else if hps >= 1.0e3 {
        format!("{:.1} kH/s", hps / 1.0e3)
    } else {
        format!("{hps:.0} H/s")
    }
}

/// Start a crack run on the selected capture.
///
/// Real mode: hands the stored [`crate::crypto::CrackTarget`] (no hc22000
/// re-parse) to the backend worker; progress and termination arrive as
/// CrackProgress/CrackFound/CrackStopped events and land in state via
/// `AppState::apply`. Requires capture stopped (radio exclusive).
/// Mock mode: a deterministic generator drives the SAME event sequence.
fn start(view: &Entity<AppRoot>, _window: &mut Window, cx: &mut gpui::App) {
    view.update(cx, |app, cx| {
        if app.crack_inflight || app.state.cracker.running {
            return;
        }
        let Some(desc) = app.state.cracker.target.clone() else {
            app.state.push_log("cracker: no target selected");
            cx.notify();
            return;
        };
        let wordlist = app.wordlist_input.read(cx).content().trim().to_string();
        if wordlist.is_empty() {
            app.state.push_log("cracker: wordlist path is empty");
            cx.notify();
            return;
        }

        // Validate everything that can fail BEFORE marking the run active,
        // so a refused start never leaves stale flags behind.
        let real_target = if !app.is_mock {
            if app.state.iface_running {
                app.state
                    .push_log("cracker: needs the radio free — stop capture first");
                cx.notify();
                return;
            }
            let Some(idx) = app.state.capture_descs().iter().position(|d| *d == desc) else {
                app.state.push_log("ERROR: cracker: capture no longer exists");
                cx.notify();
                return;
            };
            match app.state.crack_target_at(idx) {
                Some(t) => Some(t),
                None => {
                    app.state.push_log("ERROR: cracker: capture no longer exists");
                    cx.notify();
                    return;
                }
            }
        } else {
            None
        };

        app.crack_epoch += 1; // invalidate any stale mock generator ticks
        let cr = &mut app.state.cracker;
        cr.wordlist = Some(wordlist.clone());
        cr.found = None;
        cr.tried = 0;
        cr.hps = 0.0;
        cr.running = true;
        app.crack_inflight = true;
        cx.notify();

        if !app.is_mock {
            let Some(target) = real_target else { return };
            app.state.push_log(format!(
                "cracker: starting on {desc} via {wordlist} [auto backend]"
            ));
            cx.notify();
            match &app.service {
                Some(svc) => svc.spawn_crack(
                    target.describe(),
                    target,
                    std::path::PathBuf::from(&wordlist),
                    app.tx.clone(),
                ),
                None => {
                    app.state.cracker.running = false;
                    app.crack_inflight = false;
                    app.state
                        .push_log("ERROR: cracker: no service (start capture first, then stop it)");
                    cx.notify();
                }
            }
            return;
        }

        // ---- mock path: same events, fabricated numbers ----
        app.state.push_log(format!(
            "cracker: {desc} via {wordlist} [mock run]"
        ));
        cx.notify();
        let tx = app.tx.clone();
        let epoch = app.crack_epoch;
        cx.spawn(async move |this, cx| {
            let mut done = 0u64;
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(100))
                    .await;
                let live = this
                    .update(cx, |app, _cx| {
                        app.crack_epoch == epoch && app.state.cracker.running
                    })
                    .unwrap_or(false);
                if !live {
                    break;
                }
                done += (MOCK_HPS / 10.0) as u64 + done / 977 % 8_000;
                let hps = MOCK_HPS * (0.92 + (done / 331 % 15) as f64 / 100.0);
                let _ = tx.send(Event::CrackProgress { done, hps });
                if done >= WORDLIST_TOTAL {
                    let _ = tx.send(Event::CrackFound {
                        password: MOCK_PASSWORD.to_string(),
                    });
                    let _ = tx.send(Event::CrackStopped { found: true });
                    break;
                }
            }
        })
        .detach();
    });
}

/// Stop the active run.
///
/// Real mode flips the crack job's stop flag (the wordlist streamer breaks
/// at the next batch and emits CrackStopped{found:false}, which settles
/// the UI). Mock mode just invalidates the generator epoch — no terminator
/// event will arrive, so the running flags are cleared here.
fn stop(view: &Entity<AppRoot>, _window: &mut Window, cx: &mut gpui::App) {
    view.update(cx, |app, cx| {
        let active = app.crack_inflight || app.state.cracker.running;
        if !active {
            return;
        }
        app.crack_epoch += 1;
        if app.is_mock {
            app.state.cracker.running = false;
            app.crack_inflight = false;
            app.state.cracker.hps = 0.0;
            app.state.push_log("cracker: stopped by user");
            cx.notify();
            return;
        }
        if let Some(svc) = &app.service {
            svc.request_crack_stop();
            app.state.push_log("cracker: stop requested");
        } else {
            app.state.cracker.running = false;
            app.crack_inflight = false;
            app.state.push_log("cracker: stopped");
        }
        cx.notify();
    });
}

pub fn render(
    app: &mut AppRoot,
    view: &Entity<AppRoot>,
    _window: &mut Window,
    cx: &mut Context<AppRoot>,
) -> gpui::Div {
    let theme = cx.theme().clone();
    let cracker = &app.state.cracker;
    let running = cracker.running || app.crack_inflight;
    // Real runs stream an unknown-size wordlist: progress fraction is only
    // meaningful in the bounded mock run.
    let frac = if app.is_mock {
        (cracker.tried as f64 / WORDLIST_TOTAL as f64).clamp(0.0, 1.0)
    } else {
        0.0
    };
    // Real mode: cracker needs the radio free — capture must be stopped
    // and a service must have run at least once (it owns the cracker's
    // stop flag). After the first "Stop capture" this stays permanently
    // unblocked: the service is kept alive across sessions.
    let crack_blocked =
        !app.is_mock && (app.state.iface_running || app.service.is_none());
    let candidates = if app.is_mock {
        format!("candidates: {} / {WORDLIST_TOTAL}", cracker.tried)
    } else {
        format!("candidates: {}", cracker.tried)
    };

    let mut page = v_stack()
        .size_full()
        .gap_3()
        .p_4()
        .child(
            h_stack()
                .items_center()
                .gap_3()
                .child(h3("Handshake Cracker"))
                .child(small("PBKDF2-SHA1 · WPA/WPA2")),
        )
        .child(
            h_stack()
                .gap_3()
                .items_end()
                .child(div().w(px(360.)).child(app.target_select.clone()))
                .child(
                    div()
                        .w(px(360.))
                        .child(
                            text_field(&app.wordlist_input, cx)
                                .placeholder("/path/to/wordlist")
                                .full_width(true),
                        ),
                )
                .child(text(backend_label(app.is_mock)).small().muted()),
        )
        .child(
            h_stack()
                .gap_3()
                .items_center()
                .child(
                    button("btn-crack-start", "Start")
                        .disabled(running || crack_blocked)
                        .on_click({
                            let view = view.clone();
                            move |_, window, cx| start(&view, window, cx)
                        }),
                )
                .child(
                    button("btn-crack-stop", "Stop")
                        .destructive()
                        .disabled(!running)
                        .on_click({
                            let view = view.clone();
                            move |_, window, cx| stop(&view, window, cx)
                        }),
                )
                .when(running, |el| el.child(loading_indicator().small()))
                .when(crack_blocked, |el| {
                    el.child(small(if app.state.iface_running {
                        "stop capture first — cracker needs the radio"
                    } else {
                        "start then stop capture to enable the cracker"
                    }))
                }),
        )
        .child(gpuikit::elements::separator::separator())
        .child(
            h_stack()
                .gap_4()
                .child(small(format!("rate: {}", fmt_hps(if running { cracker.hps } else { 0.0 }))))
                .child(small(candidates))
                .child(
                    small(if app.is_mock {
                        format!("{:.1}%", frac * 100.0)
                    } else {
                        String::new()
                    }),
                ),
        )
        .child(progress(frac as f32).width(px(520.)));

    if let Some(found) = &cracker.found {
        page = page.child(
            h_stack()
                .gap_3()
                .items_center()
                .w(px(520.))
                .p_3()
                .rounded_md()
                .bg(theme.warning())
                .text_color(theme.bg())
                .child(text(format!("PASSWORD FOUND: {found}")).bold())
                .into_any_element(),
        );
    }

    page
}
