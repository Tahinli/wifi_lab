//! Attacks page: target banner, capture/PMKID/deauth triggers (mock-injected
//! into the event channel), capture cards, hc22000 export.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gpui::{
    Context, Entity, IntoElement, ParentElement, Styled, Window, div, prelude::FluentBuilder, px,
};
use gpuikit::elements::badge::badge;
use gpuikit::elements::button::button;
use gpuikit::elements::card::card;
use gpuikit::elements::loading_indicator::loading_indicator;
use gpuikit::elements::text_field::text_field;
use gpuikit::elements::typography::{h3, small, text};
use gpuikit::layout::{h_stack, v_stack};
use gpuikit::theme::{ActiveTheme, Themeable};

use crate::common::{Cmd, Event, HandshakeCapture, MacAddr, PmkidCapture};
use crate::ui::app::AppRoot;
use crate::ui::mock;

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Export all captures: platform save dialog if it opens, otherwise a fixed
/// fallback path under ./captures. Uses the crate's hc22000 formatting
/// (single source of truth in [`crate::handshake`]).
fn export_hc22000(view: &Entity<AppRoot>, _window: &mut Window, cx: &mut gpui::App) {
    let (lines, lossless_note) = {
        let app = view.read(cx);
        let mut lines: Vec<String> = app
            .state
            .handshakes
            .iter()
            .map(crate::handshake::handshake_hc22000)
            .chain(app.state.pmkids.iter().map(crate::handshake::pmkid_hc22000))
            .collect();
        lines.sort_unstable();
        lines.dedup();
        (lines, app.state.handshakes.len() + app.state.pmkids.len())
    };
    if lines.is_empty() {
        view.update(cx, |app, cx| {
            app.state.push_log("export: no captures yet");
            cx.notify();
        });
        return;
    }

    let suggested = format!("wifilab-{}.hc22000", unix_secs());
    let prompt = cx.prompt_for_new_path(Path::new("./captures"), Some(&suggested));
    let body = lines.join("\n") + "\n";
    let weak = view.downgrade();
    cx.spawn(async move |cx| {
        // Dialog refused/cancelled → fixed fallback; explicit cancel aborts.
        let path: Option<PathBuf> = match prompt.await {
            Ok(Ok(Some(p))) => Some(p),
            Ok(Ok(None)) => None,
            _ => Some(PathBuf::from("./captures").join(&suggested)),
        };
        let _ = weak.update(cx, |app, cx| {
            match path {
                None => app.state.push_log("export: cancelled"),
                Some(path) => {
                    if let Some(parent) = path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    match std::fs::write(&path, &body) {
                        Ok(()) => app
                            .state
                            .push_log(format!("export: {} captures → {}", lossless_note, path.display())),
                        Err(e) => app
                            .state
                            .push_log(format!("export FAILED: {e} ({})", path.display())),
                    }
                }
            }
            cx.notify();
        });
    })
    .detach();
}

/// Selected target with its current AP row (channel + essid).
fn target_info(app: &AppRoot) -> Option<(MacAddr, u8, String)> {
    let ap = app.selected?;
    let row = app.state.aps.get(&ap)?;
    Some((ap, row.channel, row.ssid.clone()))
}

/// Capture Handshake.
/// Mock mode: drive a fresh fabricated 4-way through the event pipeline.
/// Real mode: spawn the backend capture worker (channel probed first via
/// a zero-count deauth pulse); progress/completion arrive as real events.
fn capture_handshake(view: &Entity<AppRoot>, _window: &mut Window, cx: &mut gpui::App) {
    view.update(cx, |app, cx| {
        let Some(ap) = app.selected else {
            app.state.push_log("handshake: no target selected");
            cx.notify();
            return;
        };
        if app.attacking_handshake {
            return;
        }
        if !app.is_mock && !app.state.iface_running {
            app.state
                .push_log("handshake: start capture first (attacks need the radio in monitor mode)");
            cx.notify();
            return;
        }
        app.attacking_handshake = true;
        cx.notify();

        if !app.is_mock {
            let Some((ap, channel, essid)) = target_info(app) else {
                app.state
                    .push_log("handshake: target AP not in scan table yet");
                app.attacking_handshake = false;
                cx.notify();
                return;
            };
            app.state.push_log(format!(
                "handshake capture on {essid} ({ap}, ch {channel})…"
            ));
            if let Some(svc) = &app.service {
                svc.cmd(&Cmd::CaptureHs { ap, channel, essid });
            }
            cx.notify();
            return;
        }

        // ---- mock path ----
        let essid = app
            .state
            .aps
            .get(&ap)
            .map(|a| a.ssid.clone())
            .unwrap_or_else(|| ap.to_string());
        // Prefer a client actually associated with the target.
        let client = app
            .state
            .clients
            .values()
            .find(|c| c.ap == Some(ap))
            .map(|c| c.mac)
            .unwrap_or(mock::MOCK_CLIENTS[0]);
        app.state
            .push_log(format!("handshake capture on {essid} ({ap}), targeting {client}…"));
        cx.notify();

        let tx = app.tx.clone();
        let essid_ev = essid.clone();
        let salt = unix_secs();
        cx.spawn(async move |this, cx| {
            let _ = tx.send(Event::HandshakeProgress {
                ap,
                client,
                have: 0b0001,
            });
            cx.background_executor()
                .timer(Duration::from_millis(900))
                .await;
            let _ = tx.send(Event::HandshakeProgress {
                ap,
                client,
                have: 0b0011,
            });
            cx.background_executor()
                .timer(Duration::from_millis(900))
                .await;
            let cap = mock::fabricate_handshake(ap, client, &essid_ev, salt);
            let _ = tx.send(Event::HandshakeComplete(Box::new(cap)));
            let _ = this.update(cx, |app, cx| {
                app.attacking_handshake = false;
                cx.notify();
            });
        })
        .detach();
    });
}

/// PMKID attack: client-less, one exchange, captured PMKID arrives shortly.
fn pmkid_attack(view: &Entity<AppRoot>, _window: &mut Window, cx: &mut gpui::App) {
    view.update(cx, |app, cx| {
        let Some(ap) = app.selected else {
            app.state.push_log("pmkid: no target selected");
            cx.notify();
            return;
        };
        if app.attacking_pmkid {
            return;
        }
        if !app.is_mock && !app.state.iface_running {
            app.state
                .push_log("pmkid: start capture first (attacks need the radio in monitor mode)");
            cx.notify();
            return;
        }
        app.attacking_pmkid = true;
        cx.notify();

        if !app.is_mock {
            let Some((ap, channel, essid)) = target_info(app) else {
                app.state
                    .push_log("pmkid: target AP not in scan table yet");
                app.attacking_pmkid = false;
                cx.notify();
                return;
            };
            app.state
                .push_log(format!("pmkid attack on {essid} ({ap}, ch {channel})…"));
            if let Some(svc) = &app.service {
                svc.cmd(&Cmd::Pmkid { ap, channel, essid });
            }
            cx.notify();
            return;
        }

        // ---- mock path ----
        let essid = app
            .state
            .aps
            .get(&ap)
            .map(|a| a.ssid.clone())
            .unwrap_or_else(|| ap.to_string());
        app.state
            .push_log(format!("pmkid attack on {essid} ({ap})…"));
        cx.notify();

        let tx = app.tx.clone();
        let salt = unix_secs() ^ 0x77;
        cx.spawn(async move |this, cx| {
            cx.background_executor()
                .timer(Duration::from_millis(1200))
                .await;
            let cap = mock::fabricate_pmkid(ap, mock::MOCK_CLIENTS[3], &essid, salt);
            let _ = tx.send(Event::PmkidCaptured(cap));
            let _ = this.update(cx, |app, cx| {
                app.attacking_pmkid = false;
                cx.notify();
            });
        })
        .detach();
    });
}

/// Deauth: broadcast by default, or target the selected client's station.
/// Real mode blasts from the backend's own socket; mock mode fabricates
/// the same DeauthSent event the real worker emits.
fn deauth(view: &Entity<AppRoot>, _window: &mut Window, cx: &mut gpui::App) {
    view.update(cx, |app, cx| {
        let Some(ap) = app.selected else {
            app.state.push_log("deauth: no target selected");
            cx.notify();
            return;
        };
        let count64: u64 = app
            .deauth_input
            .read(cx)
            .content()
            .trim()
            .parse()
            .unwrap_or(16);

        if !app.is_mock {
            if !app.state.iface_running {
                app.state
                    .push_log("deauth: start capture first (injection needs monitor mode)");
                cx.notify();
                return;
            }
            let Some(svc) = &app.service else {
                app.state
                    .push_log("deauth: start capture first (the service owns the radio)");
                cx.notify();
                return;
            };
            let Some((ap, channel, _essid)) = target_info(app) else {
                app.state
                    .push_log("deauth: target AP not in scan table yet");
                cx.notify();
                return;
            };
            // A selected client row wins; otherwise deauth the whole net
            // broadcast-style. (Guard: the pair must still be consistent
            // with the live client table.)
            let target = app
                .selected_client
                .filter(|mac| {
                    app.state
                        .clients
                        .get(mac)
                        .is_some_and(|c| c.ap == Some(ap))
                })
                .unwrap_or(MacAddr::BROADCAST);
            let count = count64.min(u32::MAX as u64) as u32;
            app.state.push_log(format!(
                "deauth: {count} rounds → {target} (AP {ap}, ch {channel})"
            ));
            svc.cmd(&Cmd::Deauth {
                ap,
                target,
                channel,
                count,
            });
            cx.notify();
            return;
        }

        let _ = app.tx.send(Event::DeauthSent {
            ap,
            target: MacAddr::BROADCAST,
            count: count64,
        });
        cx.notify();
    });
}

fn kv(label: &str, value: impl Into<String>) -> gpui::Div {
    h_stack()
        .gap_2()
        .child(div().w(px(90.)).text_xs().child(label.to_string()))
        .child(text(value.into()).code().small().into_any_element())
}

fn handshake_card(hs: &HandshakeCapture, crackable: bool) -> gpuikit::elements::card::Card {
    card()
        .title(format!("{} — handshake", hs.essid))
        .description(format!("{} ⇄ {}", hs.ap, hs.client))
        .body(
            v_stack()
                .gap_1()
                .child(kv("key version", format!("{}", hs.key_ver)))
                .child(kv("anonce", hex(&hs.anonce[..8])))
                .child(
                    h_stack().gap_2().child(if crackable {
                        badge("crackable").secondary()
                    } else {
                        badge("partial")
                    }),
                )
                .into_any_element(),
        )
}

fn pmkid_card(pm: &PmkidCapture) -> gpuikit::elements::card::Card {
    card()
        .title(format!("{} — PMKID", pm.essid))
        .description(format!("AP {}", pm.ap))
        .body(
            v_stack()
                .gap_1()
                .child(kv("pmkid", hex(&pm.pmkid)))
                .child(kv("via (our mac)", pm.client.to_string()))
                .child(h_stack().gap_2().child(badge("crackable").secondary()))
                .into_any_element(),
        )
}

pub fn render(
    app: &mut AppRoot,
    view: &Entity<AppRoot>,
    _window: &mut Window,
    cx: &mut Context<AppRoot>,
) -> gpui::Div {
    let theme = cx.theme().clone();

    let target_block = match app.selected.and_then(|b| {
        app.state
            .aps
            .get(&b)
            .map(|ap| (ap.ssid.clone(), b, ap.channel))
    }) {
        Some((ssid, bssid, ch)) => h_stack()
            .gap_3()
            .items_center()
            .child(h3(format!("target: {ssid}")))
            .child(text(format!("{bssid} · ch {ch}")).code().small().into_any_element())
            .into_any_element(),
        None => h_stack()
            .gap_3()
            .items_center()
            .child(h3("target: none selected"))
            .child(small("pick an AP on the Networks page"))
            .into_any_element(),
    };

    let no_target = app.selected.is_none();
    // Real mode without a running capture has no radio: block the buttons
    // (a matching hint sits next to them).
    let not_running = !app.is_mock && !app.state.iface_running;
    let blocked = no_target || not_running;
    let hs_running = app.attacking_handshake;
    let pm_running = app.attacking_pmkid;

    let actions = h_stack()
        .gap_3()
        .items_center()
        .child(
            button("btn-handshake", "Capture Handshake")
                .disabled(blocked || hs_running)
                .on_click({
                    let view = view.clone();
                    move |_, window, cx| capture_handshake(&view, window, cx)
                }),
        )
        .child(
            button("btn-pmkid", "PMKID Attack")
                .disabled(blocked || pm_running)
                .on_click({
                    let view = view.clone();
                    move |_, window, cx| pmkid_attack(&view, window, cx)
                }),
        )
        .child(
            button("btn-deauth", "Deauth")
                .destructive()
                .disabled(blocked)
                .on_click({
                    let view = view.clone();
                    move |_, window, cx| deauth(&view, window, cx)
                }),
        )
        .child(
            div()
                .w(px(90.))
                .child(text_field(&app.deauth_input, cx).placeholder("count")),
        )
        .when(hs_running || pm_running, |el| {
            el.child(loading_indicator().small()).child(small("working…"))
        })
        .when(not_running, |el| {
            el.child(small("start capture first to enable attacks"))
        });

    // In-flight 4-way attempts shown with their message bitmask.
    let progress_cards: Vec<gpui::AnyElement> = app
        .hs_progress
        .iter()
        .map(|((ap, client), have)| {
            card()
                .title(format!("collecting 4-way… {}/4", have.count_ones()))
                .description(format!("{ap} ⇄ {client}"))
                .body(
                    h_stack()
                        .gap_2()
                        .child(loading_indicator().small())
                        .into_any_element(),
                )
                .into_any_element()
        })
        .collect();

    let mut page = v_stack()
        .size_full()
        .gap_3()
        .p_4()
        .child(target_block)
        .child(actions)
        .children(progress_cards)
        .child(gpuikit::elements::separator::separator())
        .child(
            h_stack()
                .items_center()
                .gap_3()
                .child(h3("Captures"))
                .child(small(format!(
                    "{} handshakes · {} PMKIDs",
                    app.state.handshakes.len(),
                    app.state.pmkids.len()
                )))
                .child(div().flex_1())
                .child(
                    button("btn-export", "Export .hc22000").on_click({
                        let view = view.clone();
                        move |_, window, cx| export_hc22000(&view, window, cx)
                    }),
                ),
        );

    let cards: Vec<gpui::AnyElement> = app
        .state
        .handshakes
        .iter()
        .map(|hs| handshake_card(hs, true).into_any_element())
        .chain(app.state.pmkids.iter().map(|pm| pmkid_card(pm).into_any_element()))
        .collect();
    if cards.is_empty() {
        page = page.child(small("nothing captured yet — run an attack"));
    } else {
        page = page.child(v_stack().gap_2().children(cards));
    }

    page.text_color(theme.fg())
}
