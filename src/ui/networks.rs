//! Networks page: sortable AP table, clients table, row-click target
//! selection.

use gpui::{Context, Entity, IntoElement, ParentElement, Styled, Window, div, px};
use gpuikit::elements::badge::badge;
use gpuikit::elements::button::button;
use gpuikit::elements::progress::progress;
use gpuikit::elements::table::{CellAlign, Column, Row, SortDirection, Table, table};
use gpuikit::elements::text_field::text_field;
use gpuikit::elements::typography::{h3, small, text};
use gpuikit::layout::{h_stack, v_stack};
use gpuikit::theme::{ActiveTheme, Themeable};

use crate::common::{AccessPoint, ClientInfo, MacAddr, ProbeInfo, Security};
use crate::ui::app::AppRoot;

use std::collections::VecDeque;

const COL_BSSID: usize = 0;
const COL_SSID: usize = 1;
// Column-order documentation; vendor columns are not sortable, so nothing
// references these by value (sort arms only name the sortable consts).
#[allow(dead_code)]
const COL_VENDOR: usize = 2;
const COL_LABEL: usize = 3;
const COL_CH: usize = 4;
const COL_BAND: usize = 5;
const COL_SEC: usize = 6;
const COL_RSSI: usize = 7;
const COL_BEACONS: usize = 8;
const COL_AGE: usize = 9;

const CCOL_MAC: usize = 0;
#[allow(dead_code)]
const CCOL_VENDOR: usize = 1;
const CCOL_STATE: usize = 2;
const CCOL_LABEL: usize = 3;
const CCOL_AP: usize = 4;
const CCOL_RSSI: usize = 5;
const CCOL_FRAMES: usize = 6;
const CCOL_AGE: usize = 7;
// Device-group id (MAC-randomization pairing); not sortable.
#[allow(dead_code)]
const CCOL_ID: usize = 8;

/// Human "last seen" age, e.g. `2s`, `5m`, `1h`. `last_seen_ms` comes from
/// the UI/service-side process-local clock ([`crate::common::now_ms`]).
pub fn age(last_seen_ms: u64) -> String {
    let s = crate::common::now_ms().saturating_sub(last_seen_ms) / 1000;
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m", s / 60)
    } else {
        format!("{}h", s / 3600)
    }
}

/// Band label for display: 2.4 GHz when the channel maps below 3 GHz,
/// else 5 GHz. (6 GHz channel numbers collide with 2.4 GHz in this app —
/// the scanner treats them as cosmetic, so 6 GHz APs may read "2.4".)
pub(crate) fn band(ch: u8) -> &'static str {
    match crate::common::freq_of_channel(ch) {
        Some(f) if f < 3000 => "2.4",
        Some(_) => "5",
        None => "?",
    }
}

pub(crate) fn sec_badge_label(label: &str, sec: Security) -> gpuikit::elements::badge::Badge {
    match sec {
        Security::Open => badge(label).outline(),
        Security::Wep => badge(label).destructive(),
        Security::Wpa | Security::Wpa2 => badge(label),
        Security::Wpa3 => badge(label).secondary(),
    }
}

fn sec_badge(sec: Security) -> gpuikit::elements::badge::Badge {
    sec_badge_label(sec.label(), sec)
}

/// Refined security label for the badge. The AKM suites of the RSN IE know
/// more than the broad `Security` buckets: a transition AP (PSK+SAE) reads
/// `WPA2/3`, an SAE-only AP reads `WPA3`, an OWE-only AP `OWE`.
pub(crate) fn sec_label(ap: &AccessPoint) -> String {
    let has = |k: crate::common::Akm| ap.akms.contains(&k);
    if ap.security == Security::Wpa3 && has(crate::common::Akm::Sae) {
        let pskish = has(crate::common::Akm::Psk)
            || has(crate::common::Akm::PskSha256)
            || has(crate::common::Akm::FtPsk);
        if !pskish {
            return "WPA3".to_string();
        }
    }
    // OWE ("enhanced open") still carries an RSN IE, so it lands in the
    // Wpa2 bucket — only the AKM list reveals it.
    if has(crate::common::Akm::Owe) && ap.akms.len() == 1 {
        return "OWE".to_string();
    }
    ap.security.label().to_string()
}

/// Station liveness badge: `up` while frames are flowing, `down` once the
/// scanner observed a deauth/disassoc hitting this client.
fn conn_badge(cl: &ClientInfo) -> gpuikit::elements::badge::Badge {
    if cl.connected {
        badge("up").secondary()
    } else {
        badge("down").destructive()
    }
}

/// Client-table text cell. Disconnected rows are dimmed so the flagged
/// stations visually recede from the live ones.
fn client_cell(cl: &ClientInfo, body: String, cx: &mut gpui::App) -> gpui::AnyElement {
    let mut cell = div().child(body);
    if !cl.connected {
        cell = cell.text_color(cx.theme().fg_muted());
    }
    cell.into_any_element()
}

/// Clients-section subtitle: `N stations`, `N stations (M down)` when the
/// scanner flagged disconnects.
fn client_counts(app: &AppRoot) -> String {
    let total = app.state.clients.len();
    let down = app.state.clients.values().filter(|c| !c.connected).count();
    if down == 0 {
        format!("{total} stations")
    } else {
        format!("{total} stations ({down} down)")
    }
}

/// OUI vendor for a MAC; `random` for locally-administered MACs (modern
/// phones/laptops rotate these — look at the ID column for the pairing),
/// `—` for unknown prefixes.
pub(crate) fn vendor_of(mac: &MacAddr) -> &'static str {
    if crate::oui::is_locally_administered(mac) {
        "random"
    } else {
        crate::oui::lookup(mac).unwrap_or("—")
    }
}

/// Normalized (trim + lowercase) form matching `state.rogue_ssids` keys.
fn norm_ssid(s: &str) -> String {
    s.trim().to_lowercase()
}

/// Sparkline cell: up to 20 bars from the recent RSSI history of `mac`,
/// right-aligned in recency order (last 20 values), padded to a stable
/// 20-slot width with transparent placeholders. Height maps rssi -95..-30
/// dBm onto 2..10 px.
pub(crate) fn sparkline(
    hist: Option<&VecDeque<i8>>,
    accent: gpui::Hsla,
) -> gpui::AnyElement {
    let mut bars: Vec<gpui::Div> = Vec::with_capacity(20);
    if let Some(hist) = hist {
        for &r in hist.iter().rev().take(20) {
            let r = r as f32;
            let h = ((r + 95.0) / 65.0 * 8.0 + 2.0).clamp(2.0, 10.0);
            bars.push(div().w(px(3.)).h(px(h)).bg(accent));
        }
        bars.reverse();
    }
    while bars.len() < 20 {
        bars.insert(0, div().w(px(3.)).h(px(1.)));
    }
    h_stack()
        .items_end()
        .gap(px(1.))
        .h(px(10.))
        .children(bars)
        .into_any_element()
}

/// MAC of the row the label editor targets: a selected client wins over
/// the selected AP.
fn label_target(app: &AppRoot) -> Option<MacAddr> {
    app.selected_client.or(app.selected)
}

/// Prefill the label input with the current label of `mac` (empty when
/// none) — called whenever a row becomes the label target.
fn prefill_label(app: &AppRoot, mac: MacAddr, cx: &mut Context<AppRoot>) {
    let cur = app.state.labels.get(&mac).cloned().unwrap_or_default();
    app.label_input
        .update(cx, |input, cx| input.set_content(cur, cx));
}

/// Save button: write the input as the label of the current target (empty
/// input = clear), then persist the whole map to `~/wifilab/labels.json`.
fn save_label(view: &Entity<AppRoot>, _window: &mut Window, cx: &mut gpui::App) {
    view.update(cx, |app, cx| {
        let Some(mac) = label_target(app) else {
            app.state.push_log("label: select an AP or client row first");
            cx.notify();
            return;
        };
        let raw = app.label_input.read(cx).content().trim().to_string();
        if raw.is_empty() {
            if app.state.labels.remove(&mac).is_some() {
                app.state.push_log(format!("label cleared: {mac}"));
            }
        } else {
            app.state.labels.insert(mac, raw.clone());
            app.state.push_log(format!("label set: {mac} = \"{raw}\""));
        }
        if let Err(e) = crate::store::save(&app.state.labels) {
            app.state.push_log(format!("label save FAILED: {e:#}"));
        }
        cx.notify();
    });
}

fn sorted_aps(app: &AppRoot) -> Vec<AccessPoint> {
    let mut rows: Vec<AccessPoint> = app.state.aps.values().cloned().collect();
    if let Some(sort) = app.ap_sort {
        let labels = &app.state.labels;
        let ord = |l: &AccessPoint, r: &AccessPoint| match sort.column {
            COL_BSSID => l.bssid.cmp(&r.bssid),
            COL_SSID => l.ssid.cmp(&r.ssid).then_with(|| l.bssid.cmp(&r.bssid)),
            COL_LABEL => labels
                .get(&l.bssid)
                .cmp(&labels.get(&r.bssid))
                .then_with(|| l.bssid.cmp(&r.bssid)),
            COL_CH => l.channel.cmp(&r.channel),
            COL_BAND => band(l.channel).cmp(band(r.channel)),
            COL_SEC => l.security.label().cmp(r.security.label()),
            COL_RSSI => l.rssi_dbm.cmp(&r.rssi_dbm),
            COL_BEACONS => l.beacons.cmp(&r.beacons),
            COL_AGE => l.last_seen_ms.cmp(&r.last_seen_ms).reverse(), // newest = 0s first
            _ => std::cmp::Ordering::Equal,
        };
        rows.sort_by(|l, r| match sort.direction {
            SortDirection::Ascending => ord(l, r),
            SortDirection::Descending => ord(l, r).reverse(),
        });
    }
    rows
}

fn sorted_clients(app: &AppRoot) -> Vec<ClientInfo> {
    let mut rows: Vec<ClientInfo> = app.state.clients.values().cloned().collect();
    if let Some(sort) = app.client_sort {
        let labels = &app.state.labels;
        let ord = |l: &ClientInfo, r: &ClientInfo| match sort.column {
            CCOL_MAC => l.mac.cmp(&r.mac),
            CCOL_STATE => l.connected.cmp(&r.connected),
            CCOL_LABEL => labels
                .get(&l.mac)
                .cmp(&labels.get(&r.mac))
                .then_with(|| l.mac.cmp(&r.mac)),
            CCOL_AP => {
            // Sort by what the column shows: the AP's SSID (bssid falls
            // back behind named entries, ties on raw MAC).
            let key = |c: &ClientInfo| {
                c.ap
                    .and_then(|b| app.state.aps.get(&b))
                    .filter(|a| !a.ssid.is_empty())
                    .map(|a| a.ssid.to_lowercase())
                    .unwrap_or_else(|| "\u{10ffff}".into())
            };
            key(l).cmp(&key(r)).then_with(|| l.ap.cmp(&r.ap))
        }
            CCOL_RSSI => l.rssi_dbm.cmp(&r.rssi_dbm),
            CCOL_FRAMES => l.frames.cmp(&r.frames),
            CCOL_AGE => l.last_seen_ms.cmp(&r.last_seen_ms).reverse(),
            _ => std::cmp::Ordering::Equal,
        };
        rows.sort_by(|l, r| match sort.direction {
            SortDirection::Ascending => ord(l, r),
            SortDirection::Descending => ord(l, r).reverse(),
        });
    }
    // Disconnected (deauth-flagged) stations sink below every connected
    // row regardless of the active sort — the state column answers "what
    // is still here", the partition is the answer at a glance. Stable
    // sort keeps the user-chosen order within each group.
    rows.sort_by_key(|c| !c.connected);
    rows
}

fn ap_table(app: &AppRoot, view: &Entity<AppRoot>) -> Table<AccessPoint> {
    let selected = app.selected;
    let rows = sorted_aps(app)
        .into_iter()
        .map(|ap| {
            let bssid = ap.bssid;
            let view = view.clone();
            Row::new(ap).selected(selected == Some(bssid)).on_click(
                move |_window, cx| {
                    view.update(cx, |app, cx| {
                        app.selected = Some(bssid);
                        // Keep the target's AP row for the Attacks card —
                        // the live record can vanish (host-capture mode
                        // never re-scans), the snapshot holds.
                        if let Some(row) = app.state.aps.get(&bssid) {
                            app.selected_ap = Some(row.clone());
                        }
                        app.selected_client = None;
                        prefill_label(app, bssid, cx);
                        app.state.push_log(format!("target selected: {bssid}"));
                        cx.notify();
                    });
                },
            )
        })
        .collect::<Vec<_>>();

    let rogues = app.state.rogue_ssids.clone();
    let rssi_hist = app.state.rssi_hist.clone();

    table("networks-aps")
        .column(
            Column::new("BSSID", |ap: &AccessPoint, _w, _cx| {
                div().child(ap.bssid.to_string()).into_any_element()
            })
            .sortable()
            .min_width(px(150.)),
        )
        .column({
            let rogues = rogues.clone();
            Column::new("SSID", move |ap: &AccessPoint, _w, _cx| {
                let mut cell = h_stack().gap_2().items_center().child(div().child(
                    if ap.ssid.is_empty() {
                        "<hidden>".to_string()
                    } else {
                        ap.ssid.clone()
                    },
                ));
                if !ap.ssid.is_empty() && rogues.contains(&norm_ssid(&ap.ssid)) {
                    cell = cell.child(badge("rogue?").destructive());
                }
                // Weak-encryption marker: Open/WEP is a liability everyone
                // in range should notice straight away.
                if matches!(ap.security, Security::Open | Security::Wep) {
                    cell = cell.child(badge("weak").destructive());
                }
                cell.into_any_element()
            })
            .sortable()
            .flex(2.0)
            .min_width(px(120.))
        })
        .column(
            Column::new("VENDOR", |ap: &AccessPoint, _w, _cx| {
                div().child(vendor_of(&ap.bssid)).into_any_element()
            })
            .flex(1.0)
            .min_width(px(90.)),
        )
        .column({
            // Snapshot per render pass (the table is rebuilt with fresh
            // state each time anyway).
            let labels = app.state.labels.clone();
            Column::new("LABEL", move |ap: &AccessPoint, _w, _cx| {
                div()
                    .child(labels.get(&ap.bssid).cloned().unwrap_or_default())
                    .into_any_element()
            })
            .sortable()
            .flex(1.0)
            .min_width(px(100.))
        })
        .column(
            Column::new("CH", |ap: &AccessPoint, _w, _cx| {
                div().child(ap.channel.to_string()).into_any_element()
            })
            .sortable()
            .fixed(px(60.))
            .end(),
        )
        .column(
            Column::new("BAND", |ap: &AccessPoint, _w, _cx| {
                div()
                    .child(format!("{} GHz", band(ap.channel)))
                    .into_any_element()
            })
            .sortable()
            .fixed(px(80.))
            .end(),
        )
        .column(
Column::new("SEC", |ap: &AccessPoint, _w, _cx| {
            // Fixed-width badge slot: the AKM text starts at the same x in
            // every row regardless of badge-label width.
            let badge_slot = div()
                .w(px(52.))
                .flex_none()
                .child(sec_badge_label(&sec_label(ap), ap.security));
            let joined = ap
                .akms
                .iter()
                .map(|a| a.label())
                .collect::<Vec<_>>()
                .join("+");
            let mut cell = h_stack().gap_1().items_center().child(badge_slot);
            if !joined.is_empty() {
                cell = cell
                    .child(div().flex_none().whitespace_nowrap().child(small(joined)))
                    .justify_start();
            }
            cell.into_any_element()
        })
        .sortable()
        .fixed(px(170.))
        .align(CellAlign::Center),
        )
        .column({
            let rssi_hist = rssi_hist.clone();
            Column::new("SIGNAL", move |ap: &AccessPoint, _w, cx| {
                sparkline(rssi_hist.get(&ap.bssid), cx.theme().accent())
            })
            .sortable()
            .fixed(px(90.))
            .align(CellAlign::Center)
        })
        .column(
            Column::new("BEACONS", |ap: &AccessPoint, _w, _cx| {
                div().child(ap.beacons.to_string()).into_any_element()
            })
            .sortable()
            .fixed(px(100.))
            .end(),
        )
        .column(
            Column::new("AGE", |ap: &AccessPoint, _w, _cx| {
                div().child(age(ap.last_seen_ms)).into_any_element()
            })
            .sortable()
            .fixed(px(70.))
            .end(),
        )
        .rows(rows)
        .sorted_by(app.ap_sort)
        .on_sort({
            let view = view.clone();
            move |request, _window, cx| {
                view.update(cx, |app, cx| {
                    app.ap_sort = Some(request.suggested());
                    cx.notify();
                });
            }
        })
        .max_h(px(340.))
        .empty("No access points heard yet — is capture running?")
}

fn client_table(app: &AppRoot, view: &Entity<AppRoot>) -> Table<ClientInfo> {
    let rows = sorted_clients(app)
        .into_iter()
        .map(|cl| {
            // Clicking a client selects the (AP, client) pair: its AP
            // becomes the target and the client is remembered for deauth.
            let ap = cl.ap;
            let mac = cl.mac;
            let view = view.clone();
            Row::new(cl)
                .selected(app.selected_client == Some(mac))
                .on_click(move |_window, cx| {
                    view.update(cx, |app, cx| {
                        match ap {
                            // Mapped client: its AP becomes the target.
                            Some(ap) => {
                                app.selected = Some(ap);
                                if let Some(row) = app.state.aps.get(&ap) {
                                    app.selected_ap = Some(row.clone());
                                }
                                app.selected_client = Some(mac);
                                prefill_label(app, mac, cx);
                                app.state
                                    .push_log(format!("target selected: {ap} (client {mac})"));
                                cx.notify();
                            }
                            // Unmapped client (scanner never resolved the
                            // association): keep the current target, target
                            // the client at it for deauth.
                            None if app.selected.is_some() => {
                                let target = app.selected.expect("checked above");
                                app.selected_client = Some(mac);
                                prefill_label(app, mac, cx);
                                app.state.push_log(format!(
                                    "client selected: {mac} (AP unmapped — deauth targets {target})"
                                ));
                                cx.notify();
                            }
                            None => {
                                app.state.push_log(format!(
                                    "client {mac}: AP unknown — pick a target AP row first"
                                ));
                                cx.notify();
                            }
                        }
                    });
                })
        })
        .collect::<Vec<_>>();

    table("networks-clients")
        .column(
            Column::new("MAC", |cl: &ClientInfo, _w, cx| {
                client_cell(cl, cl.mac.to_string(), cx)
            })
            .sortable()
            .min_width(px(150.)),
        )
        .column(
            Column::new("VENDOR", |cl: &ClientInfo, _w, cx| {
                client_cell(cl, vendor_of(&cl.mac).to_string(), cx)
            })
            .flex(1.0)
            .min_width(px(90.)),
        )
        .column(
            Column::new("STATE", |cl: &ClientInfo, _w, _cx| {
                conn_badge(cl).into_any_element()
            })
            .sortable()
            .fixed(px(90.))
            .align(CellAlign::Center),
        )
        .column({
            let labels = app.state.labels.clone();
            Column::new("LABEL", move |cl: &ClientInfo, _w, cx| {
                client_cell(cl, labels.get(&cl.mac).cloned().unwrap_or_default(), cx)
            })
            .sortable()
            .flex(1.0)
            .min_width(px(100.))
        })
        .column({
            // BSSID → SSID resolution: "which network does this client
            // belong to" reads as a name, not a MAC.
            let ap_names: std::collections::BTreeMap<MacAddr, String> = app
                .state
                .aps
                .iter()
                .filter(|(_, a)| !a.ssid.is_empty())
                .map(|(b, a)| (*b, a.ssid.clone()))
                .collect();
            Column::new("AP", move |cl: &ClientInfo, _w, cx| {
                let Some(bssid) = cl.ap else {
                    return client_cell(cl, "—".into(), cx);
                };
                match ap_names.get(&bssid) {
                    None => client_cell(cl, bssid.to_string(), cx),
                    Some(name) => {
                        let mut cell = div().child(name.clone());
                        if !cl.connected {
                            cell = cell.text_color(cx.theme().fg_muted());
                        }
                        let sub = div()
                            .text_color(cx.theme().fg_muted())
                            .child(small(bssid.to_string()));
                        v_stack().child(cell).child(sub).into_any_element()
                    }
                }
            })
            .sortable()
            .min_width(px(150.))
        })
        .column(
            Column::new("RSSI", |cl: &ClientInfo, _w, cx| {
                client_cell(cl, format!("{} dBm", cl.rssi_dbm), cx)
            })
            .sortable()
            .fixed(px(90.))
            .end(),
        )
        .column(
            Column::new("FRAMES", |cl: &ClientInfo, _w, cx| {
                client_cell(cl, cl.frames.to_string(), cx)
            })
            .sortable()
            .fixed(px(90.))
            .end(),
        )
        .column(
            Column::new("AGE", |cl: &ClientInfo, _w, cx| {
                client_cell(cl, age(cl.last_seen_ms), cx)
            })
            .sortable()
            .fixed(px(70.))
            .end(),
        )
        .column({
            // Device-group id + member count (`#1~ (2)`: group 1, "~" =
            // strong witness, two known MACs — the MAC-randomization
            // pairing). Confidence labels per `IdentConfidence::label`.
            let counts: std::collections::BTreeMap<u64, usize> = app
                .state
                .ident_groups
                .iter()
                .map(|(g, ms)| (*g, ms.len()))
                .collect();
            Column::new("ID", move |cl: &ClientInfo, _w, cx| {
                let Some(gid) = cl.ident_group else {
                    return client_cell(cl, String::new(), cx);
                };
                let conf = cl.ident_conf.map(|c| c.label()).unwrap_or("");
                let n = counts.get(&gid).copied().unwrap_or(1);
                let body = if n > 1 {
                    format!("#{gid}{conf} ({n})")
                } else {
                    format!("#{gid}{conf}")
                };
                let mut cell = div().child(body);
                if n > 1 {
                    cell = cell.text_color(cx.theme().accent());
                }
                cell.into_any_element()
            })
            .fixed(px(90.))
            .align(CellAlign::Center)
        })
        .rows(rows)
        .sorted_by(app.client_sort)
        .on_sort({
            let view = view.clone();
            move |request, _window, cx| {
                view.update(cx, |app, cx| {
                    app.client_sort = Some(request.suggested());
                    cx.notify();
                });
            }
        })
        .max_h(px(220.))
        .empty("No client stations observed")
}

/// Recently observed probe requests, newest first, capped at 300 rows.
fn probe_table(app: &AppRoot) -> Table<ProbeInfo> {
    let rows: Vec<ProbeInfo> = app.state.probes.iter().rev().take(300).cloned().collect();
    let rogues = app.state.rogue_ssids.clone();

    table("networks-probes")
        .column(
            Column::new("CLIENT", |p: &ProbeInfo, _w, _cx| {
                div()
                    .child(format!("{} ({})", p.client, vendor_of(&p.client)))
                    .into_any_element()
            })
            .min_width(px(190.)),
        )
        .column({
            let rogues = rogues.clone();
            Column::new("SSID", move |p: &ProbeInfo, _w, cx| {
                match &p.ssid {
                    Some(s) => {
                        let mut cell = div().child(s.clone());
                        if !s.is_empty() && rogues.contains(&norm_ssid(s)) {
                            cell = cell.text_color(cx.theme().warning());
                        }
                        cell.into_any_element()
                    }
                    None => div().child("<any>").into_any_element(),
                }
            })
            .flex(2.0)
            .min_width(px(120.))
        })
        .column(
            Column::new("RSSI", |p: &ProbeInfo, _w, _cx| {
                div()
                    .child(format!("{} dBm", p.rssi_dbm))
                    .into_any_element()
            })
            .fixed(px(90.))
            .end(),
        )
        .column(
            Column::new("AGE", |p: &ProbeInfo, _w, _cx| {
                div().child(age(p.at_ms)).into_any_element()
            })
            .fixed(px(70.))
            .end(),
        )
        .rows(rows.into_iter().map(Row::new).collect::<Vec<_>>())
        .max_h(px(220.))
        .empty("No probe requests observed")
}

/// Per-channel activity strip: one cell per observed channel with a small
/// progress bar scaled to the busiest channel. Hidden when idle. Used as
/// the fallback of [`channel_activity`] until the timeline has ≥2
/// snapshots.
fn channel_strip(app: &AppRoot) -> Option<gpui::AnyElement> {
    let mut stats = app.state.channel_stats.clone();
    if stats.is_empty() {
        return None;
    }
    stats.sort_by_key(|s| s.channel);
    let max_frames = stats.iter().map(|s| s.frames).max().unwrap_or(0);
    Some(
        h_stack()
            .gap_3()
            .items_center()
            .children(stats.into_iter().map(|s| {
                let frac = if max_frames < 1 {
                    0.0
                } else {
                    s.frames as f32 / max_frames as f32
                };
                v_stack()
                    .gap_1()
                    .child(small(format!("ch{}", s.channel)))
                    .child(progress(frac).width(px(60.)).height(px(4.)))
                    .child(small(s.frames.to_string()))
            }))
            .into_any_element(),
    )
}

/// Timeline over the static strip: one row per busiest channel (max 8),
/// each row a right-aligned run of per-snapshot frame-delta columns
/// (opacity = relative intensity). A channel hosting ≥4 APs gets a
/// crowded warning — overlapping BSSs eat each other's airtime.
fn channel_timeline(app: &AppRoot, theme: &gpuikit::theme::Theme) -> Option<gpui::AnyElement> {
    let tl = &app.state.chan_timeline;
    if tl.len() < 2 {
        return None;
    }
    const COLUMNS: usize = 45;
    const CROWD_WARN: usize = 4;

    // Busiest channels by latest cumulative frame count.
    let latest = tl.back().expect("len checked");
    let mut busy: Vec<crate::common::ChannelStat> = latest.clone();
    busy.sort_by_key(|s| std::cmp::Reverse(s.frames));
    busy.truncate(8);

    // AP count per channel → crowded-channel warning.
    let mut crowd: std::collections::HashMap<u8, usize> = std::collections::HashMap::new();
    for ap in app.state.aps.values() {
        if ap.channel > 0 {
            *crowd.entry(ap.channel).or_default() += 1;
        }
    }

    let accent = theme.accent();
    let rows: Vec<gpui::AnyElement> = busy
        .iter()
        .filter_map(|b| {
            let ch = b.channel;
            // Frame series for this channel across snapshots the scanner
            // reported it in (missed snapshots are skipped, minor skew).
            let series: Vec<u64> = tl
                .iter()
                .filter_map(|snap| snap.iter().find(|s| s.channel == ch).map(|s| s.frames))
                .collect();
            let deltas: Vec<u64> = series
                .windows(2)
                .map(|w| w[1].saturating_sub(w[0]))
                .collect();
            if deltas.is_empty() {
                return None;
            }
            let max = deltas.iter().copied().max().unwrap_or(0).max(1) as f32;
            let shown: &[u64] = &deltas[deltas.len().saturating_sub(COLUMNS)..];
            let mut cols: Vec<gpui::Div> = Vec::with_capacity(COLUMNS);
            // Left-pad quiet history so rows align at the newest edge.
            for _ in 0..COLUMNS.saturating_sub(shown.len()) {
                cols.push(div().w(px(4.)).h(px(12.)));
            }
            for &d in shown {
                let a = 0.15 + 0.85 * (d as f32 / max);
                cols.push(div().w(px(4.)).h(px(12.)).bg(accent.opacity(a)));
            }
            let crowd_n = *crowd.get(&ch).unwrap_or(&0);
            let mut label = div().w(px(80.)).flex_none().text_xs();
            let label_text = if crowd_n >= CROWD_WARN {
                format!("ch{ch} ⚠{crowd_n} APs")
            } else {
                format!("ch{ch}")
            };
            if crowd_n >= CROWD_WARN {
                label = label.text_color(theme.warning());
            } else {
                label = label.text_color(theme.fg_muted());
            }
            let last_delta = *deltas.last().unwrap_or(&0);
            Some(
                h_stack()
                    .gap_2()
                    .items_center()
                    .child(label.child(label_text))
                    .child(h_stack().items_end().children(cols))
                    .child(
                        div()
                            .w(px(70.))
                            .flex_none()
                            .text_xs()
                            .text_color(theme.fg_muted())
                            .child(format!("{last_delta} fr")),
                    )
                    .into_any_element(),
            )
        })
        .collect();
    if rows.is_empty() {
        return None;
    }
    Some(
        v_stack()
            .gap_1()
            .child(small(format!(
                "channel activity — last {} snapshots (one column each), brightest = busiest",
                tl.len()
            )))
            .children(rows)
            .into_any_element(),
    )
}

/// Channel activity visualization: scrolling timeline once ≥2 snapshots
/// exist, static strip before that, hidden when silent.
fn channel_activity(app: &AppRoot, theme: &gpuikit::theme::Theme) -> Option<gpui::AnyElement> {
    channel_timeline(app, theme).or_else(|| channel_strip(app))
}

pub fn render(app: &mut AppRoot, view: &Entity<AppRoot>, _window: &mut Window, cx: &mut Context<AppRoot>) -> gpui::Div {
    // Persistent label editor: applies to the selected row (a selected
    // client wins over the selected AP — see [`label_target`]).
    let label_bar = label_target(app).map(|mac| {
        h_stack()
            .items_center()
            .gap_2()
            .child(small("label for"))
            .child(text(mac.to_string()).code().small().into_any_element())
            .child(
                div()
                    .w(px(240.))
                    .child(text_field(&app.label_input, cx).placeholder("name this device…")),
            )
            .child(button("btn-label-save", "Save").on_click({
                let view = view.clone();
                move |_, window, cx| save_label(&view, window, cx)
            }))
            .child(small("(empty saves as no label)"))
            .into_any_element()
    });

    v_stack()
        .size_full()
        .gap_3()
        .p_4()
        .child(
            gpuikit::layout::h_stack()
                .items_center()
                .gap_3()
                .child(h3("Access Points"))
                .child(small(format!(
                    "{} networks — click a row to pick a target",
                    app.state.aps.len()
                ))),
        )
        .children(label_bar)
        .children(channel_activity(app, cx.theme()))
        .child(ap_table(app, view))
        .child(
            gpuikit::layout::h_stack()
                .items_center()
                .gap_3()
                .child(h3("Clients"))
                .child(small(client_counts(app))),
        )
        .child(client_table(app, view))
        .child(
            gpuikit::layout::h_stack()
                .items_center()
                .gap_3()
                .child(h3("Probes"))
                .child(small(format!("{} observed", app.state.probes.len()))),
        )
        .child(probe_table(app))
}
