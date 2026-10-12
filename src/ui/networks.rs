//! Networks page: sortable AP table, clients table, row-click target
//! selection.

use gpui::{Context, Entity, IntoElement, ParentElement, Styled, Window, div, px};
use gpuikit::elements::badge::badge;
use gpuikit::elements::table::{CellAlign, Column, Row, SortDirection, Table, table};
use gpuikit::elements::typography::{h3, small};
use gpuikit::layout::v_stack;

use crate::common::{AccessPoint, ClientInfo, MacAddr, Security};
use crate::ui::app::AppRoot;

const COL_BSSID: usize = 0;
const COL_SSID: usize = 1;
const COL_CH: usize = 2;
const COL_SEC: usize = 3;
const COL_RSSI: usize = 4;
const COL_BEACONS: usize = 5;
const COL_AGE: usize = 6;

const CCOL_MAC: usize = 0;
const CCOL_AP: usize = 1;
const CCOL_RSSI: usize = 2;
const CCOL_FRAMES: usize = 3;
const CCOL_AGE: usize = 4;

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

fn sec_badge(sec: Security) -> gpuikit::elements::badge::Badge {
    match sec {
        Security::Open => badge(sec.label()).outline(),
        Security::Wep => badge(sec.label()).destructive(),
        Security::Wpa | Security::Wpa2 => badge(sec.label()),
        Security::Wpa3 => badge(sec.label()).secondary(),
    }
}

fn sorted_aps(app: &AppRoot) -> Vec<AccessPoint> {
    let mut rows: Vec<AccessPoint> = app.state.aps.values().cloned().collect();
    if let Some(sort) = app.ap_sort {
        let ord = |l: &AccessPoint, r: &AccessPoint| match sort.column {
            COL_BSSID => l.bssid.cmp(&r.bssid),
            COL_SSID => l.ssid.cmp(&r.ssid).then_with(|| l.bssid.cmp(&r.bssid)),
            COL_CH => l.channel.cmp(&r.channel),
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
        let ord = |l: &ClientInfo, r: &ClientInfo| match sort.column {
            CCOL_MAC => l.mac.cmp(&r.mac),
            CCOL_AP => l.ap.cmp(&r.ap),
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
                        app.selected_client = None;
                        app.state.push_log(format!("target selected: {bssid}"));
                        cx.notify();
                    });
                },
            )
        })
        .collect::<Vec<_>>();

    table("networks-aps")
        .column(
            Column::new("BSSID", |ap: &AccessPoint, _w, _cx| {
                div().child(ap.bssid.to_string()).into_any_element()
            })
            .sortable()
            .min_width(px(150.)),
        )
        .column(
            Column::new("SSID", |ap: &AccessPoint, _w, _cx| {
                div().child(ap.ssid.clone()).into_any_element()
            })
            .sortable()
            .flex(2.0)
            .min_width(px(120.)),
        )
        .column(
            Column::new("CH", |ap: &AccessPoint, _w, _cx| {
                div().child(ap.channel.to_string()).into_any_element()
            })
            .sortable()
            .fixed(px(60.))
            .end(),
        )
        .column(
            Column::new("SEC", |ap: &AccessPoint, _w, _cx| {
                sec_badge(ap.security).into_any_element()
            })
            .sortable()
            .fixed(px(110.))
            .align(CellAlign::Center),
        )
        .column(
            Column::new("RSSI", |ap: &AccessPoint, _w, _cx| {
                div()
                    .child(format!("{} dBm", ap.rssi_dbm))
                    .into_any_element()
            })
            .sortable()
            .fixed(px(90.))
            .end(),
        )
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
                        if let Some(ap) = ap {
                            app.selected = Some(ap);
                            app.selected_client = Some(mac);
                            app.state
                                .push_log(format!("target selected: {ap} (client {mac})"));
                            cx.notify();
                        }
                    });
                })
        })
        .collect::<Vec<_>>();

    table("networks-clients")
        .column(
            Column::new("MAC", |cl: &ClientInfo, _w, _cx| {
                div().child(cl.mac.to_string()).into_any_element()
            })
            .sortable()
            .min_width(px(150.)),
        )
        .column(
            Column::new("AP", |cl: &ClientInfo, _w, _cx| {
                div()
                    .child(
                        cl.ap
                            .map(|ap: MacAddr| ap.to_string())
                            .unwrap_or_else(|| "—".into()),
                    )
                    .into_any_element()
            })
            .sortable()
            .min_width(px(150.)),
        )
        .column(
            Column::new("RSSI", |cl: &ClientInfo, _w, _cx| {
                div()
                    .child(format!("{} dBm", cl.rssi_dbm))
                    .into_any_element()
            })
            .sortable()
            .fixed(px(90.))
            .end(),
        )
        .column(
            Column::new("FRAMES", |cl: &ClientInfo, _w, _cx| {
                div().child(cl.frames.to_string()).into_any_element()
            })
            .sortable()
            .fixed(px(90.))
            .end(),
        )
        .column(
            Column::new("AGE", |cl: &ClientInfo, _w, _cx| {
                div().child(age(cl.last_seen_ms)).into_any_element()
            })
            .sortable()
            .fixed(px(70.))
            .end(),
        )
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

pub fn render(app: &mut AppRoot, view: &Entity<AppRoot>, _window: &mut Window, _cx: &mut Context<AppRoot>) -> gpui::Div {
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
        .child(ap_table(app, view))
        .child(
            gpuikit::layout::h_stack()
                .items_center()
                .gap_3()
                .child(h3("Clients"))
                .child(small(format!("{} stations", app.state.clients.len()))),
        )
        .child(client_table(app, view))
}
