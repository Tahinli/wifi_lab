//! GPUI + gpuikit shell for wifilab.
//!
//! `run_app` opens the window and wires the backend event channel. Today the
//! producer is the mock generator in [`mock`]; when the real
//! radiotap/dot11/scanner/attack/cracker threads land they take over the
//! `Sender` side and the UI changes nowhere else.

mod app;
mod attacks;
mod cracker;
mod log;
mod mock;
mod networks;
pub mod state;

use std::sync::Arc;

use gpui::{
    App, AppContext, Application, Bounds, TitlebarOptions, WindowBounds, WindowOptions, px, size,
};
use gpuikit::theme::{GlobalTheme, Theme};

/// Launch the UI. Blocks until the window closes.
///
/// `mock_flag` is the CLI `--mock` switch; combined with the legacy
/// `WIFILAB_MOCK` env var. The REAL backend is the default: `Backend` is
/// created lazily on the first "Start capture" click.
pub fn run_app(iface: Option<String>, mock_flag: bool) {
    let (tx, rx) = crossbeam_channel::unbounded();

    // Mock mode: `--mock` flag or WIFILAB_MOCK=1 (any value except 0/false
    // counts as 1 when set). Default (neither set) is real mode.
    let env_mock = match std::env::var_os("WIFILAB_MOCK") {
        None => false,
        Some(v) => v != "0" && v != "false",
    };
    let is_mock = mock_flag || env_mock;
    if is_mock {
        mock::spawn_mock(tx.clone());
    }

    // Interface picker choices: every wireless interface present, with the
    // CLI/default choice first (also the fallback when detection fails).
    let mut ifaces: Vec<String> = crate::iface::list_wifi_ifaces();
    if ifaces.is_empty() {
        ifaces.push("wlp14s0".to_string());
    }
    let selected = match iface {
        Some(cli) => {
            if !ifaces.contains(&cli) {
                ifaces.insert(0, cli.clone());
            }
            cli
        }
        None => ifaces[0].clone(),
    };
    if is_mock && !ifaces.iter().any(|i| i == mock::MOCK_IFACE) {
        ifaces.push(mock::MOCK_IFACE.to_string());
    }

    Application::with_platform(gpui_platform::current_platform(false))
        .with_assets(gpuikit::assets())
        .run(move |cx: &mut App| {
            gpuikit::init(cx);
            cx.set_global(GlobalTheme(Arc::new(Theme::gruvbox_dark())));

            let window = cx
                .open_window(
                    WindowOptions {
                        titlebar: Some(TitlebarOptions {
                            title: Some("wifilab".into()),
                            ..Default::default()
                        }),
                        window_bounds: Some(WindowBounds::Windowed(Bounds {
                            origin: Default::default(),
                            size: size(px(1280.0), px(760.0)),
                        })),
                        ..Default::default()
                    },
                    {
                        let tx = tx.clone();
                        let mut rx = Some(rx);
                        move |window, cx| {
                            cx.new(|cx| {
                                app::AppRoot::new(
                                    window,
                                    cx,
                                    tx,
                                    rx.take().expect("single window"),
                                    is_mock,
                                    ifaces.clone(),
                                    selected.clone(),
                                )
                            })
                        }
                    },
                )
                .expect("open main window");

            window
                .update(cx, |_app, _window, cx| {
                    cx.activate(true);
                })
                .expect("activate main window");
        });
}
