mod common;
mod crypto;
mod deauth;
mod dot11;
mod gpu;
mod handshake;
mod iface;
mod pmkid;
mod radiotap;
mod rawsock;
mod scanner;
mod service;
mod ui;
mod wordlist;

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "wifilab",
    about = "WPA/WPA2 lab: scan, capture handshakes/PMKIDs, deauth, crack (GPU/CPU)"
)]
struct Cli {
    /// Wireless interface to use (default: first detected, else wlp14s0).
    #[arg(long)]
    iface: Option<String>,
    /// Dev mode: fabricated events, no device access. Same as WIFILAB_MOCK=1.
    #[arg(long)]
    mock: bool,
    /// Internal: run as the privileged radio service (spawned by the UI,
    /// directly or via pkexec). Never returns; JSON lines on stdin/stdout.
    #[arg(long, hide = true)]
    privileged_worker: bool,
}

fn main() {
    let cli = Cli::parse();
    // Privileged service path: no GUI, no extra args needed (pkexec strips
    // the environment; everything the service needs comes over the pipe).
    if cli.privileged_worker {
        service::run_service(); // never returns
    }
    let mock = cli.mock
        || matches!(
            std::env::var_os("WIFILAB_MOCK"),
            Some(v) if v != "0" && v != "false"
        );
    // Significantly loud one-liner: mode + iface + root status.
    let iface = cli
        .iface
        .clone()
        .unwrap_or_else(|| "(auto-detect at window open)".to_string());
    println!(
        "wifilab: mode={} iface={} root={} — {}",
        if mock { "MOCK" } else { "real" },
        iface,
        iface::is_root(),
        if mock {
            "fabricated events only"
        } else if iface::is_root() {
            "monitor mode + injection available (service runs as child)"
        } else {
            "not root — polkit will ask for authentication when you start capture"
        }
    );
    ui::run_app(cli.iface, cli.mock);
}
