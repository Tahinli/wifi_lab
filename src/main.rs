mod backend;
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
}

fn main() {
    let cli = Cli::parse();
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
            "monitor mode + injection available"
        } else {
            "not root — use the \"Elevate via polkit\" button in the UI header"
        }
    );
    ui::run_app(cli.iface, cli.mock);
}
