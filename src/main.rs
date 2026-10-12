mod attack;
mod cli;
mod common;
mod crypto;
mod deauth;
mod dot11;
mod gpu;
mod handshake;
mod iface;
mod oui;
mod rainbow;
mod store;
mod pcapin;
mod pcapout;
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
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Headless crack of a capture file; no UI, no radio, no root.
    Crack(CrackArgs),
}

#[derive(clap::Args)]
struct CrackArgs {
    /// Path to a .hc22000 file (first crackable WPA*01/02 line is used).
    #[arg(long)]
    capture: String,
    #[arg(long, value_enum, default_value_t = CliMode::Wordlist)]
    mode: CliMode,
    /// Wordlist path (wordlist/rules/hybrid modes).
    #[arg(long)]
    wordlist: Option<String>,
    /// Rules file path (rules mode).
    #[arg(long)]
    rules: Option<String>,
    /// Bruteforce-ish minimum length.
    #[arg(long, default_value_t = 8)]
    min: usize,
    /// Bruteforce-ish maximum length.
    #[arg(long, default_value_t = 12)]
    max: usize,
    /// Wordlist × append-charset sweep (requires --wordlist).
    #[arg(long)]
    hybrid: bool,
    #[arg(long)]
    lower: bool,
    #[arg(long)]
    upper: bool,
    #[arg(long)]
    digits: bool,
    #[arg(long)]
    special: bool,
    /// Force the CPU backend (also keeps the run side-effect-free:
    /// no per-SSID PMK-cache appends).
    #[arg(long)]
    cpu: bool,
}

#[derive(clap::ValueEnum, Clone)]
enum CliMode {
    Wordlist,
    Rules,
    Bruteforce,
}

fn main() {
    let cli = Cli::parse();
    // Privileged service path: no GUI, no extra args needed (pkexec strips
    // the environment; everything the service needs comes over the pipe).
    if cli.privileged_worker {
        service::run_service(); // never returns
    }
    // Headless crack path: no UI startup, no radio, no root.
    if let Some(Commands::Crack(args)) = cli.command {
        let mode = match args.mode {
            CliMode::Wordlist => "wordlist",
            CliMode::Rules => "rules",
            CliMode::Bruteforce => "bruteforce",
        };
        let owned = cli::CliCrack {
            capture: args.capture,
            mode: mode.to_string(),
            wordlist: args.wordlist,
            rules: args.rules,
            min: args.min,
            max: args.max,
            hybrid: args.hybrid,
            lower: args.lower,
            upper: args.upper,
            digits: args.digits,
            special: args.special,
            cpu: args.cpu,
        };
        let mut out = std::io::stdout().lock();
        let code = cli::run_crack_cli(owned, &mut out);
        std::process::exit(code);
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
