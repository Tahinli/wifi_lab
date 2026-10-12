//! System interface control via `ip`/`iw` subprocess (boring + portable).
//!
//! The interface must not be under active control of NetworkManager or
//! wpa_supplicant while in monitor mode — that interference is the caller's
//! concern (this module intentionally does NOT kill daemons like airmon-ng).

use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::common::MacAddr;

/// Run a command, capturing stderr into the anyhow context on failure.
fn run(cmd: &str, args: &[String]) -> Result<String> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("spawning {cmd}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        bail!("{} {} failed: {}", cmd, args.join(" "), stderr);
    }
    Ok(stdout)
}

fn ip(args: &[&str]) -> Result<String> {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    run("ip", &args)
}

fn iw(args: &[&str]) -> Result<String> {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    run("iw", &args)
}

/// True when `ifname` shows up as a netdev in `iw dev` output.
fn iface_exists(ifname: &str) -> bool {
    iw(&["dev"])
        .map(|out| {
            out.lines()
                .any(|l| l.trim_start().starts_with("Interface ") && l.trim() == format!("Interface {ifname}"))
        })
        .unwrap_or(false)
}

/// Bring the link down, switch ifname to monitor mode, bring it up.
///
/// On drivers that cannot switch type in place, falls back to creating a
/// separate `<ifname>mon` monitor interface. Idempotent.
///
/// Returns the name of the interface that is now in monitor mode — either
/// `ifname` itself or the created `<ifname>mon`. Callers must pass the
/// returned name to channel-setting, sockets and `to_managed`.
pub fn to_monitor(ifname: &str) -> Result<String> {
    ip(&["link", "set", ifname, "down"])?;
    match iw(&["dev", ifname, "set", "type", "monitor"]) {
        Ok(_) => {
            ip(&["link", "set", ifname, "up"])?;
            Ok(ifname.to_string())
        }
        Err(e) => {
            // Fallback: add a dedicated monitor vif named `<ifname>mon`.
            let mon = format!("{ifname}mon");
            iw(&[
                "dev",
                ifname,
                "interface",
                "add",
                &mon,
                "type",
                "monitor",
            ])
            .with_context(|| format!("monitor fallback after: {e:#}"))?;
            ip(&["link", "set", &mon, "up"])?;
            // Bring the parent back up as well so the driver stays happy.
            let _ = ip(&["link", "set", ifname, "up"]);
            Ok(mon)
        }
    }
}

/// Reverse `to_monitor`: when `ifname` is a `<base>mon` vif that `to_monitor`
/// created via interface-add (probed through `iw dev`: base present too),
/// delete it; otherwise switch the interface itself back to managed mode.
pub fn to_managed(ifname: &str) -> Result<()> {
    let added_vif = ifname
        .strip_suffix("mon")
        .filter(|base| !base.is_empty())
        .map(|base| iface_exists(ifname) && iface_exists(base) && base != ifname)
        .unwrap_or(false);
    if added_vif {
        iw(&["dev", ifname, "del"])?;
        return Ok(());
    }
    ip(&["link", "set", ifname, "down"])?;
    iw(&["dev", ifname, "set", "type", "managed"])
        .or_else(|_| iw(&["dev", ifname, "set", "type", "station"]))?;
    ip(&["link", "set", ifname, "up"])?;
    Ok(())
}

/// Tune the interface to channel `ch` (one retry — some drivers drop the
/// first request when issued immediately after a mode switch).
pub fn set_channel(ifname: &str, ch: u8) -> Result<()> {
    let ch = ch.to_string();
    match iw(&["dev", ifname, "set", "channel", &ch]) {
        Ok(_) => Ok(()),
        Err(e) => {
            std::thread::sleep(std::time::Duration::from_millis(50));
            iw(&["dev", ifname, "set", "channel", &ch])
                .map(|_| ())
                .with_context(|| format!("set channel {ch} on {ifname} after retry: {e:#}"))
        }
    }
}

/// Parse `iw dev <ifname> info` for the current channel.
/// Err if not determinable.
pub fn current_channel(ifname: &str) -> Result<u8> {
    let out = iw(&["dev", ifname, "info"])?;
    for line in out.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("channel ") {
            let num: String = rest
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .unwrap_or("")
                .to_string();
            if let Ok(ch) = num.parse::<u8>() {
                return Ok(ch);
            }
        }
    }
    bail!("could not parse channel from `iw dev {ifname} info`")
}

/// Wireless interfaces present: /sys/class/net/<if> has DEVTYPE=wlan in its
/// uevent, or a `wireless` directory.
pub fn list_wifi_ifaces() -> Vec<String> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return out;
    };
    for ent in entries.flatten() {
        let name = ent.file_name().to_string_lossy().into_owned();
        let has_wireless = ent.path().join("wireless").exists();
        let uevent_wlan = std::fs::read_to_string(ent.path().join("uevent"))
            .map(|u| u.lines().any(|l| l == "DEVTYPE=wlan"))
            .unwrap_or(false);
        if has_wireless || uevent_wlan {
            out.push(name);
        }
    }
    out.sort();
    out
}

/// Our own MAC on ifname (`/sys/class/net/<ifname>/address`).
pub fn mac_of(ifname: &str) -> Result<MacAddr> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{ifname}/address"))
        .with_context(|| format!("reading MAC of {ifname}"))?;
    s.trim().parse::<MacAddr>()
        .with_context(|| format!("parsing MAC of {ifname}"))
}

/// True when running with euid 0; UI surfaces a warning otherwise.
pub fn is_root() -> bool {
    // SAFETY: geteuid is always successful and thread-safe.
    (unsafe { libc::geteuid() }) == 0
}

/// True while NetworkManager is active — it will fight channel control and
/// pin the card to the connected network's channel (only *that* SSID's
/// beacons get seen). No root needed to check.
pub fn networkmanager_active() -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", "NetworkManager"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Stop NetworkManager (and with it wpa_supplicant's radio fighting).
/// Requires root. Restart later with `systemctl start NetworkManager`.
pub fn stop_networkmanager() -> Result<()> {
    run(
        "systemctl",
        &["stop".into(), "NetworkManager".into()],
    )
    .map(|_| ())
}

/// True when `pkexec` (polkit) is available for GUI privilege elevation.
pub fn pkexec_available() -> bool {
    Command::new("pkexec")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Re-exec this binary via polkit (`pkexec`) as root, preserving the desktop
/// session environment so the elevated instance can open its own window.
///
/// Blocks until `pkexec` returns. A dismissed/cancelled authentication
/// dialog surfaces as a non-zero exit status (126/127). MUST be called off
/// the UI thread.
pub fn relaunch_elevated(extra_args: &[&str]) -> Result<std::process::ExitStatus> {
    let exe = std::env::current_exe().context("resolving current_exe for pkexec re-exec")?;
    let mut cmd = Command::new("pkexec");
    cmd.arg("env");
    // GUI + session bus env the elevated child needs to open a window and
    // talk to the user's services (GPU/DRI inherits via the session).
    for var in [
        "WAYLAND_DISPLAY",
        "XDG_RUNTIME_DIR",
        "DISPLAY",
        "DBUS_SESSION_BUS_ADDRESS",
        "XAUTHORITY",
    ] {
        if let Ok(v) = std::env::var(var) {
            cmd.arg(format!("{var}={v}"));
        }
    }
    cmd.arg(exe).args(extra_args);
    let status = cmd
        .status()
        .context("spawning pkexec — polkit not installed or no agent running")?;
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_wifi_ifaces_does_not_panic() {
        // On any host (lab box or CI container) this must return without
        // panic; entries, when present, are non-empty names.
        for name in list_wifi_ifaces() {
            assert!(!name.is_empty());
        }
    }

    #[test]
    fn mac_of_loopback_is_zero() {
        // lo always exists and always reports 00:00:00:00:00:00.
        let mac = mac_of("lo").expect("reading lo MAC");
        assert!(mac.is_zero());
    }

    #[test]
    fn mac_of_missing_iface_is_err() {
        assert!(mac_of("definitely-not-an-iface-xyz").is_err());
    }

    #[test]
    fn is_root_agrees_with_env() {
        // In dev/CI this runs unprivileged; under sudo it runs as root.
        // Either way the getter must match the process uid truth.
        assert_eq!(is_root(), (unsafe { libc::geteuid() }) == 0);
    }

    #[test]
    fn current_channel_of_missing_iface_errors_not_panics() {
        assert!(current_channel("definitely-not-an-iface-xyz").is_err());
    }
}
