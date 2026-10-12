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

/// Enter monitor mode by creating a DEDICATED monitor vif `<ifname>mon`
/// and bringing the original STA vif DOWN.
///
/// Why never switch type in place: on iwlwifi (verified on this lab box,
/// AX-class) a STA vif that has ever been associated drags a firmware
/// channel-context with it into monitor type — `iw set channel`/`set freq`
/// succeed at the cfg80211 level, `iw dev info` shows the new channel, yet
/// the RX path demonstrably stays pinned to the old association channel
/// (only that AP's frames ever arrive). A freshly created monitor vif has
/// no such context and receives everything, with the STA vif merely down.
/// Bringing the STA vif down also releases the channel context, so the
/// original interface survives (no `iw dev del`).
///
/// Idempotent. Returns the monitor vif name (`<ifname>mon`). Callers pass
/// the returned name to channel-setting and sockets, and call
/// [`teardown_monitor`] with the ORIGINAL ifname to restore.
pub fn to_monitor(ifname: &str) -> Result<String> {
    let mon = monitor_name(ifname);
    // STA down first: releases any channel context the association held.
    ip(&["link", "set", ifname, "down"])?;
    if !iface_exists(&mon) {
        let phy = phy_of(ifname)?;
        iw(&[
            "phy", &phy, "interface", "add", &mon, "type", "monitor",
        ])
        .with_context(|| format!("adding monitor vif {mon} on {phy}"))?;
    }
    ip(&["link", "set", &mon, "up"])?;
    Ok(mon)
}

/// Reverse [`to_monitor`]: delete the monitor vif if present and bring the
/// original interface back up (it never left managed type). Idempotent.
pub fn teardown_monitor(ifname: &str) -> Result<()> {
    let mon = monitor_name(ifname);
    if iface_exists(&mon) {
        let _ = ip(&["link", "set", &mon, "down"]);
        iw(&["dev", &mon, "del"])?;
    }
    if iface_exists(ifname) {
        ip(&["link", "set", ifname, "up"])?;
    }
    Ok(())
}

/// Monitor vif name convention — single source of truth.
pub fn monitor_name(ifname: &str) -> String {
    format!("{ifname}mon")
}

/// Resolve the wiphy name (e.g. "phy0") that owns `ifname` via sysfs.
fn phy_of(ifname: &str) -> Result<String> {
    let link = format!("/sys/class/net/{ifname}/phy80211");
    let target = std::fs::read_link(&link)
        .with_context(|| format!("reading {link} — is {ifname} wireless?"))?;
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_string)
        .with_context(|| format!("resolving phy name for {ifname}"))?;
    Ok(name)
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

/// Tune by carrier frequency — the only unambiguous way once 6 GHz enters
/// (6 GHz channel numbers collide with 2.4 GHz in `iw set channel`).
pub fn set_freq(ifname: &str, freq_mhz: u16) -> Result<()> {
    let f = freq_mhz.to_string();
    match iw(&["dev", ifname, "set", "freq", &f]) {
        Ok(_) => Ok(()),
        Err(e) => {
            std::thread::sleep(std::time::Duration::from_millis(50));
            iw(&["dev", ifname, "set", "freq", &f])
                .map(|_| ())
                .with_context(|| format!("set freq {f} on {ifname} after retry: {e:#}"))
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

/// True when `pkexec` (polkit) is available to elevate the privileged
/// service child.
pub fn pkexec_available() -> bool {
    Command::new("pkexec")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
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
