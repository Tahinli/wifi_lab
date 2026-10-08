//! System interface control via `ip`/`iw` subprocess (boring + portable).
//!
//! The interface must not be under active control of NetworkManager or
//! wpa_supplicant while in monitor mode — that interference is the caller's
//! concern (this module intentionally does NOT kill daemons like airmon-ng).

use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU16, Ordering};

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

/// RF-channel arbitration shared by the hopping scanner and the attack
/// workers. The scanner consults [`ChannelPin::get`] once per hop cycle:
/// nonzero → dwell on that frequency; zero → normal hop. Attack workers
/// move the pin instead of fighting the hopper with their own `set_freq`
/// calls (the scanner re-asserts the pinned value, not the hop plan).
///
/// Two layers: `owner` is the long-lived holder's desired MHz (the
/// handshake-capture worker — it must get the channel BACK after a short
/// interruption), `active` is what the scanner currently must dwell on.
/// A deauth worker briefly [`override_freq`](ChannelPin::override_freq)s
/// `active` per band, then [`settle`](ChannelPin::settle)s to restore the
/// owner's frequency (or free hop when nothing is held).
pub struct ChannelPin {
    active: AtomicU16,
    owner: Mutex<Option<u16>>,
}

impl ChannelPin {
    /// Long-lived hold: become the owner and pin the radio to `mhz`.
    pub fn hold(&self, mhz: u16) {
        *self.owner.lock().expect("pin owner poisoned") = Some(mhz);
        self.active.store(mhz, Ordering::Release);
    }

    /// Release a hold — only by its owner (`owner == Some(mhz)`); a
    /// foreign release is ignored so a stale worker can't un-pin a newer
    /// capture. On release the scanner returns to free hopping.
    pub fn release(&self, mhz: u16) {
        let mut owner = self.owner.lock().expect("pin owner poisoned");
        if *owner == Some(mhz) {
            *owner = None;
            self.active.store(0, Ordering::Release);
        }
    }

    /// Short-lived override (deauth per-band): move the radio now WITHOUT
    /// touching ownership — a later [`settle`](ChannelPin::settle) hands
    /// the channel back to the owner.
    pub fn override_freq(&self, mhz: u16) {
        self.active.store(mhz, Ordering::Release);
    }

    /// Deauth finished: restore the owner's frequency, or free hop (0)
    /// when nothing is held.
    pub fn settle(&self) {
        let owner = *self.owner.lock().expect("pin owner poisoned");
        self.active.store(owner.unwrap_or(0), Ordering::Release);
    }

    /// MHz the scanner must dwell on; 0 = free hopping.
    pub fn get(&self) -> u16 {
        self.active.load(Ordering::Acquire)
    }
}

impl Default for ChannelPin {
    fn default() -> Self {
        ChannelPin {
            active: AtomicU16::new(0),
            owner: Mutex::new(None),
        }
    }
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

/// Unload + reload the kernel driver bound to `ifname`'s device, then wait
/// for the interface to re-enumerate and force it back DOWN (the managed
/// vif is recreated by the driver; NetworkManager may grab it otherwise).
/// Last-resort recovery for the mt76/mt7921e monitor-TX wedge: injected
/// frames report send() success but never radiate (verified on lab MT7922:
/// 12 wildcard probes → 0 probe responses; after `modprobe -r mt7921e` +
/// reload → 7 responses). RX is unaffected by the wedge, so scans look
/// healthy while deauth/PMKID silently do nothing — the only cure found is
/// a driver reload. ALL vifs (managed + monitor) on the phy die with the
/// unload; callers must recreate the monitor vif afterwards.
pub fn reset_driver(ifname: &str) -> Result<()> {
    let uevent = std::fs::read_to_string(format!("/sys/class/net/{ifname}/device/uevent"))
        .with_context(|| format!("reading device uevent for {ifname}"))?;
    let driver = uevent
        .lines()
        .find_map(|l| l.strip_prefix("DRIVER="))
        .context("no DRIVER= in device uevent — not a PCI/USB driver?)")?;
    let run_modprobe = |args: &[&str]| {
        Command::new("modprobe")
            .args(args)
            .output()
            .with_context(|| format!("running modprobe {args:?}"))
            .and_then(|o| {
                if o.status.success() {
                    Ok(())
                } else {
                    bail!("modprobe {args:?}: {}", String::from_utf8_lossy(&o.stderr))
                }
            })
    };
    run_modprobe(&["-r", driver])
        .with_context(|| format!("unloading {driver} (injection-wedge recovery)"))?;
    std::thread::sleep(std::time::Duration::from_secs(1));
    run_modprobe(&[driver]).with_context(|| format!("reloading {driver}"))?;
    // Re-enumeration (firmware load etc.) takes a moment.
    for _ in 0..50 {
        if std::path::Path::new(&format!("/sys/class/net/{ifname}")).exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if !std::path::Path::new(&format!("/sys/class/net/{ifname}")).exists() {
        bail!("{ifname} did not re-enumerate within 5 s of reloading {driver}");
    }
    std::thread::sleep(std::time::Duration::from_millis(500));
    ip(&["link", "set", ifname, "down"])?;
    Ok(())
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
/// Requires root. Restart later with [`start_networkmanager`]
/// (`systemctl start NetworkManager`).
pub fn stop_networkmanager() -> Result<()> {
    run(
        "systemctl",
        &["stop".into(), "NetworkManager".into()],
    )
    .map(|_| ())
}

/// Start NetworkManager again (mirrors [`stop_networkmanager`]), restoring
/// normal managed-mode connectivity once capture work is done. Requires root.
pub fn start_networkmanager() -> Result<()> {
    run(
        "systemctl",
        &["start".into(), "NetworkManager".into()],
    )
    .map(|_| ())
}

/// True when the monitor vif `<ifname>mon` no longer exists — the post-scan
/// restore check wants this so we can warn the user if the interface was
/// left in monitor mode.
pub fn monitor_gone(ifname: &str) -> bool {
    !iface_exists(&monitor_name(ifname))
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

    #[test]
    fn pin_defaults_to_free_hop() {
        let pin = ChannelPin::default();
        assert_eq!(pin.get(), 0);
    }

    #[test]
    fn pin_hold_pins_and_release_frees() {
        let pin = ChannelPin::default();
        pin.hold(2437);
        assert_eq!(pin.get(), 2437);
        pin.release(2437);
        assert_eq!(pin.get(), 0);
    }

    #[test]
    fn pin_foreign_release_is_ignored() {
        let pin = ChannelPin::default();
        pin.hold(2437);
        // A stale worker releasing a DIFFERENT frequency must not un-pin.
        pin.release(5180);
        assert_eq!(pin.get(), 2437);
        pin.release(2437);
        assert_eq!(pin.get(), 0);
    }

    #[test]
    fn pin_override_moves_active_but_settle_restores_owner() {
        let pin = ChannelPin::default();
        pin.hold(2437);
        // Deauth worker briefly de-tunes to another band, then settles.
        pin.override_freq(5180);
        assert_eq!(pin.get(), 5180);
        pin.settle();
        assert_eq!(pin.get(), 2437, "settle must hand the channel back to the owner");
        pin.release(2437);
        assert_eq!(pin.get(), 0);
    }

    #[test]
    fn pin_settle_without_owner_frees() {
        let pin = ChannelPin::default();
        pin.override_freq(5180);
        pin.settle();
        assert_eq!(pin.get(), 0);
    }

    #[test]
    fn pin_rehold_replaces_owner() {
        let pin = ChannelPin::default();
        pin.hold(2437);
        pin.hold(5865);
        assert_eq!(pin.get(), 5865);
        // The old owner's release is now foreign; the new one sticks.
        pin.release(2437);
        assert_eq!(pin.get(), 5865);
        pin.release(5865);
        assert_eq!(pin.get(), 0);
    }
}
