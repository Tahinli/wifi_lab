//! Privileged service + UI-side client, replacing the old monolithic
//! `Backend`.
//!
//! Architecture: the UI process never needs root. All radio work runs in a
//! privileged SERVICE — the same binary re-spawned as a child with the
//! hidden flag `--privileged-worker` (directly when the UI is already root,
//! via `pkexec` otherwise). The two halves speak JSON lines: `Cmd` on the
//! child's stdin, `Event` on its stdout (stdout is reserved EXCLUSIVELY for
//! events; diagnostics go to stderr).
//!
//! Concurrency notes (service side):
//! - The scanner and any attack worker can coexist (deauth while capturing
//!   is the whole point). They arbitrate the RF channel through ONE shared
//!   [`iface::ChannelPin`]: the capture worker holds it for its target
//!   band, a deauth worker briefly overrides it per band and settles back
//!   afterwards, and the scanner dwells on the pinned frequency instead of
//!   hopping. Attack workers open their OWN [`RawSocket`] on the monitor
//!   interface; concurrent attacks should target the SAME network — this
//!   matches the UI, which implies a single target.
//! - `to_monitor` may create a `<orig>mon` vif; the actual monitor ifname
//!   is remembered and passed to [`iface::to_managed`] on stop/shutdown
//!   (it deletes the vif or flips the interface back, as appropriate).

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use crossbeam_channel::Sender;

use crate::common::{Cmd, Event, MacAddr};
use crate::rawsock::RawSocket;
use crate::{deauth, dot11, handshake, iface, pmkid, radiotap, scanner};

/// Exact banner the service prints on stdout before any event line. The
/// client prefix-matches lines against this while waiting (pkexec may
/// prepend its own chatter).
pub const READY_LINE: &str = "WIFILAB-SVC-READY";

/// How long the client waits for the service's READY banner (the polkit
/// dialog can block on a slow human).
const READY_TIMEOUT: Duration = Duration::from_secs(60);

fn send(tx: &Sender<Event>, ev: Event) {
    let _ = tx.send(ev);
}

fn log(tx: &Sender<Event>, msg: impl Into<String>) {
    send(tx, Event::Log(msg.into()));
}

fn log_err(tx: &Sender<Event>, msg: impl Into<String>) {
    send(tx, Event::Error(msg.into()));
}

/// RAII release of a [`iface::ChannelPin::hold`] — the capture worker's
/// channel hold is released on EVERY worker exit path (normal, error,
/// early return), never leaving the scanner pinned forever.
struct PinGuard {
    pin: Arc<iface::ChannelPin>,
    mhz: u16,
}

impl Drop for PinGuard {
    fn drop(&mut self) {
        self.pin.release(self.mhz);
    }
}

/// Wildcard-probe canary: broadcast probe requests on `mon` (already
/// tuned to the channel it will work on) and look for ANY probe response
/// (mgmt subtype 5) on the air. Why this exists: mt76/mt7921e's
/// monitor-TX path wedges silently — `send()` succeeds and RX stays
/// perfectly healthy (scans look normal), but injected frames never
/// radiate until the driver is reloaded (verified on the lab MT7922: 0
/// probe responses when wedged, 7 after `modprobe -r mt7921e` + reload).
/// ~1.2 s; Ok(false) = wedge detected, Err = canary itself inconclusive.
fn injection_canary(mon: &str) -> Result<bool> {
    let sock = RawSocket::open(mon).context("canary socket")?;
    sock.set_timeout(100)?;
    let sa = iface::mac_of(mon)?;
    let mut frame = radiotap::INJECT_HDR.to_vec();
    frame.extend_from_slice(&dot11::build_probe_req(&[], &sa));
    let mut buf = [0u8; 2048];
    let deadline = Instant::now() + Duration::from_millis(1200);
    while Instant::now() < deadline {
        let _ = sock.send(&frame); // ~10 probes across the window
        match sock.recv(&mut buf) {
            Ok(n) if is_probe_response(&buf[..n]) => return Ok(true),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e).context("canary recv"),
        }
    }
    Ok(false)
}

/// radiotap-wrapped 802.11 frame → is it a probe response (mgmt, st 5)?
fn is_probe_response(f: &[u8]) -> bool {
    let Some(rt_len) = f.get(2..4).map(|b| u16::from_le_bytes([b[0], b[1]]) as usize) else {
        return false;
    };
    let Some(fc) = f
        .get(rt_len..rt_len + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
    else {
        return false;
    };
    (fc >> 2) & 3 == 0 && (fc >> 4) & 0xF == 5
}

// ---------------------------------------------------------------------------
// Privileged half — runs as the `--privileged-worker` child process.
// ---------------------------------------------------------------------------

/// Radio-side state owned by the service process. Mirrors the old
/// `Backend` minus the cracker (which moved into the UI process).
struct RadioService {
    stop: Arc<AtomicBool>,
    handles: Mutex<Vec<JoinHandle<()>>>,
    /// Name of the interface currently in monitor mode (`None` if the
    /// mode switch failed at StartScan — nothing to restore then).
    mon_ifname: Option<String>,
    /// Interface the UI asked for; restored to managed mode on stop/
    /// shutdown when it differs from `mon_ifname`.
    orig_ifname: Option<String>,
    /// Event pipe: the forwarder thread owns the receiving end and
    /// serializes one JSON line per event onto stdout.
    tx: Sender<Event>,
    /// Channel arbitration shared with the scanner (see
    /// [`iface::ChannelPin`]): capture workers hold it, deauth briefly
    /// overrides it, the scanner dwells on it instead of hopping.
    pin: Arc<iface::ChannelPin>,
    /// BSSIDs of APs we are actively deauthenticating: the scanner's
    /// foreign-deauth detector suppresses frames sourced from these (our
    /// blasts carry the AP's BSSID as transmitter).
    deauth_suppress: Arc<Mutex<std::collections::HashSet<MacAddr>>>,
    /// Live pcap spool: `(path, shared writer)`. The writer is reused
    /// across scans while the path matches and `fresh_spool` is unset.
    spool: Option<(std::path::PathBuf, Arc<Mutex<crate::pcapout::PcapWriter>>)>,
    /// Set when this session stopped NetworkManager — shutdown restarts
    /// it (best-effort) so the box is left the way we found it.
    stopped_nm: Arc<AtomicBool>,
}

impl RadioService {
    fn new(tx: Sender<Event>) -> Self {
        RadioService {
            stop: Arc::new(AtomicBool::new(false)),
            handles: Mutex::new(Vec::new()),
            mon_ifname: None,
            orig_ifname: None,
            tx,
            pin: Arc::new(iface::ChannelPin::default()),
            deauth_suppress: Arc::new(Mutex::new(std::collections::HashSet::new())),
            spool: None,
            stopped_nm: Arc::new(AtomicBool::new(false)),
        }
    }

    fn mon(&self) -> Option<String> {
        self.mon_ifname
            .clone()
            .or_else(|| self.orig_ifname.clone())
    }

    /// Verify injected frames actually radiate; on failure reload the
    /// NIC's driver (the only known cure for the mt76 monitor-TX wedge)
    /// and recreate the monitor vif. Returns the monitor ifname to use —
    /// unchanged unless a recovery happened.
    fn ensure_injection(&self, base: &str, mon: String) -> String {
        match injection_canary(&mon) {
            Ok(true) => {
                log(&self.tx, "injection canary: probe responses seen — TX path OK");
                mon
            }
            Ok(false) => {
                log_err(
                    &self.tx,
                    format!(
                        "injection canary: NO probe responses on {mon} — injected frames are \
                         NOT radiating (driver TX wedge); reloading the wifi driver"
                    ),
                );
                match iface::reset_driver(base).and_then(|_| iface::to_monitor(base)) {
                    Ok(new_mon) => {
                        log(
                            &self.tx,
                            format!("driver reloaded, monitor vif {new_mon} recreated — re-running canary"),
                        );
                        match injection_canary(&new_mon) {
                            Ok(true) => log(&self.tx, "injection canary after recovery: OK"),
                            Ok(false) => log_err(
                                &self.tx,
                                "injection STILL dead after driver reload — scanning works but \
                                 deauth/PMKID will not; check for a kernel/firmware update",
                            ),
                            Err(e) => log_err(&self.tx, format!("post-recovery canary inconclusive: {e:#}")),
                        }
                        new_mon
                    }
                    Err(e) => {
                        log_err(
                            &self.tx,
                            format!("driver reload recovery failed: {e:#} — keeping {mon}; deauth/PMKID may not work"),
                        );
                        mon
                    }
                }
            }
            Err(e) => {
                log(&self.tx, format!("injection canary inconclusive on {mon}: {e:#} — proceeding"));
                mon
            }
        }
    }

    /// Switch `ifname` to monitor mode and start the scanner (full hop
    /// list when `channels` is empty, else parked on the given channels).
    /// Restart-safe: a running session's workers (scanner AND attacks) are
    /// stopped first, and the monitor interface is reused when it's
    /// already up for the same `ifname`. On any failure an [`Event::Error`]
    /// is emitted, the interface is put back into managed mode (best
    /// effort).
    fn start_scan(
        &mut self,
        ifname: &str,
        channels: &[u8],
        spool: Option<std::path::PathBuf>,
        fresh_spool: bool,
    ) {
        // Stop the CURRENT worker set first (scanner + attack workers): a
        // re-StartScan while running must not leak the old scanner thread —
        // it held the old stop flag and would keep hopping forever,
        // fighting the new channel plan. When the monitor interface already
        // exists for the SAME ifname it is reused (no managed↔monitor
        // churn); only the channel plan/workers change.
        let reuse_mon =
            self.orig_ifname.as_deref() == Some(ifname) && self.mon_ifname.is_some();
        self.stop.store(true, Ordering::Release);
        let old = std::mem::take(&mut *self.handles.lock().expect("handles poisoned"));
        for h in old {
            let _ = h.join();
        }
        self.stop = Arc::new(AtomicBool::new(false));
        self.orig_ifname = Some(ifname.to_string());

        // Resolve the spool writer BEFORE workers spawn: same path +
        // non-fresh reuses the open writer (truncating mid-scan would
        // interleave frame bytes with the just-rewritten header of the
        // old handle); a fresh flag or a new path reopens. Failures log
        // once and the scan simply runs without a spool.
        let spool_writer: Option<Arc<Mutex<crate::pcapout::PcapWriter>>> = match spool {
            Some(path) => {
                let reusable = match &self.spool {
                    Some((p, w)) if !fresh_spool && *p == path => Some(w.clone()),
                    _ => None,
                };
                match reusable {
                    Some(w) => {
                        self.spool = Some((path, w.clone()));
                        Some(w)
                    }
                    None => {
                        let opened = if fresh_spool {
                            crate::pcapout::create(&path)
                        } else {
                            crate::pcapout::from_path_append(&path)
                        };
                        match opened {
                            Ok(w) => {
                                let w = Arc::new(Mutex::new(w));
                                self.spool = Some((path, w.clone()));
                                Some(w)
                            }
                            Err(e) => {
                                log_err(&self.tx, format!("pcap spool at {} disabled: {e}", path.display()));
                                self.spool = None;
                                None
                            }
                        }
                    }
                }
            }
            None => {
                self.spool = None;
                None
            }
        };

        let mon_ifname = if reuse_mon {
            self.mon_ifname.clone().expect("reuse_mon ⇒ mon_ifname set")
        } else {
            self.mon_ifname = None;
            match iface::to_monitor(ifname) {
                Ok(name) => name,
                Err(e) => {
                    log_err(&self.tx, format!("monitor mode on {ifname} failed: {e:#}"));
                    // Best effort: leave the box the way we found it.
                    let _ = iface::teardown_monitor(ifname);
                    self.orig_ifname = None;
                    return;
                }
            }
        };
        // Injection canary BEFORE any worker spawns: a wedged TX path
        // would leave scans healthy while deauth/PMKID silently do
        // nothing. Recovery (driver reload + vif recreate) swaps the
        // monitor ifname.
        let mon_ifname = self.ensure_injection(ifname, mon_ifname);
        self.mon_ifname = Some(mon_ifname.clone());
        if reuse_mon {
            log(
                &self.tx,
                format!("scanner restarted on {mon_ifname} ({} channel(s))", channels.len().max(1)),
            );
        } else {
            log(&self.tx, format!("monitor mode up on {mon_ifname} (was {ifname})"));
        }

        // Own MAC on the monitor vif: deauth frames we transmit never
        // loop back into the RX path on most cards, but when they do the
        // storm detector must not cry wolf. Unresolvable → ZERO (matches
        // nothing real).
        let own_mac = iface::mac_of(&mon_ifname).unwrap_or(MacAddr::ZERO);

        // Parked-diagnostic channel numbers (2.4/5 GHz) map to frequencies;
        // empty = full default hop list incl. 6 GHz PSC.
        let freqs: Vec<u16> = channels
            .iter()
            .filter_map(|&ch| crate::common::freq_of_channel(ch))
            .collect();
        let cfg = scanner::ScannerConfig {
            ifname: mon_ifname,
            freqs,
            dwell_ms: 100,
            rssi_floor: -95,
            pin: self.pin.clone(),
            own_mac,
            deauth_suppress: self.deauth_suppress.clone(),
            spool: spool_writer,
        };
        let stop = self.stop.clone();
        let tx = self.tx.clone();
        match std::thread::Builder::new()
            .name("wifilab-scanner".into())
            .spawn(move || {
                if let Err(e) = scanner::run(cfg, tx.clone(), stop) {
                    log_err(&tx, format!("scanner stopped: {e:#}"));
                }
            }) {
            Ok(h) => self.handles.lock().expect("handles poisoned").push(h),
            Err(e) => {
                log_err(&self.tx, format!("scanner: spawn failed: {e}"));
                // Leave the UI consistent: nothing runs but the interface
                // is in monitor mode — flip it back.
                if self.mon_ifname.take().is_some() {
                    if let Some(orig) = &self.orig_ifname {
                        let _ = iface::teardown_monitor(orig);
                    }
                }
            }
        }
    }

    /// Stop the scanner + all attack workers and restore managed mode.
    /// The service stays alive for a subsequent StartScan. Idempotent.
    fn stop_scan(&mut self) {
        self.stop.store(true, Ordering::Release);
        let handles = std::mem::take(&mut *self.handles.lock().expect("handles poisoned"));
        for h in handles {
            let _ = h.join();
        }
        // Flush the pcap spool now that the scanner thread is joined: an
        // Export .pcap copies the file from disk and must see every frame.
        // The writer stays open for reuse by the next StartScan.
        if let Some((_, w)) = &self.spool {
            if let Ok(mut w) = w.lock() {
                if let Err(e) = w.finish() {
                    log_err(&self.tx, format!("pcap spool flush failed: {e:#}"));
                }
            }
        }
        let orig = self.orig_ifname.take();
        if let Some(orig) = &orig {
            if self.mon_ifname.take().is_some() {
                if let Err(e) = iface::teardown_monitor(orig) {
                    eprintln!("wifilab-svc: teardown_monitor({orig}) failed: {e:#}");
                }
            }
        }
        self.restore_check(orig.as_deref());
    }

    /// Post-teardown hygiene: a surviving `<orig>mon` vif means the driver
    /// refused our delete (or teardown never ran) — the user is left with
    /// no working wifi and needs the exact recovery command. Then restart
    /// NetworkManager if we stopped it this session. Idempotent (the NM
    /// flag is consumed), so the shutdown tail can re-run it safely; the
    /// monitor check is skipped when no scan session ever ran.
    fn restore_check(&self, orig: Option<&str>) {
        if let Some(orig) = orig {
            if !iface::monitor_gone(orig) {
                log_err(
                    &self.tx,
                    format!(
                        "interface left in monitor mode; fix: sudo iw dev {orig}mon del"
                    ),
                );
            }
        }
        if self.stopped_nm.swap(false, Ordering::AcqRel) {
            match iface::start_networkmanager() {
                Ok(()) => log(&self.tx, "nm: NetworkManager restarted"),
                Err(e) => log_err(&self.tx, format!("nm: restart failed: {e:#}")),
            }
        }
    }

    /// Register a worker thread; on spawn failure the error is reported on
    /// the event pipe.
    fn spawn(
        &self,
        name: &str,
        what: &str,
        f: impl FnOnce(Sender<Event>) + Send + 'static,
    ) -> bool {
        let worker_tx = self.tx.clone();
        match std::thread::Builder::new()
            .name(name.to_string())
            .spawn(move || f(worker_tx))
        {
            Ok(h) => {
                self.handles.lock().expect("handles poisoned").push(h);
                true
            }
            Err(e) => {
                log_err(&self.tx, format!("{what}: spawn failed: {e}"));
                false
            }
        }
    }

    /// Deauth worker: opens its own raw socket on the monitor interface,
    /// then for each `(bssid, channel)` in `aps` tunes the channel and
    /// blasts `count` rounds at `target` (broadcast allowed). Multi-entry
    /// lists cover dual-band targets — the client picks the band, we don't
    /// get to. Emits DeauthSent progress (via [`deauth::blast`]) per band.
    ///
    /// Channel arbitration: each band first moves the shared pin
    /// (`override_freq` — the scanner re-asserts it, so the radio stays on
    /// the band across the whole blast instead of being hopped away
    /// mid-burst), with one immediate `set_channel` so TX starts now.
    /// Afterwards `settle` hands the channel back to a held capture (or
    /// free hop). The blast honors the stop flag per round, so a scan
    /// restart's stop-join does not block the command loop.
    fn deauth(&self, aps: Vec<(MacAddr, u8)>, target: MacAddr, count: u32) {
        let Some(mon) = self.mon() else {
            log_err(&self.tx, "deauth: no scan session — StartScan first");
            return;
        };
        let pin = self.pin.clone();
        let stop = self.stop.clone();
        // Own frames must not trip the foreign-deauth detector: our blasts
        // carry each AP's BSSID as transmitter (addr2).
        if let Ok(mut s) = self.deauth_suppress.lock() {
            for (bssid, _) in &aps {
                s.insert(*bssid);
            }
        }
        let suppress = self.deauth_suppress.clone();
        self.spawn("wifilab-deauth", "deauth", move |tx| {
            deauth_worker(&mon, &aps, target, count, &pin, &stop, &tx);
            // Whatever happened above (early error return included): hand
            // the channel back to the capture hold, else free hop.
            pin.settle();
            if let Ok(mut s) = suppress.lock() {
                for (bssid, _) in &aps {
                    s.remove(bssid);
                }
            }
        });
    }

    /// Multi-client deauth: one worker pins `ap`'s channel and blasts
    /// `count` rounds at each target in turn, finishing with one
    /// broadcast blast (catches clients we haven't seen). Per-target
    /// errors are logged and skipped; the pin settles at the end
    /// regardless.
    fn deauth_all(&self, ap: MacAddr, channel: u8, targets: Vec<MacAddr>, count: u32) {
        let Some(mon) = self.mon() else {
            log_err(&self.tx, "deauth-all: no scan session — StartScan first");
            return;
        };
        let pin = self.pin.clone();
        let stop = self.stop.clone();
        if let Ok(mut s) = self.deauth_suppress.lock() {
            s.insert(ap);
        }
        let suppress = self.deauth_suppress.clone();
        self.spawn("wifilab-deauth-all", "deauth-all", move |tx| {
            let sock = match RawSocket::open(&mon) {
                Ok(s) => s,
                Err(e) => {
                    log_err(&tx, format!("deauth-all: raw socket on {mon} failed: {e}"));
                    pin.settle();
                    if let Ok(mut s) = suppress.lock() {
                        s.remove(&ap);
                    }
                    return;
                }
            };
            // Move the pin first (scanner re-asserts this band, not the
            // hop plan), then one immediate tune so TX starts this instant.
            if let Some(mhz) = crate::common::freq_of_channel(channel) {
                pin.override_freq(mhz);
            }
            if let Err(e) = iface::set_channel(&mon, channel) {
                log(&tx, format!("deauth-all: set_channel {channel} failed: {e:#}"));
            }
            for target in &targets {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                match deauth::blast(&sock, &ap, target, count, &tx, &stop) {
                    Ok(sent) => log(
                        &tx,
                        format!("deauth-all: {sent} frames → {target} (AP {ap}, ch {channel})"),
                    ),
                    Err(e) => log_err(&tx, format!("deauth-all: {target}: {e:#}")),
                }
            }
            if !stop.load(Ordering::Relaxed) {
                match deauth::blast(&sock, &ap, &MacAddr::BROADCAST, count, &tx, &stop) {
                    Ok(sent) => log(
                        &tx,
                        format!("deauth-all: {sent} frames → broadcast (AP {ap}, ch {channel})"),
                    ),
                    Err(e) => log_err(&tx, format!("deauth-all: broadcast: {e:#}")),
                }
            }
            pin.settle();
            if let Ok(mut s) = suppress.lock() {
                s.remove(&ap);
            }
        });
    }

    /// PMKID grab worker: single client-less auth+assoc attempt against
    /// `ap`, impersonating the monitor interface's own MAC. Emits
    /// PmkidCaptured or a "no PMKID" log line.
    fn pmkid(&self, ap: MacAddr, channel: u8, essid: String) {
        let Some(mon) = self.mon() else {
            log_err(&self.tx, "pmkid: no scan session — StartScan first");
            return;
        };
        self.spawn("wifilab-pmkid", "pmkid", move |tx| {
            let sta = match iface::mac_of(&mon) {
                Ok(m) => m,
                Err(e) => {
                    log_err(&tx, format!("pmkid: own MAC of {mon}: {e:#}"));
                    return;
                }
            };
            let sock = match RawSocket::open(&mon) {
                Ok(s) => s,
                Err(e) => {
                    log_err(&tx, format!("pmkid: raw socket on {mon} failed: {e}"));
                    return;
                }
            };
            if let Err(e) = iface::set_channel(&mon, channel) {
                log(&tx, format!("pmkid: set_channel {channel} failed: {e:#}"));
            }
            match pmkid::grab(&sock, &ap, &sta, &essid, &tx) {
                Ok(Some(cap)) => send(&tx, Event::PmkidCaptured(cap)),
                Ok(None) => log(&tx, format!("pmkid: no PMKID volunteered by {ap}")),
                Err(e) => log_err(&tx, format!("pmkid: {e:#}")),
            }
        });
    }

    /// 4-way capture worker over every `(bssid, channel)` in `targets`
    /// (dual-band aware; `targets[0]` is the selected BSSID — the UI puts
    /// its band first and that's where a deauthed client will re-auth, so
    /// that's the band we hold). Opens its own raw socket and runs
    /// [`handshake::capture_loop`] (stop flag checked every 250 ms frame
    /// poll). [`Event::HandshakeComplete`] is emitted from inside the loop
    /// when a crackable pair completes.
    ///
    /// Channel arbitration: the pin is HELD synchronously here — before
    /// the worker spawns — so a concurrently-arriving Deauth command sees
    /// the capture as owner deterministically. The worker's [`PinGuard`]
    /// releases on every exit path; the scanner dwells on the held
    /// frequency instead of hopping, so M1/M2 can't land in different
    /// dwell windows.
    fn capture_hs(&self, targets: Vec<(MacAddr, u8)>, essid: String) {
        let Some(mon) = self.mon() else {
            log_err(&self.tx, "handshake: no scan session — StartScan first");
            return;
        };
        let hold = targets
            .first()
            .and_then(|(_, ch)| crate::common::freq_of_channel(*ch));
        if let Some(mhz) = hold {
            self.pin.hold(mhz);
            log(&self.tx, format!("handshake: channel held at {mhz} MHz"));
        }
        let pin = self.pin.clone();
        let stop = self.stop.clone();
        let spawned = self.spawn("wifilab-capture", "handshake", move |tx| {
            let _guard = hold.map(|mhz| PinGuard { pin, mhz });
            let bssids: Vec<MacAddr> = targets.iter().map(|(b, _)| *b).collect();
            let mut channels: Vec<u8> = targets.iter().map(|(_, c)| *c).collect();
            channels.sort_unstable();
            channels.dedup();
            if channels.len() == 1 {
                // Apply immediately; the scanner re-asserts the same held
                // frequency from now on.
                if let Err(e) = iface::set_channel(&mon, channels[0]) {
                    log_err(&tx, format!("handshake: set_channel {} on {mon}: {e:#}", channels[0]));
                    return;
                }
            }
            let sock = match RawSocket::open(&mon) {
                Ok(s) => s,
                Err(e) => {
                    log_err(&tx, format!("handshake: raw socket on {mon} failed: {e}"));
                    return;
                }
            };
            match handshake::capture_loop(&sock, &bssids, &essid, &tx, &stop) {
                Ok(true) => {}
                Ok(false) => log(
                    &tx,
                    format!("handshake: capture ended without a pair ({essid}, {} bssid(s))", bssids.len()),
                ),
                Err(e) => log_err(&tx, format!("handshake: {e:#}")),
            }
        });
        if !spawned {
            // Worker never started — nobody else will release the hold.
            if let Some(mhz) = hold {
                self.pin.release(mhz);
            }
        }
    }

    fn stop_networkmanager(&self) {
        match iface::stop_networkmanager() {
            Ok(()) => {
                self.stopped_nm.store(true, Ordering::Release);
                log(&self.tx, "nm: stopped");
            }
            Err(e) => log(&self.tx, format!("nm: stop failed: {e:#}")),
        }
    }
}

/// Body of the deauth worker (early returns on socket/TX errors; the
/// caller settles the pin afterwards regardless).
fn deauth_worker(
    mon: &str,
    aps: &[(MacAddr, u8)],
    target: MacAddr,
    count: u32,
    pin: &iface::ChannelPin,
    stop: &AtomicBool,
    tx: &Sender<Event>,
) {
    let sock = match RawSocket::open(mon) {
        Ok(s) => s,
        Err(e) => {
            log_err(tx, format!("deauth: raw socket on {mon} failed: {e}"));
            return;
        }
    };
    for (ap, channel) in aps {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        // Move the pin first (scanner re-asserts this band, not the hop
        // plan), then one immediate tune so TX starts this instant.
        if let Some(mhz) = crate::common::freq_of_channel(*channel) {
            pin.override_freq(mhz);
        }
        if let Err(e) = iface::set_channel(mon, *channel) {
            log(tx, format!("deauth: set_channel {channel} failed: {e:#}"));
        }
        match deauth::blast(&sock, ap, &target, count, tx, stop) {
            Ok(sent) => log(
                tx,
                format!("deauth: done, {sent} frames → {target} (AP {ap}, ch {channel})"),
            ),
            Err(e) => {
                log_err(tx, format!("deauth: {e:#}"));
                return;
            }
        }
    }
}

/// Service entry point: never returns (process exits from inside).
///
/// stdout carries exactly one READY banner and then one JSON-serialized
/// [`Event`] per line — nothing else. stderr is free for diagnostics.
pub fn run_service() -> ! {
    let code = service_main();
    std::process::exit(code);
}

fn service_main() -> i32 {
    let stdout = std::io::stdout();
    // Buffered writer handed to the forwarder thread; the banner uses the
    // same lock discipline by printing through a dedicated line with an
    // explicit flush BEFORE the forwarder starts.
    {
        let mut out = stdout.lock();
        let _ = out.write_all(READY_LINE.as_bytes());
        let _ = out.write_all(b"\n");
        let _ = out.flush();
    }

    // Single writer to stdout: every event — scanner, attacks, errors,
    // logs — funnels through this channel and gets serialized by ONE
    // forwarder thread, so lines never interleave.
    let (tx, rx) = crossbeam_channel::unbounded::<Event>();
    let forwarder = std::thread::Builder::new()
        .name("wifilab-svc-fwd".into())
        .spawn(move || {
            let stdout = std::io::stdout();
            let mut out = std::io::BufWriter::new(stdout.lock());
            // Bounded drain: when the channel closes (main loop out of
            // scope) we finish queued events and exit.
            while let Ok(ev) = rx.recv() {
                match serde_json::to_string(&ev) {
                    Ok(line) => {
                        if out.write_all(line.as_bytes()).is_err()
                            || out.write_all(b"\n").is_err()
                            || out.flush().is_err()
                        {
                            return; // parent gone
                        }
                    }
                    Err(e) => eprintln!("wifilab-svc: event serialization failed: {e}"),
                }
            }
        })
        .expect("spawning service forwarder thread");

    let mut radio = RadioService::new(tx.clone());
    let stdin = std::io::stdin();
    let mut lines = BufReader::new(stdin.lock()).lines();
    loop {
        let line = match lines.next() {
            Some(Ok(l)) => l,
            Some(Err(e)) => {
                eprintln!("wifilab-svc: stdin read failed: {e}");
                break; // treat as EOF
            }
            None => break, // EOF: parent closed the pipe
        };
        if line.trim().is_empty() {
            continue;
        }
        let cmd: Cmd = match serde_json::from_str(&line) {
            Ok(c) => c,
            Err(e) => {
                log_err(&tx, format!("service: bad command line ({}): {e}", &line[..line.len().min(80)]));
                continue;
            }
        };
        match cmd {
            Cmd::StartScan {
                ifname,
                channels,
                spool,
                fresh_spool,
            } => radio.start_scan(&ifname, channels.as_deref().unwrap_or(&[]), spool, fresh_spool),
            Cmd::StopScan => radio.stop_scan(),
            Cmd::Deauth { aps, target, count } => radio.deauth(aps, target, count),
            Cmd::DeauthAll {
                ap,
                channel,
                targets,
                count,
            } => radio.deauth_all(ap, channel, targets, count),
            Cmd::Pmkid { ap, channel, essid } => radio.pmkid(ap, channel, essid),
            Cmd::CaptureHs { targets, essid } => radio.capture_hs(targets, essid),
            Cmd::StopNetworkManager => radio.stop_networkmanager(),
            Cmd::Shutdown => break,
        }
    }

    // Stop everything, restore the interface, drain the event pipe so the
    // last error lines still reach the UI, and exit. stop_scan runs the
    // monitor-mode restore-check (a surviving `<if>mon` vif → an explicit
    // fix command on the event pipe) and restarts NetworkManager when this
    // session stopped it.
    radio.stop_scan();
    drop(radio);
    drop(tx);
    let _ = forwarder.join();
    0
}

// ---------------------------------------------------------------------------
// UI-side half — owns the child process.
// ---------------------------------------------------------------------------

/// Client handle for the privileged service. Lives across scan sessions:
/// "Stop capture" only sends [`Cmd::StopScan`]; the child stays up for
/// later scans and for `StopNetworkManager`. (The cracker is NOT tracked
/// here: it is a pure UI-process job — see [`crate::attack`].)
pub struct ServiceClient {
    stdin: Arc<Mutex<ChildStdin>>,
    reader: Option<JoinHandle<()>>,
    child: Child,
}

/// Child argv: same binary, hidden worker flag. Root → spawn directly;
/// non-root → wrap in pkexec (polkit prompt appears once per session).
fn spawn_service_child() -> Result<Child> {
    let exe = std::env::current_exe().context("resolving current_exe for service spawn")?;
    if iface::is_root() {
        Command::new(exe)
            .arg("--privileged-worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("spawning privileged service")
    } else {
        if !iface::pkexec_available() {
            bail!("pkexec not available — cannot elevate the privileged service");
        }
        Command::new("pkexec")
            .arg(exe)
            .arg("--privileged-worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("spawning pkexec — polkit not installed or no agent running")
    }
}

impl ServiceClient {
    /// Spawn the privileged service and start the channel-hopping scanner
    /// on `ifname`. All service events land on `tx`. A pkexec refusal /
    /// missing READY / immediate child death surfaces as `Err` (never a
    /// panic); later events flow asynchronously.
    pub fn start(ifname: &str, tx: Sender<Event>) -> Result<Self> {
        let mut child = spawn_service_child()?;
        let stdin = child
            .stdin
            .take()
            .context("service child stdin not piped")?;
        let stdout = child
            .stdout
            .take()
            .context("service child stdout not piped")?;

        let (ready_tx, ready_rx) = crossbeam_channel::bounded::<Result<()>>(1);
        let reader = std::thread::Builder::new()
            .name("wifilab-svc-reader".into())
            .spawn(move || {
                let mut lines = BufReader::new(stdout).lines();
                let mut ready = false;
                let deadline = Instant::now() + READY_TIMEOUT;
                // READY phase: prefix-match so pkexec chatter on stdout
                // can't trip us; hard cap at READY_TIMEOUT.
                while Instant::now() < deadline {
                    match lines.next() {
                        Some(Ok(line)) if !ready => {
                            if line.starts_with(READY_LINE) {
                                ready = true;
                                let _ = ready_tx.try_send(Ok(()));
                                break;
                            }
                            // Pre-ready garbage (pkexec notes etc.): ignore.
                        }
                        Some(Ok(_)) => break,
                        Some(Err(e)) => {
                            let _ = ready_tx.try_send(Err(anyhow::anyhow!(
                                "service stdout read failed: {e}"
                            )));
                            return;
                        }
                        None => {
                            let _ = ready_tx.try_send(Err(anyhow::anyhow!(
                                "service exited before READY (polkit dismissed or spawn failed)"
                            )));
                            return;
                        }
                    }
                }
                if !ready {
                    let _ = ready_tx.try_send(Err(anyhow::anyhow!(
                        "service READY banner not seen within {} s",
                        READY_TIMEOUT.as_secs()
                    )));
                    return;
                }
                // Event phase: one JSON event per stdout line, until EOF.
                for line in lines {
                    let line = match line {
                        Ok(l) => l,
                        Err(e) => {
                            send(&tx, Event::Error(format!("service stdout read failed: {e}")));
                            break;
                        }
                    };
                    if line.trim().is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<Event>(&line) {
                        Ok(ev) => send(&tx, ev),
                        Err(e) => send(
                            &tx,
                            Event::Error(format!(
                                "service: bad event line ({}): {e}",
                                &line[..line.len().min(80)]
                            )),
                        ),
                    }
                }
                // EOF: child died. UI uses this pair to un-flip flags.
                send(&tx, Event::Log("service exited".to_string()));
                send(&tx, Event::Error("service terminated".to_string()));
            })
            .context("spawning service reader thread")?;

        // Wait for READY here (bounded), so spawn/config failures surface
        // synchronously instead of as a late async surprise.
        match ready_rx.recv_timeout(READY_TIMEOUT) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(e);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                bail!("service READY banner wait timed out");
            }
        }

        let client = ServiceClient {
            stdin: Arc::new(Mutex::new(stdin)),
            reader: Some(reader),
            child,
        };
        client.cmd(&Cmd::StartScan {
            ifname: ifname.to_string(),
            channels: None,
            spool: None,
            fresh_spool: false,
        });
        Ok(client)
    }

    /// Ship one command line to the service. BrokenPipe (service already
    /// dead) is ignored — the reader thread reported the death.
    pub fn cmd(&self, c: &Cmd) {
        let Ok(line) = serde_json::to_string(c) else {
            return;
        };
        let mut guard = self.stdin.lock().expect("service stdin poisoned");
        let _ = guard.write_all(line.as_bytes());
        let _ = guard.write_all(b"\n");
        let _ = guard.flush();
    }

    /// Stop the scan session (scanner + attack workers) but KEEP the
    /// service alive for later scans and for `StopNetworkManager`.
    pub fn stop_scan(&self) {
        self.cmd(&Cmd::StopScan);
    }

    /// Tear down: tell the service to stop everything + exit, give it a
    /// grace period, then kill and reap. The UI-side crack job is stopped
    /// separately by the owner of its stop flag (AppRoot).
    pub fn shutdown(mut self) {
        self.cmd(&Cmd::Shutdown);
        // 2 s grace for the service to restore managed mode + exit.
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(25));
                }
                Ok(None) => {
                    let _ = self.child.kill();
                    break;
                }
                Err(_) => break,
            }
        }
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

impl Drop for ServiceClient {
    /// Panic-safe mirror of [`ServiceClient::shutdown`]: the service gets
    /// a chance to restore the interface even if the UI dies.
    fn drop(&mut self) {
        self.cmd(&Cmd::Shutdown);
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(25));
                }
                Ok(None) => {
                    let _ = self.child.kill();
                    break;
                }
                Err(_) => break,
            }
        }
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}
