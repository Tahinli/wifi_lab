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
//!   is the whole point). Attack workers open their OWN [`RawSocket`] on
//!   the monitor interface and set the channel themselves; concurrent
//!   attacks should therefore target the SAME channel — this matches the
//!   UI, which implies a single target.
//! - `to_monitor` may create a `<orig>mon` vif; the actual monitor ifname
//!   is remembered and passed to [`iface::to_managed`] on stop/shutdown
//!   (it deletes the vif or flips the interface back, as appropriate).

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use crossbeam_channel::Sender;

use crate::common::{Cmd, Event, MacAddr};
use crate::crypto::CrackTarget;
use crate::gpu::{self, GpuCracker};
use crate::rawsock::RawSocket;
use crate::{deauth, handshake, iface, pmkid, scanner, wordlist};

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
}

impl RadioService {
    fn new(tx: Sender<Event>) -> Self {
        RadioService {
            stop: Arc::new(AtomicBool::new(false)),
            handles: Mutex::new(Vec::new()),
            mon_ifname: None,
            orig_ifname: None,
            tx,
        }
    }

    fn mon(&self) -> Option<String> {
        self.mon_ifname
            .clone()
            .or_else(|| self.orig_ifname.clone())
    }

    /// Switch `ifname` to monitor mode and start the channel-hopping
    /// scanner (full 2.4 + 5 GHz hop list). On any failure an
    /// [`Event::Error`] is emitted, the interface is put back into managed
    /// mode (best effort). A previous scan session must be stopped first
    /// (or have failed); the stop flag is always fresh here.
    fn start_scan(&mut self, ifname: &str, channels: &[u8]) {
        self.stop = Arc::new(AtomicBool::new(false));
        self.mon_ifname = None;
        self.orig_ifname = Some(ifname.to_string());

        let mon_ifname = match iface::to_monitor(ifname) {
            Ok(name) => name,
            Err(e) => {
                log_err(&self.tx, format!("monitor mode on {ifname} failed: {e:#}"));
                // Best effort: leave the box the way we found it.
                let _ = iface::to_managed(ifname);
                self.orig_ifname = None;
                return;
            }
        };
        self.mon_ifname = Some(mon_ifname.clone());
        log(&self.tx, format!("monitor mode up on {mon_ifname} (was {ifname})"));

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
                if let Some(mon) = self.mon_ifname.take() {
                    let _ = iface::to_managed(&mon);
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
        if let Some(mon) = self.mon_ifname.take() {
            if let Err(e) = iface::to_managed(&mon) {
                eprintln!("wifilab-svc: to_managed({mon}) failed: {e:#}");
            }
        }
        self.orig_ifname = None;
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
    /// tunes it to `channel`, then blasts `count` deauth rounds at
    /// `target` (broadcast allowed). Emits DeauthSent progress (via
    /// [`deauth::blast`]) and a final summary log.
    fn deauth(&self, ap: MacAddr, target: MacAddr, channel: u8, count: u32) {
        let Some(mon) = self.mon() else {
            log_err(&self.tx, "deauth: no scan session — StartScan first");
            return;
        };
        self.spawn("wifilab-deauth", "deauth", move |tx| {
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

    /// 4-way capture worker: tune the monitor interface to `channel`, open
    /// a raw socket, and run [`handshake::capture_loop`] (stop flag
    /// checked every 250 ms frame poll). [`Event::HandshakeComplete`] is
    /// emitted from inside the loop when a crackable pair completes.
    fn capture_hs(&self, ap: MacAddr, channel: u8, essid: String) {
        let Some(mon) = self.mon() else {
            log_err(&self.tx, "handshake: no scan session — StartScan first");
            return;
        };
        let stop = self.stop.clone();
        self.spawn("wifilab-capture", "handshake", move |tx| {
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

    fn stop_networkmanager(&self) {
        match iface::stop_networkmanager() {
            Ok(()) => log(&self.tx, "nm: stopped"),
            Err(e) => log(&self.tx, format!("nm: stop failed: {e:#}")),
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
            Cmd::StartScan { ifname, channels } => {
                radio.start_scan(&ifname, channels.as_deref().unwrap_or(&[]))
            }
            Cmd::StopScan => radio.stop_scan(),
            Cmd::Deauth {
                ap,
                target,
                channel,
                count,
            } => radio.deauth(ap, target, channel, count),
            Cmd::Pmkid { ap, channel, essid } => radio.pmkid(ap, channel, essid),
            Cmd::CaptureHs { ap, channel, essid } => radio.capture_hs(ap, channel, essid),
            Cmd::StopNetworkManager => radio.stop_networkmanager(),
            Cmd::Shutdown => break,
        }
    }

    // Stop everything, restore the interface, drain the event pipe so the
    // last error lines still reach the UI, and exit.
    radio.stop_scan();
    drop(radio);
    drop(tx);
    let _ = forwarder.join();
    0
}

// ---------------------------------------------------------------------------
// UI-side half — owns the child process and the crack thread.
// ---------------------------------------------------------------------------

/// Client handle for the privileged service. Lives across scan sessions:
/// "Stop capture" only sends [`Cmd::StopScan`]; the child stays up for
/// later scans and for `StopNetworkManager`. The GPU cracker runs as a
/// plain thread in the UI process (no privilege needed) and is tracked
/// here for its stop flag only.
pub struct ServiceClient {
    stdin: Arc<Mutex<ChildStdin>>,
    reader: Option<JoinHandle<()>>,
    child: Child,
    /// Stop flag of the currently running crack job (if any). Radio
    /// workers live in the service; this is a pure UI-process thread.
    pub crack_stop: Mutex<Option<Arc<AtomicBool>>>,
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
            crack_stop: Mutex::new(None),
        };
        client.cmd(&Cmd::StartScan {
            ifname: ifname.to_string(),
            channels: None,
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

    /// Ask the running crack job (if any) to stop. UI-side flag only —
    /// the service is not involved in cracking.
    pub fn request_crack_stop(&self) {
        if let Some(flag) = &*self.crack_stop.lock().expect("crack_stop poisoned") {
            flag.store(true, Ordering::Relaxed);
        }
    }

    /// Crack worker: stream `wordlist` through the GPU cracker (CPU
    /// fallback when no adapter) against `target` — as a plain thread in
    /// the UI process (GPU + wordlist need no root). Emits CrackProgress,
    /// then exactly one terminator: CrackFound + CrackStopped{found:true}
    /// on success, CrackStopped{found:false} on stop or wordlist
    /// exhaustion.
    pub fn spawn_crack(
        &self,
        target_desc: String,
        target: CrackTarget,
        wordlist: PathBuf,
        tx: Sender<Event>,
    ) {
        let stop = Arc::new(AtomicBool::new(false));
        *self.crack_stop.lock().expect("crack_stop poisoned") = Some(stop.clone());
        let err_tx = tx.clone();
        let result = std::thread::Builder::new()
            .name("wifilab-crack".into())
            .spawn(move || {
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
                            format!(
                                "cracker: GPU backend: {} — cracking {target_desc}",
                                g.device_name()
                            ),
                        );
                        g.crack(&target, &mut words, &mut progress, &stop)
                    }
                    None => {
                        log(
                            &tx,
                            format!(
                                "cracker: no GPU adapter, CPU fallback — cracking {target_desc}"
                            ),
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
        if let Err(e) = result {
            send(&err_tx, Event::Error(format!("cracker: spawn failed: {e}")));
            send(&err_tx, Event::CrackStopped { found: false });
        }
    }

    /// Tear down: tell the service to stop everything + exit, give it a
    /// grace period, then kill and reap. Also stops any UI-side crack job
    /// and joins the reader thread.
    pub fn shutdown(mut self) {
        self.request_crack_stop();
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
        self.request_crack_stop();
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
