//! Cracker page: target dropdown (fed by captures), attack-mode select
//! (wordlist / bruteforce / rainbow PMK table) with per-mode inputs,
//! backend label, Start/Stop, live throughput/progress, rainbow-table
//! build controls, recent-activity log, found-password banner.
//!
//! Cracking is a plain UI-process job ([`crate::attack`]): it does NOT
//! need the privileged radio service and is completely independent of
//! capture state — a run may be started while a capture is live.
//! In mock mode Start runs a deterministic simulation on a gpui
//! background task instead (same event sequence; the attack mode is
//! ignored there).

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::Duration;

use gpui::{
    Context, Entity, InteractiveElement, IntoElement, ParentElement, StatefulInteractiveElement,
    Styled, Window, div, prelude::FluentBuilder, px,
};
use gpuikit::elements::button::button;
use gpuikit::elements::loading_indicator::loading_indicator;
use gpuikit::elements::progress::progress;
use gpuikit::elements::text_field::text_field;
use gpuikit::elements::typography::{h3, small, text};
use gpuikit::layout::{h_stack, v_stack};
use gpuikit::theme::{ActiveTheme, Themeable};

use crate::attack::Attack;
use crate::common::Event;
use crate::ui::app::AppRoot;

/// Mock run length: this many "candidates" before the password turns up.
const WORDLIST_TOTAL: u64 = 1_000_000;
/// Mock GPU throughput (guesses/second).
const MOCK_HPS: f64 = 1_250_000.0;
const MOCK_PASSWORD: &str = "parafin2024!";
/// Label for the backend column: real runs detect GPU-vs-CPU inside the
/// worker and log it ("cracker: GPU backend: … / CPU fallback").
const fn backend_label(is_mock: bool) -> &'static str {
    if is_mock {
        "GPU (wgpu) · mock"
    } else {
        "GPU (wgpu) → CPU"
    }
}

fn fmt_hps(hps: f64) -> String {
    if hps >= 1.0e6 {
        format!("{:.2} MH/s", hps / 1.0e6)
    } else if hps >= 1.0e3 {
        format!("{:.1} kH/s", hps / 1.0e3)
    } else {
        format!("{hps:.0} H/s")
    }
}

/// Human duration for worst-case ETAs ("3d 4h", "2h 05m", "3m 12s", "12s").
fn fmt_dur(secs: f64) -> String {
    if !secs.is_finite() || secs < 1.0 {
        return "<1s".to_string();
    }
    let s = secs.round() as u64;
    let (d, h, m, sec) = (s / 86400, s / 3600 % 24, s / 60 % 60, s % 60);
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m:02}m")
    } else if m > 0 {
        format!("{m}m {sec:02}s")
    } else {
        format!("{sec}s")
    }
}

/// Worst-case remaining time: every not-yet-tried candidate at the
/// current rate. Empty when the total or the rate is unknown.
fn fmt_worst_case(done: u64, hps: f64, total: Option<u64>) -> Option<String> {
    let t = total?;
    if hps <= 0.0 || done >= t {
        return None;
    }
    Some(format!("worst case left: ~{}", fmt_dur((t - done) as f64 / hps)))
}

/// Build the [`Attack`] selected by `app.attack_mode` from the page's
/// input fields. Returns `None` (after logging the reason) when an input
/// is empty or fails to parse.
fn selected_attack(app: &mut AppRoot, cx: &mut gpui::App) -> Option<Attack> {
    match app.attack_mode.as_str() {
        "bruteforce" => {
            let custom = app
                .charset_input
                .read(cx)
                .content()
                .trim_end_matches(['\r', '\n'])
                .as_bytes()
                .to_vec();
            // Union of the checked preset chips + the custom field.
            let charset = crate::attack::charset::compose(
                app.cs_lower,
                app.cs_upper,
                app.cs_digits,
                app.cs_special,
                &custom,
            );
            if charset.is_empty() {
                app.state.push_log(
                    "cracker: empty charset — pick a preset chip or type custom chars",
                );
                return None;
            }
            let min_s = app.len_min_input.read(cx).content().trim().to_string();
            let max_s = app.len_max_input.read(cx).content().trim().to_string();
            let min = match min_s.parse::<usize>() {
                Ok(v) => v,
                Err(_) => {
                    app.state.push_log(format!("cracker: bad min length '{min_s}'"));
                    return None;
                }
            };
            let max = match max_s.parse::<usize>() {
                Ok(v) => v,
                Err(_) => {
                    app.state.push_log(format!("cracker: bad max length '{max_s}'"));
                    return None;
                }
            };
            Some(Attack::Bruteforce { charset, min, max, freq_order: app.freq_order })
        }
        "rules" => {
            let wl = app.wordlist_input.read(cx).content().trim().to_string();
            if wl.is_empty() {
                app.state.push_log("cracker: wordlist path is empty");
                return None;
            }
            let rules = app.rules_input.read(cx).content().trim().to_string();
            if rules.is_empty() {
                app.state.push_log("cracker: rules path is empty");
                return None;
            }
            Some(Attack::Rules {
                wordlist: PathBuf::from(wl),
                rules: PathBuf::from(rules),
            })
        }
        "hybrid" => {
            let wl = app.wordlist_input.read(cx).content().trim().to_string();
            if wl.is_empty() {
                app.state.push_log("cracker: wordlist path is empty");
                return None;
            }
            let custom = app
                .charset_input
                .read(cx)
                .content()
                .trim_end_matches(['\r', '\n'])
                .as_bytes()
                .to_vec();
            let charset = crate::attack::charset::compose(
                app.cs_lower,
                app.cs_upper,
                app.cs_digits,
                app.cs_special,
                &custom,
            );
            if charset.is_empty() {
                app.state.push_log(
                    "cracker: empty charset — pick a preset chip or type custom chars",
                );
                return None;
            }
            let min_s = app.hyb_min_input.read(cx).content().trim().to_string();
            let max_s = app.hyb_max_input.read(cx).content().trim().to_string();
            let min = match min_s.parse::<usize>() {
                Ok(v) => v.clamp(1, 4),
                Err(_) => {
                    app.state.push_log(format!("cracker: bad hybrid min '{min_s}'"));
                    return None;
                }
            };
            let max = match max_s.parse::<usize>() {
                Ok(v) => v.clamp(1, 4),
                Err(_) => {
                    app.state.push_log(format!("cracker: bad hybrid max '{max_s}'"));
                    return None;
                }
            };
            if min > max {
                app.state
                    .push_log(format!("cracker: hybrid min {min} > max {max}"));
                return None;
            }
            Some(Attack::Hybrid {
                wordlist: PathBuf::from(wl),
                charset,
                min,
                max,
            })
        }
        "rainbow" => {
            let path = app.rainbow_input.read(cx).content().trim().to_string();
            if path.is_empty() {
                app.state.push_log("cracker: PMK table path is empty");
                return None;
            }
            Some(Attack::Rainbow(PathBuf::from(path)))
        }
        _ => {
            let path = app.wordlist_input.read(cx).content().trim().to_string();
            if path.is_empty() {
                app.state.push_log("cracker: wordlist path is empty");
                return None;
            }
            Some(Attack::Wordlist(PathBuf::from(path)))
        }
    }
}

/// Start a crack run on the selected capture.
///
/// Real mode: builds the selected [`Attack`], validates it (files
/// opened, charset/lengths checked) BEFORE any flag is set, then hands
/// the stored [`crate::crypto::CrackTarget`] (no hc22000 re-parse) to
/// `crate::attack::spawn_crack`; progress and termination arrive as
/// CrackProgress/CrackFound/CrackStopped events and land in state via
/// `AppState::apply`. No radio or service involvement.
/// Mock mode: a deterministic generator drives the SAME event sequence.
fn start(view: &Entity<AppRoot>, _window: &mut Window, cx: &mut gpui::App) {
    view.update(cx, |app, cx| {
        if app.crack_inflight || app.state.cracker.running || app.bench_running {
            return;
        }
        let Some(desc) = app.state.cracker.target.clone() else {
            app.state.push_log("cracker: no target selected");
            cx.notify();
            return;
        };

        // Validate everything that can fail BEFORE marking the run active,
        // so a refused start never leaves stale flags behind.
        let real = if !app.is_mock {
            let Some(attack) = selected_attack(app, cx) else {
                cx.notify();
                return;
            };
            if let Err(e) = attack.validate() {
                app.state.push_log(format!("ERROR: cracker: {e:#}"));
                cx.notify();
                return;
            }
            let Some(idx) = app.state.capture_descs().iter().position(|d| *d == desc) else {
                app.state.push_log("ERROR: cracker: capture no longer exists");
                cx.notify();
                return;
            };
            match app.state.crack_target_at(idx) {
                Some(t) => Some((t, attack)),
                None => {
                    app.state.push_log("ERROR: cracker: capture no longer exists");
                    cx.notify();
                    return;
                }
            }
        } else {
            None
        };

        app.crack_epoch += 1; // invalidate any stale mock generator ticks
        let wordlist = app.wordlist_input.read(cx).content().trim().to_string();
        let cr = &mut app.state.cracker;
        cr.wordlist = Some(wordlist.clone());
        cr.found = None;
        cr.tried = 0;
        cr.hps = 0.0;
        cr.total = None;
        // A fresh foreground start supersedes any saved resume position.
        cr.resume = None;
        cr.running = true;
        app.crack_inflight = true;
        // Fresh run: the throughput curve belongs to it, not the last run.
        app.state.hps_hist.clear();
        cx.notify();

        if !app.is_mock {
            let Some((target, attack)) = real else { return };
            app.state.push_log(format!(
                "cracker: starting on {desc} — {}",
                attack.describe()
            ));
            // Remember the wordlist path in the MRU list (wordlist-family
            // attacks only) so it shows up as a one-click chip later.
            let wl_path: Option<String> = match &attack {
                Attack::Wordlist(p) => Some(p.display().to_string()),
                Attack::Rules { wordlist, .. } | Attack::Hybrid { wordlist, .. } => {
                    Some(wordlist.display().to_string())
                }
                _ => None,
            };
            if let Some(wl_path) = wl_path {
                crate::store::remember_wordlist(&mut app.profiles, &wl_path);
                if let Err(e) = crate::store::save_profiles(&app.profiles) {
                    app.state.push_log(format!("profiles: save FAILED: {e:#}"));
                }
            }
            // Track the live attack for the resume session file
            // (throttle-saved on progress, finalized on stop).
            app.state.cracker.active_attack = Some(attack.clone());
            cx.notify();
            app.crack_stop = Some(crate::attack::spawn_crack(
                target.describe(),
                target,
                attack,
                0,
                app.tx.clone(),
                false,
            ));
            return;
        }

        // ---- mock path: same events, fabricated numbers ----
        app.state.push_log(format!(
            "cracker: {desc} via {wordlist} [mock run]"
        ));
        cx.notify();
        let tx = app.tx.clone();
        let epoch = app.crack_epoch;
        cx.spawn(async move |this, cx| {
            let mut done = 0u64;
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(100))
                    .await;
                let live = this
                    .update(cx, |app, _cx| {
                        app.crack_epoch == epoch && app.state.cracker.running
                    })
                    .unwrap_or(false);
                if !live {
                    break;
                }
                done += (MOCK_HPS / 10.0) as u64 + done / 977 % 8_000;
                let hps = MOCK_HPS * (0.92 + (done / 331 % 15) as f64 / 100.0);
                let _ = tx.send(Event::CrackProgress {
                    done,
                    hps,
                    total: Some(WORDLIST_TOTAL),
                });
                if done >= WORDLIST_TOTAL {
                    let _ = tx.send(Event::CrackFound {
                        password: MOCK_PASSWORD.to_string(),
                    });
                    let _ = tx.send(Event::CrackStopped { found: true });
                    break;
                }
            }
        })
        .detach();
    });
}

/// Stop the active run.
///
/// Real mode flips the crack job's stop flag (the worker breaks at the
/// next batch and emits CrackStopped{found:false}, which settles the UI
/// and clears `app.crack_stop`). Mock mode just invalidates the
/// generator epoch — no terminator event will arrive, so the running
/// flags are cleared here.
fn stop(view: &Entity<AppRoot>, _window: &mut Window, cx: &mut gpui::App) {
    view.update(cx, |app, cx| {
        let active = app.crack_inflight || app.state.cracker.running;
        if !active {
            return;
        }
        app.crack_epoch += 1;
        if app.is_mock {
            app.state.cracker.running = false;
            app.crack_inflight = false;
            app.state.cracker.hps = 0.0;
            app.state.push_log("cracker: stopped by user");
            cx.notify();
            return;
        }
        if let Some(flag) = &app.crack_stop {
            flag.store(true, Ordering::Relaxed);
            app.state.push_log("cracker: stop requested");
        }
        cx.notify();
    });
}

/// Start a rainbow PMK-table build for the selected capture's SSID.
///
/// Validates both paths (wordlist must open, table path must be given)
/// BEFORE marking the build active; progress arrives as
/// RainbowProgress, termination as RainbowBuilt — the latter settles
/// `rainbow_building` and `app.rainbow_stop`.
fn build(view: &Entity<AppRoot>, _window: &mut Window, cx: &mut gpui::App) {
    view.update(cx, |app, cx| {
        if app.state.cracker.rainbow_building
            || app.crack_inflight
            || app.state.cracker.running
            || app.bench_running
        {
            return;
        }
        let Some(desc) = app.state.cracker.target.clone() else {
            app.state.push_log("rainbow: no target selected");
            cx.notify();
            return;
        };
        let Some(idx) = app.state.capture_descs().iter().position(|d| *d == desc) else {
            app.state.push_log("ERROR: rainbow: capture no longer exists");
            cx.notify();
            return;
        };
        let Some(target) = app.state.crack_target_at(idx) else {
            app.state.push_log("ERROR: rainbow: capture no longer exists");
            cx.notify();
            return;
        };
        let ssid = target.essid().to_string();

        let wl = app.wordlist_input.read(cx).content().trim().to_string();
        if wl.is_empty() {
            app.state.push_log("rainbow: wordlist path is empty");
            cx.notify();
            return;
        }
        if let Err(e) = std::fs::File::open(&wl) {
            app.state
                .push_log(format!("ERROR: rainbow: cannot open wordlist {wl}: {e}"));
            cx.notify();
            return;
        }
        let out = app.rainbow_input.read(cx).content().trim().to_string();
        if out.is_empty() {
            app.state.push_log("rainbow: PMK table path is empty");
            cx.notify();
            return;
        }

        app.state.cracker.rainbow_building = true;
        app.state.cracker.rainbow_done = 0;
        app.state.cracker.rainbow_hps = 0.0;
        app.state.cracker.rainbow_total = None;
        app.state.push_log(format!(
            "rainbow: building table {out} for ssid \"{ssid}\" from {wl}"
        ));
        cx.notify();
        app.rainbow_stop = Some(crate::attack::spawn_rainbow_build(
            ssid,
            PathBuf::from(wl),
            PathBuf::from(out),
            app.tx.clone(),
        ));
    });
}

/// Stop the running rainbow-table build: flip the job's stop flag; the
/// terminating RainbowBuilt event settles the UI.
fn build_stop(view: &Entity<AppRoot>, _window: &mut Window, cx: &mut gpui::App) {
    view.update(cx, |app, cx| {
        if let Some(flag) = &app.rainbow_stop {
            flag.store(true, Ordering::Relaxed);
            app.state.push_log("rainbow: stop requested");
            cx.notify();
        }
    });
}

/// Resume the saved run shown in the banner: same capture, same attack,
/// continuing at the saved candidate offset.
fn resume_saved(view: &Entity<AppRoot>, _window: &mut Window, cx: &mut gpui::App) {
    view.update(cx, |app, cx| {
        if app.crack_inflight
            || app.state.cracker.running
            || app.state.cracker.rainbow_building
            || app.bench_running
        {
            return;
        }
        let Some(r) = app.state.cracker.resume.clone() else {
            return;
        };
        // Files may have vanished since the run was saved — refuse with a
        // visible reason, keep the session file + banner untouched.
        if let Err(e) = r.attack.validate() {
            app.state
                .push_log(format!("ERROR: cracker: saved run no longer valid: {e:#}"));
            cx.notify();
            return;
        }
        let Some(idx) = app
            .state
            .capture_descs()
            .iter()
            .position(|d| *d == r.target_desc)
        else {
            app.state
                .push_log("ERROR: cracker: saved run's capture no longer exists");
            cx.notify();
            return;
        };
        let Some(target) = app.state.crack_target_at(idx) else {
            app.state
                .push_log("ERROR: cracker: saved run's capture no longer exists");
            cx.notify();
            return;
        };

        app.crack_epoch += 1;
        let cr = &mut app.state.cracker;
        cr.found = None;
        cr.tried = r.done;
        cr.hps = 0.0;
        cr.total = r.total;
        cr.active_attack = Some(r.attack.clone());
        cr.resume = None;
        cr.running = true;
        app.crack_inflight = true;
        app.state.hps_hist.clear();
        // The new run's throttle-saves supersede the old session file;
        // clear eagerly so a crash cannot doubly arm the banner.
        if let Err(e) = crate::store::clear_session() {
            app.state
                .push_log(format!("cracker: session clear failed: {e:#}"));
        }
        app.state.push_log(format!(
            "cracker: resuming saved run — {} at {}{}",
            r.attack.describe(),
            r.done,
            r.total.map(|t| format!("/{t}")).unwrap_or_default()
        ));
        cx.notify();
        app.crack_stop = Some(crate::attack::spawn_crack(
            target.describe(),
            target,
            r.attack,
            r.done,
            app.tx.clone(),
            false,
        ));
    });
}

/// Delete the saved session file and dismiss the banner.
fn discard_saved(view: &Entity<AppRoot>, _window: &mut Window, cx: &mut gpui::App) {
    view.update(cx, |app, cx| {
        if let Err(e) = crate::store::clear_session() {
            app.state
                .push_log(format!("cracker: session clear failed: {e:#}"));
        }
        app.state.cracker.resume = None;
        app.state.push_log("cracker: saved run discarded");
        cx.notify();
    });
}

/// Save the current mode + paths as a named preset in `app.profiles`
/// (name auto-derived as `{mode}:{basename(wordlist)}`; a same-name
/// preset is replaced). Persisted via [`crate::store::save_profiles`].
fn save_preset(view: &Entity<AppRoot>, _window: &mut Window, cx: &mut gpui::App) {
    view.update(cx, |app, cx| {
        let mode = app.attack_mode.clone();
        if mode == "rainbow" {
            app.state.push_log("profiles: rainbow presets are not saved");
            cx.notify();
            return;
        }
        let wordlist = app.wordlist_input.read(cx).content().trim().to_string();
        if wordlist.is_empty() {
            app.state.push_log("profiles: wordlist path is empty — nothing to save");
            cx.notify();
            return;
        }
        let rules = match mode.as_str() {
            "rules" => {
                let r = app.rules_input.read(cx).content().trim().to_string();
                if r.is_empty() {
                    app.state.push_log("profiles: rules path is empty — nothing to save");
                    cx.notify();
                    return;
                }
                Some(r)
            }
            _ => None,
        };
        let base = std::path::Path::new(&wordlist)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| wordlist.clone());
        let name = format!("{mode}:{base}");
        let profile = crate::store::CrackProfile {
            name: name.clone(),
            mode,
            wordlist,
            rules,
        };
        app.profiles.profiles.retain(|p| p.name != name);
        app.profiles.profiles.push(profile);
        match crate::store::save_profiles(&app.profiles) {
            Ok(()) => app.state.push_log(format!("profiles: saved preset {name}")),
            Err(e) => app.state.push_log(format!("profiles: save FAILED: {e:#}")),
        }
        cx.notify();
    });
}

/// Apply a saved preset: switch the attack mode and prefill the
/// wordlist/rules input fields.
fn apply_preset(profile: crate::store::CrackProfile, view: &Entity<AppRoot>, cx: &mut gpui::App) {
    view.update(cx, |app, cx| {
        app.attack_mode = profile.mode.clone();
        app.attack_select.update(cx, |sel, cx| {
            sel.set_selected(Some(profile.mode.clone()), cx);
        });
        let wl = profile.wordlist.clone();
        app.wordlist_input.update(cx, |input, cx| {
            input.set_content(wl, cx);
        });
        if let Some(rules) = &profile.rules {
            let r = rules.clone();
            app.rules_input.update(cx, |input, cx| {
                input.set_content(r, cx);
            });
        }
        app.state
            .push_log(format!("profiles: applied preset {}", profile.name));
        cx.notify();
    });
}

/// Import captures from .cap/.pcap files (via [`crate::pcapin::extract`])
/// or .hc22000 text files (via [`crate::crypto::parse_hc22000`]). Each
/// extracted capture arrives as a CaptureImported event; the heavy parse
/// runs on a worker thread streaming events like the crack threads do.
/// `import_busy` is cleared at the very end, after all chosen files.
fn import_captures(view: &Entity<AppRoot>, _window: &mut Window, cx: &mut gpui::App) {
    let prompt = cx.prompt_for_paths(gpui::PathPromptOptions {
        files: true,
        directories: false,
        multiple: true,
        prompt: None,
    });
    view.update(cx, |app, cx| {
        app.import_busy = true;
        cx.notify();
    });
    let weak = view.downgrade();
    cx.spawn(async move |cx| {
        // oneshot recv err OR platform dialog err OR explicit cancel all
        // land here as "no file chosen".
        let picked: Option<Vec<PathBuf>> = match prompt.await {
            Ok(Ok(paths)) => paths,
            _ => None,
        };
        let Some(paths) = picked else {
            let _ = weak.update(cx, |app, cx| {
                app.import_busy = false;
                app.state.push_log("import: no file chosen");
                cx.notify();
            });
            return;
        };
        // Heavy parsing (multi-GB pcaps) must not block the UI executor:
        // stream results from a plain thread like the crack workers do.
        let tx = match weak.update(cx, |app, _cx| app.tx.clone()) {
            Ok(tx) => tx,
            Err(_) => return, // view gone — nothing to report to
        };
        // At the very end (after all files) the worker signals completion
        // on this channel; the gpui continuation below clears import_busy
        // (a bare std thread cannot touch gpui state).
        let (done_tx, done_rx) = crossbeam_channel::bounded::<()>(1);
        std::thread::Builder::new()
            .name("wifilab-import".into())
            .spawn(move || {
                for path in paths {
                    let disp = path.display().to_string();
                    let is_hc22000 = disp.contains("22000")
                        || std::fs::read_to_string(&path)
                            .map(|s| {
                                s.lines()
                                    .take(8)
                                    .any(|l| l.starts_with("WPA*01") || l.starts_with("WPA*02"))
                            })
                            .unwrap_or(false);
                    if is_hc22000 {
                        match std::fs::read_to_string(&path) {
                            Ok(text) => {
                                let mut n = 0usize;
                                let mut m = 0usize;
                                for line in text.lines() {
                                    let line = line.trim();
                                    if line.is_empty() {
                                        continue;
                                    }
                                    let bare = line.strip_prefix("WPA*").unwrap_or(line);
                                    match crate::crypto::parse_hc22000(bare) {
                                        Ok(crate::crypto::CrackTarget::Handshake(h)) => {
                                            let _ = tx.send(Event::CaptureImported(
                                                crate::common::ImportedCapture::Handshake(
                                                    Box::new(h),
                                                ),
                                            ));
                                            n += 1;
                                        }
                                        Ok(crate::crypto::CrackTarget::Pmkid(p)) => {
                                            let _ = tx.send(Event::CaptureImported(
                                                crate::common::ImportedCapture::Pmkid(p),
                                            ));
                                            n += 1;
                                        }
                                        Err(_) => m += 1,
                                    }
                                }
                                let _ = tx.send(Event::Log(format!(
                                    "import: {disp}: {n} captures ({m} skipped)"
                                )));
                            }
                            Err(e) => {
                                let _ = tx.send(Event::Error(format!("import: {disp}: {e}")));
                            }
                        }
                    } else {
                        match crate::pcapin::extract(&path) {
                            Ok(caps) => {
                                let n = caps.len();
                                for cap in caps {
                                    let _ = tx.send(Event::CaptureImported(cap));
                                }
                                let _ = tx.send(Event::Log(format!(
                                    "import: {disp}: {n} captures (0 skipped)"
                                )));
                            }
                            Err(e) => {
                                let _ = tx.send(Event::Error(format!("import: {disp}: {e:#}")));
                            }
                        }
                    }
                }
                let _ = done_tx.send(());
            })
            .expect("spawn import thread");
        // Wait for completion on the background executor, then clear the
        // busy flag on the gpui side.
        let bg = cx.background_executor().clone();
        bg.spawn(async move {
            let _ = done_rx.recv();
        })
        .await;
        let _ = weak.update(cx, |app, cx| {
            app.import_busy = false;
            cx.notify();
        });
    })
    .detach();
}

/// Run a 3 s H/s benchmark (GPU if available, CPU always). Results
/// arrive as one BenchmarkDone event; `bench_running` is cleared on the
/// app drain side. Mock mode fabricates a fixed result after ~1.5 s.
fn benchmark(view: &Entity<AppRoot>, _window: &mut Window, cx: &mut gpui::App) {
    view.update(cx, |app, cx| {
        if app.bench_running
            || app.crack_inflight
            || app.state.cracker.running
            || app.state.cracker.rainbow_building
        {
            return;
        }
        app.bench_running = true;
        app.state.push_log("benchmark: measuring crack speed (3s)…");
        cx.notify();
        if !app.is_mock {
            // The worker holds its own Arc; the flag is never flipped by
            // the UI, so dropping our copy is safe.
            drop(crate::attack::spawn_benchmark(3, app.tx.clone()));
            return;
        }
        // Mock: fabricate a BenchmarkDone after ~1.5 s. No epoch
        // invalidation: bench_running already blocks a concurrent second
        // click, and a crack started meanwhile does not invalidate a
        // machine-speed measurement.
        let tx = app.tx.clone();
        cx.spawn(async move |this, cx| {
            cx.background_executor()
                .timer(Duration::from_millis(1500))
                .await;
            let live = this.update(cx, |app, _cx| app.bench_running).unwrap_or(false);
            if live {
                let _ = tx.send(Event::BenchmarkDone {
                    gpu_hps: Some(MOCK_HPS),
                    cpu_hps: 310_000.0,
                });
            }
        })
        .detach();
    });
}

/// Estimate worst-case crack durations from the measured benchmark rate
/// and the current input fields; results go to the activity log as
/// "estimate:" lines (candidate-space math always, times only when a
/// benchmark has run).
fn estimate(view: &Entity<AppRoot>, _window: &mut Window, cx: &mut gpui::App) {
    view.update(cx, |app, cx| {
        let hps = match (app.state.bench_gpu, app.state.bench_cpu) {
            (Some(g), Some(c)) => Some(g.max(c)),
            (Some(g), None) => Some(g),
            (None, Some(c)) => Some(c),
            (None, None) => None,
        };
        let Some(hps) = hps.filter(|h| *h > 0.0) else {
            app.state
                .push_log("estimate: run Benchmark for times; candidate-space math only");
            cx.notify();
            return;
        };

        // (a) wordlist family: lines × rules (rules mode) at best rate.
        let wl = app.wordlist_input.read(cx).content().trim().to_string();
        let wl_space: Option<u128> = if wl.is_empty() {
            Some(WORDLIST_TOTAL as u128)
        } else {
            match crate::wordlist::line_count(std::path::Path::new(&wl)) {
                Ok(n) => Some(n as u128),
                Err(e) => {
                    app.state
                        .push_log(format!("estimate: wordlist unreadable: {e:#}"));
                    None
                }
            }
        };
        if let Some(mut space) = wl_space {
            let mut what = format!("wordlist {}", if wl.is_empty() { "(mock-size)" } else { &wl });
            if app.attack_mode == "rules" {
                let rp = app.rules_input.read(cx).content().trim().to_string();
                match crate::attack::rule_count(std::path::Path::new(&rp)) {
                    Ok(r) if r > 0 => {
                        space = space.saturating_mul(r as u128);
                        what = format!("{what} × {r} rules");
                    }
                    Ok(_) => {}
                    Err(e) => {
                        app.state
                            .push_log(format!("estimate: rules unreadable: {e:#}"));
                        space = 0;
                    }
                }
            }
            if space > 0 {
                app.state.push_log(format!(
                    "estimate: {what}: {space} candidates, worst case ~{} @ {}",
                    fmt_dur(space as f64 / hps),
                    fmt_hps(hps)
                ));
            }
        }

        // (b) bruteforce space at best rate.
        let custom = app
            .charset_input
            .read(cx)
            .content()
            .trim_end_matches(['\r', '\n'])
            .as_bytes()
            .to_vec();
        let charset = crate::attack::charset::compose(
            app.cs_lower,
            app.cs_upper,
            app.cs_digits,
            app.cs_special,
            &custom,
        );
        if charset.is_empty() {
            app.state.push_log("estimate: empty charset — bruteforce space n/a");
        } else {
            let min = app
                .len_min_input
                .read(cx)
                .content()
                .trim()
                .parse::<usize>()
                .unwrap_or(8);
            let max = app
                .len_max_input
                .read(cx)
                .content()
                .trim()
                .parse::<usize>()
                .unwrap_or(10);
            match crate::attack::BruteForce::new(charset.clone(), min, max, false) {
                Ok(bf) => {
                    let space = bf.space();
                    app.state.push_log(format!(
                        "estimate: bruteforce {min}..={max}: {space} candidates, worst case ~{} @ {}",
                        fmt_dur(space as f64 / hps),
                        fmt_hps(hps)
                    ));
                }
                Err(e) => app
                    .state
                    .push_log(format!("estimate: bruteforce range invalid: {e:#}")),
            }
        }

        // (c) entropy of the strength-input candidate against the current
        // charset union: bits ≈ len × log2(charset size).
        let candidate = app.strength_input.read(cx).content().trim().to_string();
        if !candidate.is_empty() && !charset.is_empty() {
            let csize = charset.len() as f64;
            let bits = candidate.len() as f64 * csize.log2();
            let guess_s = 2f64.powf(bits - 1.0) / hps;
            app.state.push_log(format!(
                "estimate: {} chars × log2({}) ≈ {bits:.0} bits — avg crack ~{} @ {}",
                candidate.len(),
                charset.len(),
                fmt_dur(guess_s),
                fmt_hps(hps)
            ));
        } else if candidate.is_empty() {
            app.state.push_log("estimate: type a candidate for its entropy line");
        }
        cx.notify();
    });
}

/// One bruteforce charset preset chip. Toggling flips the app flag;
/// [`crate::attack::charset::compose`] unions the active chips with the
/// custom field at Start.
fn charset_chip(
    id: &'static str,
    label: &'static str,
    active: bool,
    view: &Entity<AppRoot>,
    cx: &gpui::App,
    flag: fn(&mut AppRoot) -> &mut bool,
) -> gpui::Stateful<gpui::Div> {
    let theme = cx.theme().clone();
    let hover = theme.accent_bg();
    div()
        .id(gpui::SharedString::from(id))
        .px_2()
        .py_1()
        .rounded_md()
        .border_1()
        .border_color(theme.border())
        .cursor_pointer()
        .text_xs()
        .when(active, |el| el.bg(theme.accent_bg()))
        .when(!active, |el| el.hover(move |style| style.bg(hover)))
        .child(label)
        .on_click({
            let view = view.clone();
            move |_, _window, cx| {
                view.update(cx, |app, cx| {
                    let f = flag(app);
                    *f = !*f;
                    cx.notify();
                });
            }
        })
}

/// Throughput curve of the current run: one bar per progress sample,
/// right-aligned (newest at the right edge), height scaled to the run's
/// own maximum so a CPU-scale run doesn't render as a flat line next to
/// GPU-scale history.
fn hps_curve(
    hist: &std::collections::VecDeque<f64>,
    accent: gpui::Hsla,
) -> Option<gpui::AnyElement> {
    if hist.len() < 2 {
        return None;
    }
    const COLUMNS: usize = 40;
    const MAX_H: f32 = 14.0;
    let max = hist.iter().copied().fold(0.0f64, f64::max).max(1.0);
    let mut cols: Vec<gpui::Div> = Vec::with_capacity(COLUMNS);
    let shown: Vec<f64> = hist.iter().copied().rev().take(COLUMNS).collect();
    for _ in 0..COLUMNS.saturating_sub(shown.len()) {
        cols.push(div().w(px(6.)).h(px(1.)));
    }
    for h in shown.iter().rev() {
        let hpx = (2.0 + MAX_H * (*h as f32 / max as f32)).min(MAX_H + 2.0);
        cols.push(div().w(px(6.)).h(px(hpx)).bg(accent));
    }
    Some(h_stack().gap_1().items_end().children(cols).into_any_element())
}

pub fn render(
    app: &mut AppRoot,
    view: &Entity<AppRoot>,
    _window: &mut Window,
    cx: &mut Context<AppRoot>,
) -> gpui::Div {
    let theme = cx.theme().clone();
    let cracker = &app.state.cracker;
    let running = cracker.running || app.crack_inflight;
    let rainbow_building = cracker.rainbow_building;
    // Coverage fraction: mock is bounded by construction; real runs get
    // their worst-case total from the worker (wordlist lines, brute
    // space, table entries) when countable.
    let effective_total = if app.is_mock {
        Some(WORDLIST_TOTAL)
    } else {
        cracker.total.filter(|t| *t > 0)
    };
    let frac = effective_total
        .map(|t| (cracker.tried as f64 / t as f64).clamp(0.0, 1.0))
        .unwrap_or(0.0);
    let candidates = if let Some(t) = effective_total {
        format!("candidates: {} / {t}", cracker.tried)
    } else {
        format!("candidates: {}", cracker.tried)
    };
    // Worst-case remaining time (real runs): every untried candidate at
    // the current measured rate.
    let eta = (!app.is_mock && running)
        .then(|| fmt_worst_case(cracker.tried, cracker.hps, cracker.total))
        .flatten();

    // Per-mode inputs, swapped under the attack-mode dropdown.
    let mode_inputs: gpui::AnyElement = match app.attack_mode.as_str() {
        "bruteforce" => h_stack()
            .gap_2()
            .items_center()
            .child(charset_chip("cs-lower", "a-z", app.cs_lower, view, cx, |a| &mut a.cs_lower))
            .child(charset_chip("cs-upper", "A-Z", app.cs_upper, view, cx, |a| &mut a.cs_upper))
            .child(charset_chip("cs-digits", "0-9", app.cs_digits, view, cx, |a| &mut a.cs_digits))
            .child(charset_chip("cs-special", "!@#…", app.cs_special, view, cx, |a| &mut a.cs_special))
            .child(charset_chip("cs-freq-order", "freq-order", app.freq_order, view, cx, |a| {
                &mut a.freq_order
            }))
            .child(
                div().w(px(160.)).child(
                    text_field(&app.charset_input, cx)
                        .placeholder("custom chars")
                        .full_width(true),
                ),
            )
            .child(
                div().w(px(64.)).child(
                    text_field(&app.len_min_input, cx)
                        .placeholder("min")
                        .full_width(true),
                ),
            )
            .child(
                div().w(px(64.)).child(
                    text_field(&app.len_max_input, cx)
                        .placeholder("max")
                        .full_width(true),
                ),
            )
            .child(small("chips + custom · min..max len · freq-order: common characters first").muted())
            .into_any_element(),
        "rules" => h_stack()
            .gap_2()
            .items_end()
            .child(
                div().w(px(320.)).child(
                    text_field(&app.wordlist_input, cx)
                        .placeholder("/path/to/wordlist")
                        .full_width(true),
                ),
            )
            .child(
                div().w(px(320.)).child(
                    text_field(&app.rules_input, cx)
                        .placeholder("/path/to/rules (hashcat-subset)")
                        .full_width(true),
                ),
            )
            .child(small("word × mutation rules").muted())
            .into_any_element(),
        "hybrid" => h_stack()
            .gap_2()
            .items_center()
            .child(
                div().w(px(280.)).child(
                    text_field(&app.wordlist_input, cx)
                        .placeholder("/path/to/wordlist")
                        .full_width(true),
                ),
            )
            .child(charset_chip("cs-lower", "a-z", app.cs_lower, view, cx, |a| &mut a.cs_lower))
            .child(charset_chip("cs-upper", "A-Z", app.cs_upper, view, cx, |a| &mut a.cs_upper))
            .child(charset_chip("cs-digits", "0-9", app.cs_digits, view, cx, |a| &mut a.cs_digits))
            .child(charset_chip("cs-special", "!@#…", app.cs_special, view, cx, |a| &mut a.cs_special))
            .child(
                div().w(px(120.)).child(
                    text_field(&app.charset_input, cx)
                        .placeholder("custom chars")
                        .full_width(true),
                ),
            )
            .child(
                div().w(px(56.)).child(
                    text_field(&app.hyb_min_input, cx)
                        .placeholder("min")
                        .full_width(true),
                ),
            )
            .child(
                div().w(px(56.)).child(
                    text_field(&app.hyb_max_input, cx)
                        .placeholder("max")
                        .full_width(true),
                ),
            )
            .child(small("word + charset suffix len min..max (1..=4)").muted())
            .into_any_element(),
        "rainbow" => h_stack()
            .gap_2()
            .items_end()
            .child(
                div().w(px(360.)).child(
                    text_field(&app.rainbow_input, cx)
                        .placeholder("/path/to/pmk-table")
                        .full_width(true),
                ),
            )
            .child(
                div().w(px(280.)).child(
                    text_field(&app.wordlist_input, cx)
                        .placeholder("wordlist to build from")
                        .full_width(true),
                ),
            )
            .child(
                button("btn-rainbow-build", "Build table")
                    .disabled(rainbow_building || running)
                    .on_click({
                        let view = view.clone();
                        move |_, window, cx| build(&view, window, cx)
                    }),
            )
            .into_any_element(),
        _ => div()
            .w(px(360.))
            .child(
                text_field(&app.wordlist_input, cx)
                    .placeholder("/path/to/wordlist")
                    .full_width(true),
            )
            .into_any_element(),
    };

    // Recent cracker activity: surfaces errors, estimates, import and
    // benchmark results that would otherwise only be visible on the Log
    // page.
    let activity: Vec<String> = app
        .state
        .log
        .iter()
        .filter(|line| {
            line.starts_with("cracker:")
                || line.starts_with("rainbow:")
                || line.starts_with("estimate:")
                || line.starts_with("benchmark:")
                || line.starts_with("import:")
                || line.starts_with("pmk cache")
                || line.starts_with("profiles:")
                || line.contains("PASSWORD")
        })
        .rev()
        .take(5)
        .cloned()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();

    // Presets + recent wordlists: one-click chips applied to the
    // wordlist/rules fields and (for presets) the attack-mode select.
    let hover_bg = theme.accent_bg();
    let mut preset_row = h_stack().gap_2().items_center();
    let has_presets = !app.profiles.profiles.is_empty() || !app.profiles.recent_wordlists.is_empty();
    for p in &app.profiles.profiles {
        let profile = p.clone();
        preset_row = preset_row.child(
            div()
                .id(gpui::SharedString::from(format!("preset-{}", p.name)))
                .px_2()
                .py_1()
                .rounded_md()
                .border_1()
                .border_color(theme.border())
                .cursor_pointer()
                .text_xs()
                .hover(move |style| style.bg(hover_bg))
                .child(p.name.clone())
                .on_click({
                    let view = view.clone();
                    move |_, _window, cx| apply_preset(profile.clone(), &view, cx)
                }),
        );
    }
    if !app.profiles.profiles.is_empty() {
        preset_row = preset_row.child(
            button("btn-preset-save", "Save preset")
                .on_click({
                    let view = view.clone();
                    move |_, window, cx| save_preset(&view, window, cx)
                }),
        );
    }
    let mut recent_row = h_stack().gap_2().items_center();
    for wl in &app.profiles.recent_wordlists {
        let wl_path = wl.clone();
        let base = std::path::Path::new(wl)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| wl.clone());
        recent_row = recent_row.child(
            div()
                .id(gpui::SharedString::from(format!("recent-{wl}")))
                .px_2()
                .py_1()
                .rounded_md()
                .border_1()
                .border_color(theme.border())
                .cursor_pointer()
                .text_xs()
                .hover(move |style| style.bg(hover_bg))
                .child(base)
                .on_click({
                    let view = view.clone();
                    move |_, _window, cx| {
                        let wl = wl_path.clone();
                        view.update(cx, |app, cx| {
                            app.wordlist_input.update(cx, |input, cx| {
                                input.set_content(wl, cx);
                            });
                            cx.notify();
                        });
                    }
                }),
        );
    }

    // Benchmark card lines (below the Start/Stop row).
    let bench_gpu_line = match app.state.bench_gpu {
        Some(g) => format!("GPU: {}", fmt_hps(g)),
        None => {
            if app.state.bench_cpu.is_some() {
                "GPU: none (CPU only)".to_string()
            } else {
                "not measured — run Benchmark".to_string()
            }
        }
    };
    let bench_cpu_line = app
        .state
        .bench_cpu
        .map(|c| format!("CPU: {}", fmt_hps(c)))
        .unwrap_or_default();
    let bench_disabled =
        app.bench_running || app.crack_inflight || cracker.running || cracker.rainbow_building;

    let mut page = v_stack()
        .size_full()
        .gap_3()
        .p_4()
        .child(
            h_stack()
                .items_center()
                .gap_3()
                .child(h3("Handshake Cracker"))
                .child(small("PBKDF2-SHA1 · WPA/WPA2"))
                .child(div().flex_1())
                .child(
                    button("btn-import", "Import .cap/.pcap/.hc22000")
                        .disabled(app.import_busy)
                        .on_click({
                            let view = view.clone();
                            move |_, window, cx| import_captures(&view, window, cx)
                        }),
                ),
        )
        .when(has_presets, |el| {
            el.child(preset_row)
                .when(
                    !app.profiles.recent_wordlists.is_empty() || !app.profiles.profiles.is_empty(),
                    |el2| el2.child(recent_row),
                )
        })
        .when(!has_presets, |el| {
            // No saved state yet — still offer one-click saving of the
            // current setup.
            el.child(
                h_stack().gap_2().items_center().child(
                    button("btn-preset-save", "Save preset")
                        .on_click({
                            let view = view.clone();
                            move |_, window, cx| save_preset(&view, window, cx)
                        }),
                ),
            )
        })
        .child(
            h_stack()
                .gap_3()
                .items_end()
                .child(div().w(px(360.)).child(app.target_select.clone()))
                .child(div().w(px(200.)).child(app.attack_select.clone()))
                .child(mode_inputs)
                .child(text(backend_label(app.is_mock)).small().muted()),
        )
        .child(
            h_stack()
                .gap_3()
                .items_center()
                .child(
                    button("btn-crack-start", "Start")
                        .disabled(running || app.bench_running)
                        .on_click({
                            let view = view.clone();
                            move |_, window, cx| start(&view, window, cx)
                        }),
                )
                .child(
                    button("btn-crack-stop", "Stop")
                        .destructive()
                        .disabled(!running)
                        .on_click({
                            let view = view.clone();
                            move |_, window, cx| stop(&view, window, cx)
                        }),
                )
                .when(running, |el| el.child(loading_indicator().small())),
        )
        .child(gpuikit::elements::separator::separator())
        .child(
            h_stack()
                .gap_4()
                .child(small(format!("rate: {}", fmt_hps(if running { cracker.hps } else { 0.0 }))))
                .child(small(candidates))
                .child(
                    small({
                        // Coverage % whenever a total exists; ETA needs a
                        // live run too.
                        let pct = effective_total.map(|_| format!("{:.1}%", frac * 100.0));
                        match (pct, &eta) {
                            (Some(p), Some(e)) => format!("{p} · {e}"),
                            (Some(p), None) => p,
                            (None, Some(e)) => e.clone(),
                            (None, None) => String::new(),
                        }
                    }),
                ),
        )
        .child(progress(frac as f32).width(px(520.)))
        .children(
            hps_curve(&app.state.hps_hist, theme.accent()).map(|curve| {
                v_stack()
                    .gap_1()
                    .child(small("rate over time (one bar per progress sample)").muted())
                    .child(curve)
            }),
        )
        .child(
            // Benchmark card: measured crack speed on this machine.
            h_stack()
                .gap_3()
                .items_center()
                .p_3()
                .rounded_md()
                .border_1()
                .border_color(theme.border())
                .child(small("crack speed on this machine"))
                .child(
                    button("btn-benchmark", "Benchmark (3s)")
                        .disabled(bench_disabled)
                        .on_click({
                            let view = view.clone();
                            move |_, window, cx| benchmark(&view, window, cx)
                        }),
                )
                .when(app.bench_running, |el| el.child(loading_indicator().small()))
                .child(small(bench_gpu_line).muted())
                .child(small(bench_cpu_line).muted()),
        )
        .child(
            // Estimator card: worst-case times from the measured rate.
            h_stack()
                .gap_3()
                .items_center()
                .p_3()
                .rounded_md()
                .border_1()
                .border_color(theme.border())
                .child(small("candidate strength / time estimate"))
                .child(
                    div().w(px(220.)).child(
                        text_field(&app.strength_input, cx)
                            .placeholder("type a candidate password")
                            .full_width(true),
                    ),
                )
                .child(
                    button("btn-estimate", "Estimate")
                        .disabled(app.bench_running)
                        .on_click({
                            let view = view.clone();
                            move |_, window, cx| estimate(&view, window, cx)
                        }),
                )
                .child(small("results land in recent activity below").muted()),
        );

    // Recent captures: the newest few crackable targets, so the page shows
    // what material exists without opening the dropdown. Newest last in
    // state → reversed for display.
    let recent_caps: Vec<String> = app
        .state
        .capture_descs()
        .into_iter()
        .rev()
        .take(4)
        .collect();
    if !recent_caps.is_empty() {
        page = page.child(
            v_stack()
                .gap_1()
                .child(small("recent captures (all of them are in the target dropdown)").muted())
                .children(recent_caps.into_iter().map(|d| {
                    text(d).code().small().into_any_element()
                }))
                .into_any_element(),
        );
    }

    if let Some(found) = &cracker.found {
        page = page.child(
            h_stack()
                .gap_3()
                .items_center()
                .w(px(520.))
                .p_3()
                .rounded_md()
                .bg(theme.warning())
                .text_color(theme.bg())
                .child(text(format!("PASSWORD FOUND: {found}")).bold())
                .into_any_element(),
        );
    }

    // Interrupted-run resume banner (saved session file matched to a
    // loaded capture; hidden while anything runs).
    if !running && !rainbow_building && !app.is_mock {
        if let Some(r) = &cracker.resume {
            let status = match r.total {
                Some(t) => format!("{} / {t} tried", r.done),
                None => format!("{} tried", r.done),
            };
            page = page.child(
                h_stack()
                    .gap_3()
                    .items_center()
                    .p_3()
                    .rounded_md()
                    .border_1()
                    .border_color(theme.border())
                    .bg(theme.accent_bg())
                    .child(small(format!(
                        "saved run: {} — {} · {status}",
                        r.target_desc,
                        r.attack.describe()
                    )))
                    .child(
                        button("btn-crack-resume", "Resume")
                            .on_click({
                                let view = view.clone();
                                move |_, window, cx| resume_saved(&view, window, cx)
                            }),
                    )
                    .child(
                        button("btn-crack-discard", "Discard")
                            .destructive()
                            .on_click({
                                let view = view.clone();
                                move |_, window, cx| discard_saved(&view, window, cx)
                            }),
                    ),
            );
        }
    }

    if !activity.is_empty() {
        let mut block = v_stack().gap_1();
        for line in activity {
            block = block.child(small(line).muted());
        }
        page = page.child(block);
    }

    if rainbow_building {
        page = page.child(
            h_stack()
                .gap_3()
                .items_center()
                .child(loading_indicator().small())
                .child(small(format!(
                    "rainbow build: {} PMKs · {} · {}",
                    cracker.rainbow_done,
                    fmt_hps(cracker.rainbow_hps),
                    fmt_worst_case(cracker.rainbow_done, cracker.rainbow_hps, cracker.rainbow_total)
                        .unwrap_or_default()
                )))
                .child(
                    button("btn-rainbow-stop", "Stop build")
                        .destructive()
                        .on_click({
                            let view = view.clone();
                            move |_, window, cx| build_stop(&view, window, cx)
                        }),
                ),
        );
    }

    page
}
