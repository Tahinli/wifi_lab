# wifilab — usage

WPA/WPA2 lab tool: passive scan → capture a 4-way handshake or PMKID →
crack it on the GPU (CPU fallback). Single binary, GPUI shell.

## Running

No terminal privileges needed. Start the app normally:

```sh
cargo build --release
./target/release/wifilab
```

Privileges are handled by a **privileged service**: the UI itself never
needs root and never respawns. The first time you click **Start capture**
the app spawns the same binary as a child process with the hidden flag
`--privileged-worker` — directly when already root, otherwise through
`pkexec`, which pops the system polkit dialog **once per capture
session**. All radio work (monitor mode, scanning, deauth, PMKID grab,
handshake capture) happens inside that service; the two halves talk JSON
lines over the child's stdin/stdout and only distilled events cross the
pipe. The GPU cracker needs no privilege and runs as a plain thread in
the UI process.

- `--iface <name>` picks the wireless interface (default: first detected
  wireless interface, falling back to `wlp14s0`). The header bar's picker
  can also switch interfaces while capture is stopped.
- `--mock` (or `WIFILAB_MOCK=1`) runs the UI against fabricated events —
  no device access, for development only.
- On startup the tool prints one line: mode, interface, root status.
  Not root? The badge says *user (service will elevate)* and a toast
  notes polkit will ask when capture starts — the UI stays fully usable.
  A dismissed polkit dialog just logs an error; click Start again to
  retry.

**NetworkManager fight:** while NetworkManager is active it pins the card
to the connected network's channel — during a scan you will typically see
**only that one SSID** (e.g. your connected network) instead of every
neighbour. The app detects this at *Start capture*, shows a destructive
toast, logs a warning, and offers a **"Stop NM"** button in the header
(the request runs inside the elevated service). Restore it afterwards
with `systemctl start NetworkManager`. Everything else on the system is
left untouched.

## Workflow

1. **Start capture (monitor)** — switches the interface to monitor mode
   (creates `<iface>mon` on drivers that can't switch in place) and starts
   the channel hopper. APs and clients stream into the Networks page.
2. Click the target network (e.g. *parafin*) in the AP table — or click a
   client row to select the (AP, client) pair.
   The Networks page also shows, per AP/client: OUI vendor (IEEE MA-L/MA-M/
   MA-S registries; `random` marks a locally-administered address — the
   [MAC-randomization] norm for modern phones), security detail (AKM
   suites; the badge refines to `WPA2/3` transition, `WPA3` SAE-only, or
   `OWE` enhanced-open), and a signal-history sparkline; a per-channel
   activity strip sits above the AP table; a **Probes** section lists
   nearby clients' probe requests (hidden SSIDs also get correlated from
   association requests). Client rows resolve their AP column to the SSID
   name, and the **ID** column pairs rotated/randomized MACs of one
   physical radio: `#1~ (2)` = device group 1, two known MACs, `~` = strong
   witness (`?` fingerprint only, `~` fingerprint + shared probed SSID or
   uninterrupted sequence numbers, `=` WPS UUID-E). Pairing uses the
   ordered-IE fingerprint of probe/assoc frames plus those witnesses — see
   the Log page for pairing decisions. AP rows flag risk at a glance:
   `weak` on Open/WEP networks, `<hidden>` for cloaked SSIDs, `rogue?` when
   the same SSID appears on another BSSID with different security. The
   activity strip above the AP table becomes a scrolling per-channel
   timeline once traffic accumulates (one column per snapshot, brightest =
   busiest); a channel hosting ≥4 APs gets a crowded warning — overlapping
   BSSs eat each other's airtime. A sudden deauth storm from a source that
   is not us (≥10 frames to one target in 10 s) raises a `DEAUTH STORM`
   alert.
3. **Attacks** page — the top card is a full target briefing, built from
   everything Networks already knows: BSSID, channel/band, OUI vendor,
   security badge + AKM suites, signal sparkline, beacon count, material
   already captured for this AP family, your label, and a bold **advice
   line** ("deauth a client while capture runs", "no clients mapped — run
   PMKID first", "SAE-only — dead end", "WPA3 transition — crackable") that
   answers "which button do I press". The card survives the AP leaving the
   scan table (a "last scan snapshot" note marks the fallback), so locking
   onto a host-connected network no longer blanks it. The Stations list
   shows each mapped station with vendor, ID-pairing chip, RSSI, and
   whether its AP link is real or assumed.
   - **Capture Handshake** — parks on the target channel and tracks EAPOL
     4-way exchanges; `M1..M4` progress shows live until a crackable
     M1+M2 pair lands.
   - **Deauth** — forces a client (the selected one, or broadcast) to
     re-authenticate so the handshake capture above completes fast. Count
     comes from the input next to the button. Deauth while capturing is
     the intended combo: keep both on the same channel (the UI targets a
     single AP, so this is automatic). When the AP has ≥2 connected
     clients a **Deauth all clients (N)** button appears: targeted frames
     at every known client plus one broadcast round.
   - **PMKID Attack** — clientless: auth+assoc from the monitor
     interface's own MAC and read the PMKID from the AP's M1. Many APs
     don't volunteer one — the log tells you either way.
   - **SAE-only APs** (WPA3 without the PSK AKM) offer no offline-crackable
     handshake or PMKID — the capture/deauth buttons are disabled for them
     with an explanation. WPA2/WPA3 transition APs (PSK AKM present) are
     crackable as usual.
   - **Export .hc22000** — writes every capture in hashcat 22000 format.
   - **Export .pcap** — copies the session's raw-frame spool
     (`~/wifilab/spool.pcap`, radiotap linktype, truncated on each Start
     capture) for Wireshark.
4. **Cracker** page — pick the capture, the attack mode, hit **Start**.
   Cracking is a plain UI-process job (GPU + wordlist need neither root
   nor the radio), so it runs while capturing, before ever capturing, or
   after a restart (captures are persisted and restored). Modes:
   - **wordlist** — dictionary run; point the field at a wordlist file
     (e.g. rockyou; note it is NOT preinstalled — download/choose a real
     path, the page refuses to start on a path it cannot open).
   - **rules** — dictionary × mangling rules (hashcat-subset:
     `l u c C t r d $X ^X [ ] sXY`, multi-op lines, `#` comments): the
     classic human-password crack that plain wordlists miss. Resume
     continues at the flattened word×rule index.
   - **hybrid** — wordlist × append sweep: every word gets every suffix
     of 1..4 characters from the charset chips (human pattern
     "summer2024"), clamped to WPA's 63 bytes.
   - **bruteforce** — exhaustive `charset^len` sweep over the given
     min..max lengths (clamped to WPA's 8..63). The charset is the union
     of the checked preset chips (a-z, A-Z, 0-9, common specials) and the
     custom-chars field. Grows combinatorially — the status row shows
     the exact total and the worst-case ETA. The **freq-order** chip
     (default on) tries most-common password characters first (same
     space, better early-hit odds).
   - **rainbow** — a precomputed PMK table for the capture's SSID: no
     PBKDF2 at run time, one MIC compare per entry (millions/s). Build
     one from any wordlist with **Build table** (pays PBKDF2 once, GPU
     when available); reuse it for every later capture of that SSID.
     Tables are salt-bound to the SSID — a table for another SSID is
     refused up front, not silently exhausted.
   Live H/s and candidate count stream in, with a throughput curve (one
   bar per progress sample), a coverage progress bar with exact percentage
   whenever the worker knows the worst-case total, and a worst-case ETA
   (every untried candidate at the current rate — wordlist/table line
   counts are upper bounds, brute force is exact). A **recent captures**
   block lists the newest crackable targets so you can see what material
   you have without opening the dropdown. The recent-activity block on
   the page mirrors cracker/rainbow log lines (including failures).
   **Stop** flips the job's stop flag and the worker exits
   at the next batch.

   **PMK cache** — wordlist-family runs first blast through a per-SSID
   cache of already-computed PMKs (`~/wifilab/cache/<ssid-hex>.pmk`,
   rainbow format — one MIC compare per entry) and skip those candidates
   in the main run. Pure-CPU runs APPEND their PMKs to the cache (GPU
   runs cannot — the verify pipeline has no PMK readback). A cache for a
   different SSID is never used.

   **Presets & recents** — the row above the target picker saves the
   current mode+paths as a named chip and re-applies them later; the last
   five wordlists are one click away (`~/wifilab/profiles.json`).

   **Import** — `Import .cap/.pcap/.hc22000` brings in captures made
   elsewhere: pcap files (radiotap or raw 802.11) are scanned for
   beacons + EAPOL exchanges and PMKIDs; hc22000 files are parsed line
   by line. Everything importable lands in the target picker.

   **Benchmark & estimator** — `Benchmark (3s)` measures this machine's
   GPU and CPU hash rate. The estimator card then converts any candidate
   or attack configuration into worst-case crack times (log lines
   prefixed `estimate:`); without a benchmark it shows candidate-space
   math only.

   A found password raises a desktop notification (best-effort; silently
   no-ops headless) on top of the in-app banner and toast.

   **Resume:** an interrupted run autosaves its position to
   `~/wifilab/crack-session.json` every couple of seconds (and once on
   Stop) — crash, power cut, or closing the window loses at most ~2 s
   of work. On the next start the page shows a "saved run" banner with
   **Resume** (wordlist/table re-open and skip forward, brute force
   seeks the odometer in O(1); progress and ETA keep counting against
   the full space) and **Discard**. A found password or an exhausted
   space deletes the session instead.
5. Everything the service (and the crack thread) does is mirrored on the
   **Log** page, including worker errors (permissions, channel-change
   failures, wordlist open failures). During a scan a compact
   `scan: N rx frames, M beacons -> K APs live (ch C)` heartbeat lands
   every 10 s — the evidence line distinguishing RX-silence from parser
   drops.

On exit (window close) the service is told to shut down: it stops all
radio workers, restores the interface to managed mode (deleting the
`<iface>mon` vif if one was created), restarts NetworkManager if it was
stopped this session, and exits; the UI-side crack thread is stopped as
well. The restore is verified: if the monitor vif survives, the log
carries the exact manual recovery command (`sudo iw dev <if>mon del`).

## Headless CLI

`wifilab crack --capture capture.hc22000 --wordlist rockyou.txt` runs the
same engine with no UI, no radio, no root: first crackable `WPA*` line of
the capture file is the target; modes `--mode wordlist|rules|bruteforce`
plus `--rules`, `--hybrid`, `--min/--max`, charset chips, and `--cpu`
(force CPU; also fully side-effect-free — no PMK-cache appends). Exit
codes: 0 password found (`FOUND: …`), 1 space exhausted, 2 usage/io
error. Consults the per-SSID PMK cache like the UI does.

## Cracking backends

The cracker prefers the GPU (wgpu/Vulkan compute; works headless, e.g.
radv). `GpuCracker::try_new()` returns `None` when no suitable adapter
exists and the run transparently falls back to the CPU reference cracker —
the log line says which backend is active. WPA passphrases 8..63 bytes;
wordlist lines are trimmed/streamed, huge files are fine. Rainbow runs
use precomputed PMKs and skip PBKDF2 entirely (the GPU is then only used
for the one-time build).

## Files

- Captures export to `./captures/wifilab-<ts>.hc22000` (or the path chosen
  in the save dialog) in hashcat `-m 22000` format — one `WPA*02` line per
  handshake, one `WPA*01` line per PMKID. Export .pcap copies the spool
  instead.
- `~/wifilab/spool.pcap` — raw frames (radiotap) of the current capture
  session, written by the service; truncated on each Start capture.
- `~/wifilab/cache/<ssid-hex>.pmk` — per-SSID PMK cache (rainbow format),
  consulted by every wordlist-family run; appended by pure-CPU runs.
- `~/wifilab/profiles.json` — cracker presets + recent wordlists.
- `~/wifilab/captures.jsonl`, `labels.json`, `crack-session.json` — as
  before (captures, per-MAC labels, resume state).
