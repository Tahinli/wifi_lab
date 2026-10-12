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
3. **Attacks** page:
   - **Capture Handshake** — parks on the target channel and tracks EAPOL
     4-way exchanges; `M1..M4` progress shows live until a crackable
     M1+M2 pair lands.
   - **Deauth** — forces a client (the selected one, or broadcast) to
     re-authenticate so the handshake capture above completes fast. Count
     comes from the input next to the button. Deauth while capturing is
     the intended combo: keep both on the same channel (the UI targets a
     single AP, so this is automatic).
   - **PMKID Attack** — clientless: auth+assoc from the monitor
     interface's own MAC and read the PMKID from the AP's M1. Many APs
     don't volunteer one — the log tells you either way.
   - **Export .hc22000** — writes every capture in hashcat 22000 format.
4. **Cracker** page — stop capture first (the cracker holds the wordlist
   stream for a long time; radio access is exclusive). Pick the capture,
   point the wordlist field at e.g. `/usr/share/wordlists/rockyou.txt`,
   hit **Start**. Live H/s and candidate count stream in. **Stop** flips
   the job's stop flag and the worker exits at the next batch.
5. Everything the service (and the crack thread) does is mirrored on the
   **Log** page, including worker errors (permissions, channel-change
   failures, wordlist open failures). During a scan a compact
   `scan: N rx frames, M beacons -> K APs live (ch C)` heartbeat lands
   every 10 s — the evidence line distinguishing RX-silence from parser
   drops.

On exit (window close) the service is told to shut down: it stops all
radio workers, restores the interface to managed mode (deleting the
`<iface>mon` vif if one was created), and exits; the UI-side crack
thread is stopped as well.

## Cracking backends

The cracker prefers the GPU (wgpu/Vulkan compute; works headless, e.g.
radv). `GpuCracker::try_new()` returns `None` when no suitable adapter
exists and the run transparently falls back to the CPU reference cracker —
the log line says which backend is active. WPA passphrases 8..63 bytes;
wordlist lines are trimmed/streamed, huge files are fine.

## Files

- Captures export to `./captures/wifilab-<ts>.hc22000` (or the path chosen
  in the save dialog) in hashcat `-m 22000` format — one `WPA*02` line per
  handshake, one `WPA*01` line per PMKID.
