# wifilab — usage

WPA/WPA2 lab tool: passive scan → capture a 4-way handshake or PMKID →
crack it on the GPU (CPU fallback). Single binary, GPUI shell.

## Running

No terminal privileges needed. Start the app normally:

```sh
cargo build --release
./target/release/wifilab
```

Privileges are handled **inside the UI**: when not running as root the
header shows a **"Elevate via polkit"** button — one click pops the
system polkit dialog, and the app restarts itself elevated (same window,
same selected interface). The unprivileged window closes automatically
once the elevated instance is up. Starting a capture while unprivileged
just logs a reminder; nothing fails mid-attack.

- `--iface <name>` picks the wireless interface (default: first detected
  wireless interface, falling back to `wlp14s0`). The header bar's picker
  can also switch interfaces while capture is stopped.
- `--mock` (or `WIFILAB_MOCK=1`) runs the UI against fabricated events —
  no device access, for development only.
- On startup the tool prints one line: mode, interface, root status.
  Not root? The badge shows it and a toast warns once — the UI stays
  usable, but every attack will fail with errors in the Log page.

The tool does **not** kill or stop anything on your system. If
NetworkManager/wpa_supplicant grab the interface (channel changes fail,
no packets), stop them yourself, e.g.:

```sh
sudo systemctl stop NetworkManager   # optional, only if attacks misbehave
```

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
5. Everything the backend does is mirrored on the **Log** page, including
   worker errors (permissions, channel-change failures, wordlist open
   failures).

On exit (window close) all workers are stopped and the interface is
restored to managed mode (the `<iface>mon` vif is deleted if one was
created).

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
