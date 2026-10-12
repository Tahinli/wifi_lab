# wifilab — module contract

Single bin crate `wifilab`. All modules live flat under `src/`. Shared domain
types are in `src/common.rs` (MacAddr, Security, AccessPoint, ClientInfo,
HandshakeCapture, PmkidCapture, Event, channel lists). These are FIXED.

Everything must compile with `cargo check` on stable Rust 1.99, edition 2024.
Errors: `anyhow::Result` at module boundaries. No new dependencies beyond
`Cargo.toml`. No `unsafe` outside `rawsock.rs`.

## radiotap.rs (owner: radio-core)
Zero-copy radiotap parser + TX injection header.

```rust
/// Parsed metadata from an RX radiotap header.
pub struct RxMeta {
    pub rssi_dbm: i8,                 // antenna signal, 0 if absent
    pub freq_mhz: u16,                // channel frequency, 0 if absent
}
pub const INJECT_HDR: [u8; 8];        // version 0, pad 0, len 8, present 0
/// Parse radiotap; returns (meta, remaining 802.11 frame bytes).
/// Returns None if the buffer is not a well-formed radiotap header.
pub fn strip(frame: &[u8]) -> Option<(RxMeta, &[u8])>;
```
Must handle: length bounds, field alignment, present bitmap order
(tsft/flags/rate/channel/antenna-signal). Unknown present bits: skip per
alignment rules of the known ones; if an unknown extension appears, degrade
gracefully (still return header end via it_len).

## dot11.rs (owner: radio-core)
802.11 MAC frame parsing/building. Zero-copy where possible. Little work on
QoS/data frames beyond finding BSSID/STA and EAPOL payloads.

```rust
pub struct MgmtInfo {
    pub bssid: MacAddr,
    pub transmitter: MacAddr,          // addr2
    pub ssid: Option<String>,          // None if hidden/zero-len
    pub channel: Option<u8>,           // DS parameter set IE
    pub security: Security,            // from RSN/WPA IEs + capability privacy bit
}
/// Parse beacon OR probe-response; None for other/broken frames.
pub fn parse_beacon_or_probe(f: &[u8]) -> Option<MgmtInfo>;
/// Parse probe-request → Some(ssid of probe) — used to discover clients.
pub fn parse_probe_req(f: &[u8]) -> Option<(MacAddr /*sta*/, Option<String>)>;
/// Parse deauth/disassoc → (from-ap MacAddr as transmitter, target addr1).
pub fn parse_deauth(f: &[u8]) -> Option<(MacAddr, MacAddr)>;
/// Extract (bssid, station) that best describes a data frame's endpoints
/// using ToDS/FromDS bits. None for mgmt/ctrl frames.
pub fn data_endpoints(f: &[u8]) -> Option<(MacAddr, MacAddr)>;
/// If frame carries an EAPOL-Key payload (LLC/SNAP 88-8e in data frame),
/// return (bssid, station_is_ap_sender, eapol_bytes).
pub fn parse_eapol(f: &[u8]) -> Option<(MacAddr, bool, &[u8])>;

pub struct EapolKey<'a> {
    pub key_info: u16,        // raw key info field (BE order as on wire)
    pub key_ver: u8,          // bits 0..3 of key_info (descriptor version)
    pub install: bool,        // bit6
    pub key_ack: bool,        // bit7
    pub key_mic: bool,        // bit8
    pub secure: bool,         // bit9
    pub replay_counter: u64,
    pub nonce: [u8; 32],
    pub mic: [u8; 16],        // raw mic field (or RSN IE scan for pmkid)
    pub key_data: &'a [u8],   // for PMKID extraction (RSN IE, KDE 00-0f-ac:4)
    pub raw: &'a [u8],        // full eapol frame starting at version byte
}
/// 1..=4 4way message number derived from flags, 0 if not an EAPOL-Key.
pub fn parse_eapol_key(eapol: &[u8]) -> Option<EapolKey<'_>>;
pub fn eapol_4way_msg(k: &EapolKey) -> u8;   // classic heuristics (M1..M4)

// frame builders (return full 802.11 frame, NO radiotap — caller prepends INJECT_HDR)
pub fn build_deauth(ap: &MacAddr, target: &MacAddr, reason: u16) -> Vec<u8>;
pub fn build_disassoc(ap: &MacAddr, target: &MacAddr, reason: u16) -> Vec<u8>;
pub fn build_auth_open(ap: &MacAddr, sta: &MacAddr, seq: u16) -> Vec<u8>;
pub fn build_assoc_req(ap: &MacAddr, sta: &MacAddr, ssid: &[u8]) -> Vec<u8>;
```
Wire details: deauth FC = 0x00c0, assoc FC = 0x0000, auth FC = 0x00b0.
Sequence control may be left 0. Duration 314. FCS omitted (driver appends).
Unit tests must cover parse↔build roundtrips and the classic 4way M1..M4 flag
matrices.

## rawsock.rs (owner: radio-core)
Only module allowed to use `unsafe` (libc AF_PACKET).

```rust
pub struct RawSocket { /* fd + ifindex */ }
impl RawSocket {
    /// AF_PACKET SOCK_RAW ETH_P_ALL bound to ifname. Requires CAP_NET_RAW.
    pub fn open(ifname: &str) -> std::io::Result<Self>;
    pub fn ifname(&self) -> String;
    /// Blocking receive of one L2 frame (radiotap + 802.11 in monitor mode).
    pub fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize>;
    /// Transmit an 802.11 frame prefixed with radiotap INJECT_HDR (len arg
    /// includes the header).
    pub fn send(&self, frame_with_radiotap: &[u8]) -> std::io::Result<usize>;
    /// Receive timeout toggle for poll-style loops.
    pub fn set_timeout(&self, ms: u32) -> std::io::Result<()>;
}
```
Implement with raw `libc` calls (no socket2). Handle EINTR on recv (retry).

## iface.rs (owner: attacks)
System interface control via `ip`/`iw` subprocess (boring + portable).

```rust
/// Switch ifname to monitor mode (down → set type monitor → up). Idempotent.
pub fn to_monitor(ifname: &str) -> anyhow::Result<()>;
pub fn to_managed(ifname: &str) -> anyhow::Result<()>;
pub fn set_channel(ifname: &str, ch: u8) -> anyhow::Result<()>;
/// Parse `iw dev` for the current channel; Err if not determinable.
pub fn current_channel(ifname: &str) -> anyhow::Result<u8>;
/// Wireless interfaces present (from /sys/class/net/*/wireless).
pub fn list_wifi_ifaces() -> Vec<String>;
/// Our own MAC on ifname.
pub fn mac_of(ifname: &str) -> anyhow::Result<crate::common::MacAddr>;
/// True when running with euid 0; UI surfaces a warning otherwise.
pub fn is_root() -> bool;
// note: NetworkManager/wpa_supplicant interference is the caller's concern;
// expose `kill_interferers()` that runs NM radio off like airmon does NOT —
// instead just document required state.
```

## scanner.rs (owner: attacks)
```rust
pub struct ScannerConfig { pub ifname: String, pub channels: Vec<u8>, pub dwell_ms: u32, pub rssi_floor: i8 }
/// Blocking channel-hop passive scan. Sends Event::{ApUpdated,ApLost,
/// ClientUpdated,Log} into `tx`; returns when `stop` flips true.
pub fn run(cfg: ScannerConfig, tx: crossbeam_channel::Sender<Event>, stop: std::sync::Arc<std::sync::atomic::AtomicBool>) -> anyhow::Result<()>;
```
APs expire (ApLost) after 30 s silent; clients after 60 s. Clients learned
from data frames + probe requests. Deduplicate by BSSID; keep best RSSI.

## handshake.rs (owner: attacks)
4-way tracker + hc22000/hashcat-22000 export.
```rust
pub struct Tracker { /* per (ap,sta) partial state; anonce/snonce/mics */ }
impl Tracker {
    pub fn new() -> Self;
    /// Feed a parsed EapolKey (+ endpoints + current essid for ap).
    /// Emits HandshakeProgress events; returns Some(capture) once a crackable
    /// pair (M1+M2, or M2+M3 with replay check) is complete.
    pub fn ingest(&mut self, ap: MacAddr, sta: MacAddr, essid: &str,
                  key: &crate::dot11::EapolKey, tx: &crossbeam_channel::Sender<Event>)
        -> Option<HandshakeCapture>;
}
/// hashcat -m 22000 WPA-PBKDF2-PMKID+EAPOL line for a handshake (type 02).
pub fn handshake_hc22000(h: &HandshakeCapture) -> String;
/// hashcat -m 22000 PMKID line (type 01).
pub fn pmkid_hc22000(p: &PmkidCapture) -> String;
/// Parse one hc22000 line back into a CrackTarget (for loading captures).
```
M1+M2 must verify replay counters consistent (rc(M2) == rc(M1)) and nonces
nonzero. ESSID comes from the last seen beacon for that BSSID — supply param.
AP-less ESSID unknown → skip capture (cannot crack without salt).

## deauth.rs (owner: attacks)
```rust
/// Send `count` deauth frames ap→target and target→ap (both directions),
/// rate-limited to ~64 pps, plus Event::DeauthSent every 32 frames.
/// If target is BROADCAST: broadcast deauth from AP side only.
/// Returns frames actually sent.
pub fn blast(sock: &RawSocket, ap: &MacAddr, target: &MacAddr,
             count: u32, tx: &crossbeam_channel::Sender<Event>) -> anyhow::Result<u64>;
pub const REASON_UNSPECIFIED: u16 = 1;
pub const REASON_CLASS2: u16 = 6;
pub const REASON_CLASS3: u16 = 7;
```

## pmkid.rs (owner: attacks)
```rust
/// Clientless PMKID grab: auth (open) + assoc to `ap` impersonating our
/// station MAC `sta`, watch the wire for EAPOL M1 carrying RSN PMKID KDE
/// (type 00-0f-ac, subtype 4) for ~3 s. Idempotent-ish: single attempt.
/// Returns Some(capture) with essid filled from `essid`.
pub fn grab(sock: &RawSocket, ap: &MacAddr, sta: &MacAddr, essid: &str)
    -> anyhow::Result<Option<PmkidCapture>>;
```

## crypto.rs (owner: cracker) — CPU reference implementation
```rust
pub enum CrackTarget { Handshake(HandshakeCapture), Pmkid(PmkidCapture) }
impl CrackTarget { pub fn essid(&self)->&str; pub fn describe(&self)->String; /* from hc22000 parse */ }
pub fn pmk(pass: &[u8], ssid: &[u8]) -> [u8; 32];
pub fn ptk(pmk: &[u8; 32], ap: &MacAddr, sta: &MacAddr,
           anonce: &[u8; 32], snonce: &[u8; 32]) -> [u8; 64];  // PRF-512
pub fn mic(ptk: &[u8; 64], eapol: &[u8], key_ver: u8) -> [u8; 16]; // ver1/2: HMAC-SHA1-128; ver3: AES-CMAC
pub fn pmkid_hash(pmk: &[u8; 32], ap: &MacAddr, sta: &MacAddr) -> [u8; 16]; // HMAC-SHA1-128("PMK Name", ap||sta)
pub fn verify(target: &CrackTarget, pass: &[u8]) -> bool;
pub fn parse_hc22000(line: &str) -> anyhow::Result<CrackTarget>;
```
PRF per 802.11-2016 §12.7.1.2: "Pairwise key expansion" counter loop, A =
min(ap,sta)||max(ap,sta), B = min(anonce,snonce)||max(anonce,snonce).
MIC: zero bytes 81..97 of the EAPOL frame before hashing. AES-CMAC via
hand-rolled AES-128 (no new deps) or constant util — key_ver 3 rare for
WPA2-PSK; implement anyway.
Tests: RFC 6070 PBKDF2 vectors + roundtrip: build synthetic handshake from
known (ssid,pass), verify() == true, tampered pass == false, hc22000
export→parse→verify == true.

## gpu.rs + pbkdf2.wgsl (owner: cracker)
wgpu compute cracker. Must run on Vulkan (radv) headless, fall back to CPU
(on `GpuCracker::try_new() -> Option`).
```rust
pub struct GpuCracker;
impl GpuCracker {
    /// None when no suitable adapter (caller falls back to cpu::crack).
    pub fn try_new() -> Option<Self>;
    pub fn device_name(&self) -> String;
    /// Stream wordlist (any bytes iterator of \n-trimmed candidates 8..=63),
    /// batch through the GPU, call `progress(batch_done, hps_estimate)`
    /// periodically; Some(pass) on MIC match. Honors `stop`.
    pub fn crack(&self, target: &CrackTarget,
                 words: &mut dyn Iterator<Item = Vec<u8>>,
                 progress: &mut dyn FnMut(u64, f64),
                 stop: &std::sync::Arc<std::sync::atomic::AtomicBool>)
        -> Option<String>;
}
pub fn cpu_crack(target: &CrackTarget, words: &mut dyn Iterator<Item = Vec<u8>>,
                 progress: &mut dyn FnMut(u64, f64),
                 stop: &std::sync::Arc<std::sync::atomic::AtomicBool>) -> Option<String>;
```
Algorithm (hashcat-style): host computes per candidate SHA1 midstate for
ipad/opad HMAC keys **and U1 = PRF(state, salt||0x00000001), U1' (block
2 = ...||0x00000002)** — salt = target essid, so U1/U1' are per-candidate×2
only because key pads differ. Upload SoA arrays {sha1 midstate a,b ×2 (5 u32
each), u1 (5), u1'(5)}. Kernel runs 4095 chained HMAC iterations per block
(U = HMAC(P, U); T ^= U) producing 40 bytes → PMK[0..20]|PMK2[0..20] → PMK =
first20||first12. Host then derives PTK+MIC per PMK on CPU (cheap relative to
4096 HMACs) and compares. Batch size tuned to adapter limits (start 65536
candidates, halve on timeout). WGSL uses u32 SHA1, no naga extensions.
Correctness test: gpu crack must agree with crypto::verify on a synthetic
target and find a planted passphrase mid-wordlist; also cross-check PMK of
first 32 candidates vs pbkdf2 crate. Mark GPU test `#[ignore]`? NO — must run
in CI-less env: if no adapter, test early-returns Ok.

## wordlist.rs (owner: cracker)
```rust
/// Streaming iterator over a wordlist file (mmap not required; BufReader),
/// yielding trimmed 8..=63-byte candidates, counting progress.
pub fn open(path: &std::path::Path) -> anyhow::Result<Box<dyn Iterator<Item = Vec<u8>> + Send>>;
```
