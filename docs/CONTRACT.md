# wifilab — module contract

Single bin crate `wifilab`. All modules live flat under `src/`. Shared domain
types are in `src/common.rs` (MacAddr, Security, Akm, AccessPoint, ClientInfo,
HandshakeCapture, PmkidCapture, ChannelStat, ProbeInfo, ImportedCapture,
Event, Cmd, channel lists). The wire format evolves ADDITIVELY ONLY: new enum
variants may be appended (externally-tagged serde, ordering free) and new
struct/enum fields must carry `#[serde(default)]` so older records
deserialize losslessly (precedent: `ClientInfo.connected`,
`Cmd::StartScan.spool`/`fresh_spool`, `AccessPoint.akms`). Never rename,
remove, or change the meaning of existing variants/fields.

## imported-capture (common.rs)
`Event::CaptureImported(ImportedCapture)` carries a capture recovered from an
external file (pcap/hc22000 import): `ImportedCapture::Handshake(Box<
HandshakeCapture>) | Pmkid(PmkidCapture)`. `store::StoredCapture` stays in
store.rs (common must not depend on store); the UI converts at the boundary.
Other wire additions: `Event::ChannelStats(Vec<ChannelStat>)` (cumulative
per-channel frame/beacon counters), `Event::ProbeObserved(ProbeInfo)` (novel
probe request), `Event::DeauthAlert { source, target, count }` (≥10 deauths
per (src,dst) pair per 10 s from a source we did not cause),
`Event::BenchmarkDone { gpu_hps: Option<f64>, cpu_hps: f64 }`, and
`Cmd::DeauthAll { ap, channel, targets, count }` (pin `channel`, blast
`count` rounds at each target then one broadcast blast).
`AccessPoint.akms` lists the RSN/WPA AKM suites (empty = unknown; deduped
in first-seen order); `Akm` labels: Psk→"PSK", Sae→"SAE", Owe→"OWE",
FtPsk→"FT-PSK", PskSha256→"PSK-SHA256", OneX→"802.1X", Other(_)→"other".

## device-correlation (common.rs)
`Event::ClientIdent { mac, group, confidence }`: `mac` was correlated by
the scanner into device group `group` (u64, 1-based, process-lifetime
stable) — the MAC-randomization pairing: all MACs witnessed on one physical
radio share the group id. `IdentConfidence` = `Probable` ("?": ordered-IE
fingerprint match only) < `Strong` ("~": fingerprint + shared probed SSID
or uninterrupted 802.11 sequence numbers) < `Exact` ("=": WPS UUID-E
match). Emitted once per pairing decision (first assignment, or re-entry
after the 15-minute scanner-side group TTL). `ClientInfo` gains
`ident_group`/`ident_conf` (serde-default mirrors of the last decision).

Everything must compile with `cargo check` on stable Rust 1.99, edition 2024.
Errors: `anyhow::Result` at module boundaries. No new dependencies beyond
`Cargo.toml` (which already includes `notify-rust` for the desktop
notification on password found — best-effort, headless/no-D-Bus drops the
error). No `unsafe` outside `rawsock.rs`.

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
    pub akms: Vec<Akm>,                // AKM suites from RSN/WPA IE; empty for open/WEP
}
/// Parse beacon OR probe-response; None for other/broken frames.
pub fn parse_beacon_or_probe(f: &[u8]) -> Option<MgmtInfo>;
/// Parse probe-request → Some(ssid of probe) — used to discover clients.
pub fn parse_probe_req(f: &[u8]) -> Option<(MacAddr /*sta*/, Option<String>)>;
/// Association/reassociation request → (station, bssid, ssid).
/// ssid None for hidden (empty / NUL-padded SSID IE). Subtype 0 = assoc,
/// subtype 1 = reassoc.
pub fn parse_assoc_req(f: &[u8]) -> Option<(MacAddr, MacAddr, Option<String>)>;

// -- device correlation (MAC-randomization pairing; scanner.rs::GroupBook
//    consumes these, one event per frame, scanner decides identity) -------
/// 12-bit per-transmitter sequence number (bytes 22-24, seq<<4|frag).
pub fn seq_of(f: &[u8]) -> Option<u16>;
/// Ordered-IE fingerprint: FNV-1a over (tag,len) pairs + full rate-tag
/// payloads + vendor-IE OUI+type tuples. The SSID tag's LENGTH is excluded
/// (directed vs wildcard probes of one radio must hash equal).
pub fn ie_fingerprint(f: &[u8], ie_off: usize) -> Option<u32>;
/// WPS UUID-E (vendor IE 00:50:f2:04, attribute 0x1047) if present.
pub fn wps_uuid_e(f: &[u8], ie_off: usize) -> Option<[u8; 16]>;

pub struct ProbeIdent { pub sta: MacAddr, pub ssid: Option<String>, pub fingerprint: u32, pub uuid: Option<[u8; 16]> }
pub struct AssocIdent { pub sta: MacAddr, pub bssid: MacAddr, pub ssid: Option<String>, pub fingerprint: u32, pub uuid: Option<[u8; 16]> }
/// Probe request with correlation material; None when the IE chain can't
/// be fingerprinted (or it's not a probe request). IEs walk from 24.
pub fn parse_probe_ident(f: &[u8]) -> Option<ProbeIdent>;
/// Assoc/reassoc with correlation material (same offsets as
/// `parse_assoc_req`). Hidden/NUL-padded SSID → None.
pub fn parse_assoc_ident(f: &[u8]) -> Option<AssocIdent>;
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

AKM parsing (`MgmtInfo.akms`): in the RSN IE body the AKM suite list sits at
`8 + 4×pairwise_count` (after version(2) group(4) pairwise_cnt(2)
pairwise[4n] akm_cnt(2)); each suite is OUI 00:0f:ac + type byte. Only the
type byte is inspected:

| type | Akm           | label        |
|------|---------------|--------------|
| 1    | `OneX`        | 802.1X       |
| 2    | `Psk`         | PSK          |
| 4    | `FtPsk`       | FT-PSK       |
| 6    | `PskSha256`   | PSK-SHA256   |
| 8    | `Sae`         | SAE          |
| 18   | `Owe`         | OWE          |
| any other | `Other(t)` | other        |

The vendor WPA IE (tag 221, OUI+type 00:50:f2:01) implies WPA1, which only
ever used PSK key management, so a single `Akm::Psk` is pushed. The
`Security` label (WPA3 iff SAE present) is independent of this list. The
final list is DEDUPED (first-seen order kept): a mixed WPA+WPA2 AP must
not surface `PSK+PSK`.

`parse_assoc_req` frame offsets (receivers check `f.len() < ie_off` first):
addr1 (bssid) at 4, addr2 (station) at 10; fixed params capability(2) +
listen interval(2) at 24; IEs walk from 28 for subtype 0, from 34 for
subtype 1 (reassoc inserts the 6-byte current-AP address). SSID IE (tag 0)
is taken if non-empty and not NUL-padded.

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
/// Reload the driver bound to ifname's device (mt76 monitor-TX wedge
/// recovery); waits for re-enumeration, leaves the managed vif DOWN.
/// Destroys ALL vifs on the phy — recreate the monitor vif afterwards.
pub fn reset_driver(ifname: &str) -> anyhow::Result<()>;
/// Wireless interfaces present (from /sys/class/net/*/wireless).
pub fn list_wifi_ifaces() -> Vec<String>;
/// Our own MAC on ifname.
pub fn mac_of(ifname: &str) -> anyhow::Result<crate::common::MacAddr>;
/// True when running with euid 0; UI surfaces a warning otherwise.
pub fn is_root() -> bool;
/// Stop NetworkManager (systemctl stop). Requires root.
pub fn stop_networkmanager() -> anyhow::Result<()>;
/// Start NetworkManager again (systemctl start); best-effort restore on exit.
pub fn start_networkmanager() -> anyhow::Result<()>;
/// True when the monitor vif `<ifname>mon` no longer exists (post-scan
/// restore check: remaining monitor vif → interface left in monitor mode).
pub fn monitor_gone(ifname: &str) -> bool;
// note: NetworkManager/wpa_supplicant interference is the caller's concern;
// expose `kill_interferers()` that runs NM radio off like airmon does NOT —
// instead just document required state.
```

## oui.rs (owner: ui)
MAC prefix → vendor lookup backed by CHECKED-IN snapshot files, one line
per entry: `HEX|Vendor` (uppercase hex prefix, `|`, vendor name truncated
to 32 chars; sorted ascending LC_ALL=C byte order, deduplicated BY PREFIX —
first vendor wins for historical re-registrations, e.g. 0001C8, 080030):
- `src/data/oui.txt`   — MA-L 24-bit  (6 hex chars), IEEE MA-L registry
  (`https://standards-oui.ieee.org/oui/oui.txt`, lines `XX-XX-XX   (hex)`)
- `src/data/oui28.txt` — MA-M 28-bit  (7 hex chars), IEEE MA-M registry
  (`.../oui28/mam.txt`: base `XX-XX-XX (hex)` line + `(base 16)` range
  line; key = base<<4 | range-top-nibble)
- `src/data/oui36.txt` — MA-S 36-bit  (9 hex chars), IEEE MA-S registry
  (`.../oui36/oui36.txt`, same pairing; key = base<<12 | range-top-12-bits)
Refresh by re-downloading and re-normalizing, never hand-edit rows.
Lookup is LONGEST-PREFIX-FIRST (MA-S → MA-M → MA-L): the sub-assignment
vendors sit under someone else's MA-L base, so specificity wins. Files are
compile-time data: `include_str!` + parsed once into sorted `LazyLock`
vecs, binary-searched — the binary
has no network or runtime-file dependency for lookups, and vendor strings
reflect the snapshot date, not live registrations.

```rust
/// Locally administered = first-byte U/L bit set (mac.0[0] & 0x02): the
/// randomized/rotated MACs modern stations send. These have no IEEE vendor;
/// the UI shows them as "random", not "unknown".
pub fn is_locally_administered(mac: &crate::common::MacAddr) -> bool;
/// Vendor for a MAC's prefix (longest-first MA-S → MA-M → MA-L); None for
/// locally-administered or unknown prefixes.
pub fn lookup(mac: &crate::common::MacAddr) -> Option<&'static str>;
```

## scanner.rs (owner: attacks)
```rust
pub struct ScannerConfig {
    pub ifname: String, pub freqs: Vec<u16>, pub dwell_ms: u32, pub rssi_floor: i8,
    pub pin: std::sync::Arc<crate::iface::ChannelPin>,
    /// Monitor interface's own MAC — deauth TX never trips the storm detector.
    pub own_mac: crate::common::MacAddr,
    /// BSSIDs of APs being user-deauthed right now (suppressed like own_mac).
    pub deauth_suppress: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<crate::common::MacAddr>>>,
    /// Shared pcap spool writer (linktype 127; raw frames WITH radiotap header).
    pub spool: Option<std::sync::Arc<std::sync::Mutex<crate::pcapout::PcapWriter>>>,
}
/// Blocking channel-hop passive scan. Sends Event::{ApUpdated,ApLost,
/// ClientUpdated,ChannelStats,ProbeObserved,DeauthAlert,Log} into `tx`;
/// returns when `stop` flips true.
pub fn run(cfg: ScannerConfig, tx: crossbeam_channel::Sender<Event>, stop: std::sync::Arc<std::sync::atomic::AtomicBool>) -> anyhow::Result<()>;
```
APs expire (ApLost) after 30 s silent; clients after 60 s. Clients learned
from data frames + probe requests; an observed deauth/disassoc flags the
target `connected=false` (any later frame flips it back). Deduplicate by
BSSID; keep best RSSI.

New SCANNER behaviors (W2):
- **Channel stats**: cumulative per-channel `(frames, beacons)` histogram,
  attributed by radiotap carrier freq (fallback: last-tuned freq), emitted
  as ONE `Event::ChannelStats` every 2 s.
- **Probe panel**: novel (client, ssid) probe requests emit
  `Event::ProbeObserved`; repeats within 60 s are deduped (state reaped on
  the expire pass).
- **Hidden SSID / AKM**: assoc/reassoc-req frames (`dot11::parse_assoc_req`)
  bind client→AP AND fill in an AP's empty ssid (emit-on-change ApUpdated);
  beacon/probe-resp `MgmtInfo.akms` populate `AccessPoint.akms` (changes are
  emit-on-change too).
- **Device correlation (MAC-randomization pairing)**: probe/assoc frames
  feed `GroupBook` (fingerprint + WPS UUID-E + probed-SSID set + sequence
  numbers — the same frame's `dot11::parse_probe_ident`/`parse_assoc_ident`
  + `seq_of` products). One `Event::ClientIdent { mac, group, confidence }`
  per pairing decision; groups live 15 min (outliving the 60 s client-row
  TTL so a rotated MAC that appears after the old row expired still lands
  in the same group). Key witness rules: UUID-E equal → Exact; fingerprint
  + shared probed SSID or seq continuation (delta 1..=32 within the 12-bit
  wrap) → Strong; fingerprint alone → Probable; fingerprint mismatch →
  never paired (except via UUID-E, which is matched before fingerprints so
  it survives a chain change). A MAC joins at most one live group and
  groups never merge post-hoc: a later-arriving bridge fingerprint does
  not rejoin groups that split early. Pairing runs BEFORE client creation
  so the creation event already carries `ident_group`/`ident_conf`.
- **Foreign-deauth detection**: ≥10 deauth/disassoc frames per
  (source, target) pair within a 10 s sliding window → one
  `Event::DeauthAlert`, then a 30 s per-pair cooldown. Frames sourced from
  `own_mac` or a BSSID in `deauth_suppress` (our own blasts carry the
  victim AP as transmitter) never count. Window logic is the pure
  `pub(crate) fn deauth_alert(&mut VecDeque<u64>, now)`.
- **Pcap spool**: when `cfg.spool` is set, every raw frame straight off the
  socket (radiotap included, linktype 127) is appended via the shared
  writer. The service (service.rs) picks the writer on `Cmd::StartScan`:
  `fresh_spool` → `pcapout::create` (truncate), else a NEW path →
  `pcapout::from_path_append`; same path + non-fresh REUSES the open
  writer. Open failure → one error log, scan runs spool-less. At runtime,
  3 consecutive append errors → one `Event::Log("pcap spool disabled: …")`
  and the spool is latched off for that scan.

Service-side `start_scan` runs an injection CANARY (wildcard probes →
expect probe responses) before spawning workers: mt76/mt7921e wedges its
monitor-TX path silently (send() succeeds, RX healthy, nothing radiates);
on failure the service reloads the driver via `iface::reset_driver` and
recreates the monitor vif, logging loudly either way. The UI additionally
marks deauth targets down optimistically (monitor TX never loops back to
the scanner socket) and sweeps client rows silent > 60 s as a backstop for
scanner restarts.

Service exit hygiene (W2): `Cmd::Deauth`/`Cmd::DeauthAll` workers register
their victim BSSIDs in `deauth_suppress` for their lifetime (scanner storm
detector suppression). `Cmd::StopNetworkManager` sets a flag; `stop_scan`
(and thus the shutdown tail) runs the restore-check — a surviving
`<if>mon` vif yields `Event::Error` with the exact `iw dev <if>mon del`
fix — and best-effort restarts NetworkManager (`Event::Log` on success)
when that flag is set.

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
/// `stop` is checked per round and breaks the blast cleanly.
/// Returns frames actually sent.
pub fn blast(sock: &RawSocket, ap: &MacAddr, target: &MacAddr,
             count: u32, tx: &crossbeam_channel::Sender<Event>,
             stop: &std::sync::atomic::AtomicBool) -> anyhow::Result<u64>;
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
(on `GpuCracker::try_new() -> Option`). FULL-PIPELINE kernel: the shader
does per candidate the HMAC key midstates (2 compressions), U1/U2 from
host-precomputed padded salt messages, the 4095-iteration chained HMAC
loop (registers only), and the verify EPILOGUE on-device (PTK-KCK HMAC +
EAPOL MIC compare, or PMKID compare — everything SHA1-family). The host
packs raw candidate bytes only (BE u32 words ×16) and reads back a
16-byte hit slot per batch — midstate upload + CPU MIC phases were the
pipeline's throughput ceiling (effective had run at ~1/3 of kernel-only).
Verify messages arrive PRE-PADDED in params (constant per run; padding
follows the implicit 64-byte HMAC pad prefix, bitlen = (64+len)*8).
Targets with AES-CMAC MIC (key_ver 3), frames < 99 B, or ESSIDs > 51 B
are NOT expressible in the shader: `gpu_verifiable()` routes them to
cpu_crack even when a GPU adapter exists (attack.rs). Fast path:
`create_shader_module_trusted(..., ShaderRuntimeChecks::unchecked())`
(static module; the tail guard `idx >= params.n` clamps partial batches).
Dispatch buffers + bind group live in a persistent 2-slot pool
(`KernelPool`); uploads are zero-copy (native-LE u32 slice, BE hosts fail
at compile time). The `pmk_out` entry point (same module) writes PMK rows
for the rainbow-table build. Measured on radv (RX 9060 XT, 108 VGPRs,
no spills): ~320k H/s effective ≈ kernel-only (was 135–190k pipelined /
240k kernel-only before the epilogue; hashcat on the same card: ~1.09
MH/s — remaining gap is shader codegen, benchmarked and documented in
dev/research; a 2-candidates/thread ILP interleave measured −9% and was
rejected: 144 VGPR cost outweighed dual-issue gains).
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
/// PMK sink for pure-CPU runs: every tried candidate's PMK is pushed to
/// the per-SSID cache (attack.rs supplies it; GPU runs NEVER get one —
/// no PMK readback is plumbed through the verify pipeline). The first
/// push error logs ONCE via the callback, then the sink self-disables.
pub struct CpuPmkSink;
impl CpuPmkSink {
    pub fn new(w: rainbow::TableWriter, log: Box<dyn FnMut(String) + Send>) -> Self;
    pub fn push(&mut self, pmk: &[u8; 32], word: &[u8]);
    /// Flush; entries appended by THIS sink.
    pub fn finish(self) -> std::io::Result<u64>;
}
/// cache_sink receives (pmk, word) per tried candidate (pure-CPU pmk
/// cache population; None anywhere else).
pub fn cpu_crack(target: &CrackTarget, words: &mut dyn Iterator<Item = Vec<u8>>,
                 progress: &mut dyn FnMut(u64, f64),
                 stop: &std::sync::Arc<std::sync::atomic::AtomicBool>,
                 cache_sink: Option<&mut CpuPmkSink>) -> Option<String>;
```
Benchmark note (attack.rs): `benchmark(seconds) -> (Option<f64>, f64)`
measures raw PBKDF2 throughput — GPU half batches 4096 fixed words
through `pmk_batch_gpu`, CPU half times `crypto::pmk` over 512-word
batches; the numbers feed the cracker-page crack-time estimator and
`Event::BenchmarkDone`.
Kernel algorithm: candidate wire format = password bytes packed BE into
16 u32 (zero pad; WPA passphrases ≤ 63 B never spill the HMAC key block).
U1/U2 message blocks (salt||INT32BE(1|2), padded) are constant per run
and precomputed host-side into params. SHA1 uses hashcat's minimal-op
round forms (Ch: `d ^ (b & (c ^ d))`; Maj: `(b & c) ^ (d & (b ^ c))`) and
the doubled-step (rotl-2) message schedule for t ≥ 32 — bit-identical,
shorter serial depth. t2[3]/t2[4] XOR accumulation is dropped (PMK needs
only t2[0..12] bytes). Batch 65536 candidates, workgroup 256 (swept
64/128/256; 256 consistently ~2% faster), 30 s dispatch timeout guard.
Correctness tests: GPU crack finds planted passphrases (handshake kv2 and
PMKID), rejects wrong candidates, PMK rows bit-exact vs crypto::pmk
(RFC 6070-anchored), key_ver 3 and >51 B ESSIDs route to CPU. GPU tests
run un-ignored; with no adapter they early-return Ok.

## wordlist.rs (owner: cracker)
```rust
/// Streaming iterator over a wordlist file (mmap not required; BufReader),
/// yielding trimmed 8..=63-byte candidates, counting progress.
pub fn open(path: &std::path::Path) -> anyhow::Result<Box<dyn Iterator<Item = Vec<u8>> + Send>>;
```

## attack.rs (owner: cracker) — attack modes + UI-side workers
Cracking is a **UI-process job, fully independent of the radio/capture
state**: candidates and the GPU need no privileges, so no capture
start/stop (or even service spawn) precondition exists. The UI selects an
`Attack`, `validate()`s it (fail-fast, no zombie run), then `spawn_crack`
starts the worker thread and returns its stop flag. Worker event contract
(one terminator always): progress via `CrackProgress`, then
`CrackFound`+`CrackStopped{found:true}` or `CrackStopped{found:false}`.
```rust
pub enum Attack { Wordlist(PathBuf), Rules { wordlist: PathBuf, rules: PathBuf },
    Hybrid { wordlist: PathBuf, charset: Vec<u8>, min: usize, max: usize },
    Bruteforce { charset: Vec<u8>, min: usize, max: usize, #[serde(default)] freq_order: bool }, Rainbow(PathBuf) }
impl Attack { pub fn describe(&self) -> String; pub fn validate(&self) -> anyhow::Result<()>; }
/// Charset presets unioned with the custom field (UI chips). SPECIAL is
/// only the common symbols; exotic bytes go into the custom field.
pub mod charset { pub const LOWER/UPPER/DIGITS/SPECIAL: &[u8]; pub fn compose(...) -> Vec<u8>; }
/// Odometer-order charset^len generator, clamped to WPA 8..=63; `space()` = total candidates.
/// freq_order permutes the charset by a password-frequency rank literal
/// (bijection: space size and seek indices unchanged).
pub struct BruteForce;
impl BruteForce { pub fn new(charset: Vec<u8>, min: usize, max: usize, freq_order: bool) -> anyhow::Result<Self>; pub fn space(&self) -> u128;
    /// O(1) jump to candidate index n (little-endian odometer math) — the resume path.
    pub fn seek(&mut self, n: u64); }
/// Hashcat-subset rules (`: l u c C t r d $X ^X [ ] sXY`; spaces separate ops,
/// `#` comments, blank lines skipped). Rule outputs outside 8..=63 are
/// filtered but STILL CONSUME their flattened index — resume stays exact.
pub fn parse_rules(path: &Path) -> anyhow::Result<Vec<Rule>>;
pub fn rule_count(path: &Path) -> anyhow::Result<u64>;
/// wordlist × rules, WORD-MAJOR/rule-minor: flattened index = word_idx*rules_len
/// + rule_idx, so resume is a plain skip_n over the stream.
pub struct RuleIter;
/// wordlist × append-charset ("hybrid"): word + charset^k for k in min..=max
/// (clamped 1..=4), rightmost-fastest odometer; candidates >63 B skipped after
/// consuming their index. Flattened index = word_idx*per_word + inner with
/// per_word = Σ|charset|^k; total = line_count(wordlist) × per_word (upper bound).
pub struct HybridIter;
impl HybridIter {
    pub fn new(words: Box<dyn Iterator<Item = Vec<u8>> + Send>, charset: Vec<u8>, min: usize, max: usize) -> anyhow::Result<Self>;
    pub fn validate(charset: &[u8], min: usize, max: usize) -> anyhow::Result<()>;
    pub fn per_word(&self) -> u64;
    /// Exact flattened-index resume (skip words + prime the odometer).
    pub fn seek_flat(&mut self, n: u64);
}
/// Drops candidates covered by the PMK cache consult (a miss proves they
/// are not the password); resume indices still refer to the RAW stream.
pub struct CacheSkipIter<I: Iterator<Item = Vec<u8>>>;
/// Rainbow run: precomputed PMKs, one PTK+MIC compare each, no PBKDF2.
pub fn rainbow_crack(target: &CrackTarget, entries: &mut dyn Iterator<Item = ([u8; 32], Vec<u8>)>,
                     progress: &mut dyn FnMut(u64, f64), stop: &Arc<AtomicBool>) -> Option<String>;
/// resume_from: skip/seek past that many leading candidates (flattened
/// index for rules/hybrid); progress events still count against the FULL
/// space (ETA stays meaningful). force_cpu pins the CPU backend and
/// DISABLES PMK-cache writes (headless CLI `--cpu`, side-effect-free).
/// Wordlist-family runs first consult the per-SSID PMK cache
/// (store::cache_file): hit → CrackFound+found-terminator with NO main run;
/// miss → Log "pmk cache: N entries, no hit — continuing …" and the main
/// iterator is CacheSkipIter-wrapped; unreadable cache → ONE Log, full run.
/// Pure-CPU main runs POPULATE the cache (gpu::CpuPmkSink via
/// rainbow::append_open); GPU runs never do.
pub fn spawn_crack(target_desc: String, target: CrackTarget, attack: Attack, resume_from: u64, tx: Sender<Event>, force_cpu: bool) -> Arc<AtomicBool>;
/// Build job: PMK-table from wordlist (GPU when available). Progress via
/// RainbowProgress; ALWAYS ends with exactly one RainbowBuilt (entries written).
pub fn spawn_rainbow_build(ssid: String, wordlist: PathBuf, out: PathBuf, tx: Sender<Event>) -> Arc<AtomicBool>;
/// Measured H/s for the crack-time estimator: GPU batches of 4096 via
/// pmk_batch_gpu (None without an adapter), CPU via crypto::pmk loop.
pub fn benchmark(seconds: u32) -> (Option<f64>, f64);
/// Background benchmark thread; exactly one Event::BenchmarkDone terminator
/// (a zeroed one follows the Error on spawn failure). Honors stop between batches.
pub fn spawn_benchmark(seconds: u32, tx: Sender<Event>) -> Arc<AtomicBool>;
```

## rainbow.rs (owner: cracker) — SSID-scoped PMK tables
"Rainbow" for WPA: PMK = PBKDF2(pass, essid) is SSID-bound, so a table is
reusable for every capture of one SSID. Text format, one entry per line:
`# wifilab-pmk v1 ssid=<essid>` header, then `<64-hex-pmk> <pass>`.
```rust
/// Returns header SSID (None when absent — MUST be refused by the caller
/// via check_ssid, PMKs compare-fail silently on the wrong SSID).
pub fn open(path: &Path) -> anyhow::Result<(Option<String>, Box<dyn Iterator<Item = ([u8; 32], Vec<u8>)> + Send>)>;
/// Fresh table with header; truncates. Parent directories are created
/// (the per-SSID cache lives in ~/wifilab/cache/, created on use).
pub fn create(path: &Path, ssid: &str) -> anyhow::Result<TableWriter>;
/// Per-SSID cache writer: missing/zero-length file → create-with-header;
/// existing file → header SSID MUST pass check_ssid (mismatch = Err, the
/// table is never poisoned by appends for another SSID), then open append.
pub fn append_open(path: &Path, ssid: &str) -> anyhow::Result<TableWriter>;
pub fn check_ssid(table_ssid: Option<&str>, target_ssid: &str) -> anyhow::Result<()>;
```

## store.rs — persistence (labels, captures, session, PMK cache, profiles)
PMK cache: `~/wifilab/cache/<ssid-hex>.pmk` (rainbow text format) —
`pub fn cache_dir() -> PathBuf` (data_dir()/cache, create_dir_all on use),
`pub fn cache_file(ssid: &str) -> PathBuf` (filename = lowercase hex of the
SSID bytes + `.pmk`). Profiles: `~/wifilab/profiles.json` —
```rust
pub struct CrackProfile { pub name: String, pub mode: String, pub wordlist: String, pub rules: Option<String> }
pub struct Profiles { pub profiles: Vec<CrackProfile>, pub recent_wordlists: Vec<String> }
pub fn load_profiles() -> anyhow::Result<Profiles>;   // missing/parse-err -> default (eprintln log, then fresh)
pub fn save_profiles(&Profiles) -> anyhow::Result<()>; // tmp+rename
pub fn remember_wordlist(&mut Profiles, path: &str);   // front-insert dedup, cap 5
```

## Crack session (store.rs) — resume after stop/crash
`~/wifilab/crack-session.json`: `{capture: StoredCapture, attack, done,
total}` — autosaved by the UI every ~2 s of progress (atomic tmp+rename,
so a crash cannot tear it), finalized on Stop, deleted on found/exhausted,
restored at startup and matched back to a loaded capture by value
equality. Wordlist/table resume re-opens and skips `done` candidates;
bruteforce `seek`s in O(1).
```rust
pub struct CrackSession { pub capture: StoredCapture, pub attack: Attack, pub done: u64, pub total: Option<u64> }
pub fn save_session(&CrackSession) -> anyhow::Result<()>;
pub fn load_session() -> anyhow::Result<Option<CrackSession>>;
pub fn clear_session() -> anyhow::Result<()>;
```

## pcapout.rs — libpcap capture-file writer (spool + export)
Standard libpcap (DLT) file. Global header and every per-packet record are
little-endian; recorded timestamps are wall-clock (`SystemTime`), lengths
are `incl_len == orig_len == frame.len()` (spool frames are the raw socket
read incl. radiotap header).
```rust
pub struct PcapWriter { /* BufWriter<File> */ }          // flushes on finish() and Drop
pub fn create(path: &Path) -> std::io::Result<PcapWriter>;          // truncate + global header
pub fn from_path_append(path: &Path) -> std::io::Result<PcapWriter>; // existing non-empty file: append, NO header rewrite; missing/empty: like create
impl PcapWriter { pub fn append(&mut self, frame: &[u8]) -> std::io::Result<()>; pub fn finish(&mut self) -> std::io::Result<()>; }
```
Writer field layout (all LE): magic `0xa1b2c3d4`, version 2.4, thiszone 0,
sigfigs 0, snaplen 65535, linktype 127 (`DLT_IEEE802_11_RADIO`).

## pcapin.rs — capture-file importer
`pub fn extract(path: &Path) -> anyhow::Result<Vec<common::ImportedCapture>>`
— the headless/CLI-capable entry point used by the UI Import button.
Importer guarantees:
- Both byte orders of the file magic are accepted (`0xa1b2c3d4` LE,
  `0xd4c3b2a1` BE); all other magics → error.
- Supported linktypes: 127 (`DLT_IEEE802_11_RADIO`, radiotap prefix stripped
  via `radiotap::strip`; malformed prefixes are skipped and counted) and 105
  (`DLT_IEEE802_11`, raw 802.11). Any other linktype → error naming the
  numeric linktype.
- Two in-memory passes: (1) beacons/probe-responses → bssid→essid map;
  (2) EAPOL frames → `parse_eapol` → `parse_eapol_key` → `handshake::Tracker`
  (progress events drained internally, never surfaced); M1-shaped keys are
  additionally scanned for PMKID KDEs (`pmkid::extract_pmkid`),
  yielding `ImportedCapture::Pmkid` with the observed station as `client`.
- essid-skip semantics: a capture (handshake or PMKID) whose AP's essid is
  not resolvable from the file's beacons/probe-responses is uncrackable
  (essid = PBKDF2 salt) and is skipped; skips are reported via
  `tracing::warn!`, not in the return value. `extract` therefore returns
  only crackable captures.
`pub(crate) fn frames(path: &Path) -> io::Result<(u32, Vec<Vec<u8>>)>`
returns (linktype, frame payloads) after global-header validation; packet
records with truncated payload → `UnexpectedEof`.

## cli.rs — headless `wifilab crack` subcommand
Clap subcommand on the main binary (`src/main.rs` `Commands::Crack`); runs
with NO UI, no radio, no root — `--privileged-worker` dispatch stays ahead
of it and is untouched. `main.rs` owns the derived `CrackArgs`/`CliMode`
clap structs and converts them 1:1 into the owned, clap-free
`cli::CliCrack` for testability.
```rust
pub struct CliCrack { pub capture: String, pub mode: String /* "wordlist"|"rules"|"bruteforce" */,
    pub wordlist: Option<String>, pub rules: Option<String>, pub min: usize, pub max: usize,
    pub hybrid: bool, pub lower: bool, pub upper: bool, pub digits: bool, pub special: bool,
    pub cpu: bool }
pub fn run_crack_cli(args: CliCrack, out: &mut dyn std::io::Write) -> i32;
```
Flags: `--capture` (required hc22000 file), `--mode wordlist|rules|bruteforce`
(default wordlist), `--wordlist` (required by wordlist/rules/hybrid),
`--rules` (required by rules), `--min 8` / `--max 12`, `--hybrid`
(wordlist × append-charset sweep; takes precedence over `--mode`),
`--lower/--upper/--digits/--special` charset chips — when ALL chips are
false the charset defaults to lower+digits. `--cpu` forces the CPU backend
(`spawn_crack(.., force_cpu: true)`).
Target rule: the capture file is read as text; each line is tried as
`crypto::parse_hc22000(line.strip_prefix("WPA*").unwrap_or(line))` (the
hashcat `WPA*` prefix is stripped because parse takes the bare form) and
the FIRST parseable line is the target — unparseable lines are skipped
silently; none parseable → `error: no crackable WPA* line in <path>` + exit 2.
Exit codes: 0 password found (`FOUND: <password>` on the sink), 1 keyspace
exhausted, 2 usage/IO error (unreadable capture, no crackable line, missing
wordlist-family file, `attack.validate()` failure, engine `Error` event).
Progress throttled to one `done/total @ H/s` line per 2 s; engine `Log`
lines pass through verbatim.
Cache semantics: consult-only intent lives in the ENGINE, not the CLI —
wordlist-family runs always CONSULT the per-SSID PMK cache
(`store::cache_file`). Writes: `--cpu` (force_cpu) disables the cache sink,
so a forced-CPU CLI run is fully side-effect-free. Without `--cpu` on a
GPU-less machine the pure-CPU fallback DOES append newly computed PMKs to
`~/wifilab/cache` (engine semantics) — later runs of the same SSID benefit.
Tests: `cli_crack_finds_fabricated` (fabricated-mic capture crackable by
the mock password → wordlist → exit 0, `FOUND:` on the sink; pinned
password constant must track ui/cracker.rs `MOCK_PASSWORD`),
`cli_crack_missing_files_exit_2` (both usage-error paths).
