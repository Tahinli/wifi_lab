//! Shared domain types — the contract between radio, attack, crypto and UI
//! layers, AND the wire format between the UI process and the privileged
//! service (`--privileged-worker` child): every type here (plus [`Cmd`])
//! serializes through `serde_json` lines. Signatures and field meanings are
//! FIXED; implementations must conform exactly. Times are `last_seen_ms`
//! (millis since the process-local epoch, see [`now_ms`]), RSSI in dBm.
//! Fields added after the wire format froze carry serde defaults so older
//! records deserialize losslessly (e.g. `ClientInfo.connected`, serde
//! default true).

use std::fmt;
use std::time::Instant;

use serde::{Deserialize, Serialize};

/// Process-local epoch: `now_ms` returns elapsed millis since the first
/// deref of this static. Every process has its own epoch — values are only
/// comparable within one process.
#[doc(hidden)]
static EPOCH: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);

/// Milliseconds since the process-local epoch; used for `last_seen_ms`
/// timestamps so they cross the UI/service JSON pipe (an `Instant` can't).
pub fn now_ms() -> u64 {
    EPOCH.elapsed().as_millis() as u64
}

/// 6-octet 802.11 MAC address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const BROADCAST: MacAddr = MacAddr([0xff; 6]);
    pub const ZERO: MacAddr = MacAddr([0; 6]);

    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xff; 6]
    }
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 1 == 1
    }
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 6]
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::str::FromStr for MacAddr {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        anyhow::ensure!(parts.len() == 6, "MAC needs 6 octets: {s}");
        let mut out = [0u8; 6];
        for (i, p) in parts.iter().enumerate() {
            out[i] = u8::from_str_radix(p, 16)?;
        }
        Ok(MacAddr(out))
    }
}

/// WLAN security suite derived from RSN/WPA IEs (or lack thereof).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Security {
    Open,
    Wep,
    /// WPAv1 (TKIP-era, legacy WPA IE).
    Wpa,
    /// WPA2-PSK (RSN, no SAE).
    Wpa2,
    /// WPA3 (RSN with SAE AKM) or WPA2/WPA3 transition mode.
    Wpa3,
}

impl Security {
    pub fn label(&self) -> &'static str {
        match self {
            Security::Open => "OPEN",
            Security::Wep => "WEP",
            Security::Wpa => "WPA",
            Security::Wpa2 => "WPA2",
            Security::Wpa3 => "WPA2/3",
        }
    }
}

/// Authentication key-management suites parsed from the RSN/WPA IE.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Akm {
    Psk,
    Sae,
    Owe,
    FtPsk,
    PskSha256,
    OneX,
    Other(u8),
}

impl Akm {
    pub fn label(self) -> &'static str {
        match self {
            Akm::Psk => "PSK",
            Akm::Sae => "SAE",
            Akm::Owe => "OWE",
            Akm::FtPsk => "FT-PSK",
            Akm::PskSha256 => "PSK-SHA256",
            Akm::OneX => "802.1X",
            Akm::Other(_) => "other",
        }
    }
}

/// A discovered access point. Live-updated by the scanner.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessPoint {
    pub bssid: MacAddr,
    pub ssid: String,
    pub channel: u8,
    pub security: Security,
    pub rssi_dbm: i8,
    pub beacons: u64,
    /// Millis since the process-local epoch ([`now_ms`]) of the last frame
    /// seen from this AP. Age display = `now_ms() - last_seen_ms`.
    pub last_seen_ms: u64,
    /// AKM suites advertised in the RSN/WPA IE; empty = unknown (old peers,
    /// non-RSN APs).
    #[serde(default)]
    pub akms: Vec<Akm>,
}

/// A discovered client station.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientInfo {
    pub mac: MacAddr,
    /// BSSID of the AP this station is talking to, if determinable.
    pub ap: Option<MacAddr>,
    pub rssi_dbm: i8,
    pub frames: u64,
    /// Millis since the process-local epoch ([`now_ms`]) of the last frame
    /// seen from this station.
    pub last_seen_ms: u64,
    /// Station liveness: true while the station is active/associated; the
    /// scanner flips it false when it observes a deauth/disassoc affecting
    /// the station, and any later frame from the station flips it back
    /// true. Serde default is true so pre-field wire records deserialize
    /// as connected.
    #[serde(default = "crate::common::default_true")]
    pub connected: bool,
    /// MAC-randomization pairing: device-group id from the scanner
    /// (`Event::ClientIdent`), when this MAC was correlated.
    #[serde(default)]
    pub ident_group: Option<u64>,
    #[serde(default)]
    pub ident_conf: Option<IdentConfidence>,
}

/// Serde `default` for fields whose absent wire value means `true`
/// ([`ClientInfo::connected`]).
pub fn default_true() -> bool {
    true
}

/// A complete, crackable WPA 4-way handshake capture (M1+M2 minimum).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeCapture {
    pub ap: MacAddr,
    pub client: MacAddr,
    pub essid: String,
    pub anonce: [u8; 32],
    pub snonce: [u8; 32],
    mic: [u8; 16],
    /// Full EAPOL-Key frame payload (starting at the EAPOL version byte) of
    /// message 2, with the MIC field NOT zeroed (zeroing happens in crypto).
    pub eapol_m2: Vec<u8>,
    /// RSN key-info version: 1, 2 (HMAC-SHA1 MIC) or 3 (AES-CMAC MIC).
    pub key_ver: u8,
}

impl HandshakeCapture {
    pub fn mic(&self) -> &[u8; 16] {
        &self.mic
    }
}

impl HandshakeCapture {
    pub fn new(
        ap: MacAddr,
        client: MacAddr,
        essid: String,
        anonce: [u8; 32],
        snonce: [u8; 32],
        mic: [u8; 16],
        eapol_m2: Vec<u8>,
        key_ver: u8,
    ) -> Self {
        Self {
            ap,
            client,
            essid,
            anonce,
            snonce,
            mic,
            eapol_m2,
            key_ver,
        }
    }
}

/// A PMKID capture (clientless attack result).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PmkidCapture {
    pub ap: MacAddr,
    pub client: MacAddr, // the station we impersonated (our MAC)
    pub essid: String,
    pub pmkid: [u8; 16],
}

/// Cumulative per-channel frame counters (scanner → UI snapshot).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChannelStat {
    pub channel: u8,
    pub frames: u64,
    pub beacons: u64,
}

/// One observed probe request (client asking for a network).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProbeInfo {
    pub client: MacAddr,
    /// SSID of the probe; `None` for broadcast/wildcard probes.
    pub ssid: Option<String>,
    pub rssi_dbm: i8,
    /// Millis since the process-local epoch ([`now_ms`]).
    pub at_ms: u64,
}

/// Strength of a MAC-randomization pairing decision ([`Event::ClientIdent`]).
/// Ordered weakest→strongest; UI displays it as `?`/`~`/`=` per `label()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IdentConfidence {
    /// Only the ordered-IE fingerprint matched — driver-class witness.
    Probable,
    /// Fingerprint match plus a per-frame witness: shared probed SSID or
    /// uninterrupted 802.11 sequence numbers across the rotation.
    Strong,
    /// WPS UUID-E matched — the device identifies itself.
    Exact,
}

impl IdentConfidence {
    pub fn label(self) -> &'static str {
        match self {
            IdentConfidence::Probable => "?",
            IdentConfidence::Strong => "~",
            IdentConfidence::Exact => "=",
        }
    }
}

/// Which of the two capture kinds was imported from a file (store::StoredCapture
/// stays in store.rs; common must not depend on store).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ImportedCapture {
    Handshake(Box<HandshakeCapture>),
    Pmkid(PmkidCapture),
}

/// Events flowing from worker threads to the UI. In the real architecture
/// the privileged service serializes them as `serde_json` lines on the
/// child's stdout; in mock mode a thread pushes them onto a
/// `crossbeam_channel::Sender<Event>` directly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Event {
    ApUpdated(AccessPoint),
    ApLost(MacAddr),
    ClientUpdated(ClientInfo),
    /// Station silent past the scanner's client-expiry window — the UI
    /// drops it from the clients table.
    ClientLost(MacAddr),
    /// Progress while collecting 4-way messages.
    HandshakeProgress {
        ap: MacAddr,
        client: MacAddr,
        /// Bitmask of collected messages: bit0=M1, bit1=M2, bit2=M3, bit3=M4.
        have: u8,
    },
    HandshakeComplete(Box<HandshakeCapture>),
    PmkidCaptured(PmkidCapture),
    /// Count of deauth/disassoc frames actually written to the wire.
    DeauthSent { ap: MacAddr, target: MacAddr, count: u64 },
    /// Candidates checked so far (`done`), current throughput (`hps`),
    /// and the worst-case candidate total (`total`, when the attack
    /// mode's space is countable) of a running crack job. Worst-case
    /// remaining time = (total - done) / hps.
    CrackProgress { done: u64, hps: f64, total: Option<u64> },
    /// A crack job recovered the passphrase.
    CrackFound { password: String },
    /// The active crack job ended: `found` distinguishes success from
    /// exhaustion/user-stop (emitted after [`Event::CrackFound`] too).
    CrackStopped { found: bool },
    /// Throughput of a rainbow-table build job (PMKs written so far);
    /// `total` is the wordlist's line count (worst-case table size).
    RainbowProgress { done: u64, hps: f64, total: Option<u64> },
    /// A rainbow-table build job ended (always exactly one; `entries` is
    /// what actually landed in `path`, 0 on failure).
    RainbowBuilt { path: String, entries: u64 },
    Log(String),
    Error(String),
    /// Cumulative per-channel counters snapshot (emitted every ~2 s).
    ChannelStats(Vec<ChannelStat>),
    /// A novel probe request was observed.
    ProbeObserved(ProbeInfo),
    /// Deauth/disassoc storm detected on a (source, target) pair that we
    /// did not cause — a foreign deauth attack in progress.
    DeauthAlert {
        source: MacAddr,
        target: MacAddr,
        count: u32,
    },
    /// A capture was imported from an external file (pcap / hc22000).
    CaptureImported(ImportedCapture),
    /// `mac` was correlated with a device group (MAC-randomization pairing):
    /// every MAC witnessed on the same physical radio shares `group`.
    ClientIdent {
        mac: MacAddr,
        group: u64,
        confidence: IdentConfidence,
    },
    /// Crack-speed benchmark finished.
    BenchmarkDone { gpu_hps: Option<f64>, cpu_hps: f64 },
}

/// Channel list for hopper: all enabled 2.4 GHz + 5 GHz UNII channels of the
/// lab card (keep conservative, driver validates anyway).
pub const HOP_CHANNELS_24: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
pub const HOP_CHANNELS_5: &[u8] = &[36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128];

/// 2.4 GHz channel → carrier frequency (MHz).
pub fn freq_of_channel(ch: u8) -> Option<u16> {
    match ch {
        1..=13 => Some(2407 + 5 * ch as u16),
        14 => Some(2484),
        36..=173 => Some(5000 + 5 * ch as u16),
        _ => None,
    }
}

/// Default hop list as FREQUENCIES (MHz): every 2.4 GHz channel, the full
/// TR-legal 5 GHz span (incl. 132/136/140 which plain channel lists often
/// miss), and the 6 GHz PSC channels (6, 22, 38, 54, 70, 86 =
/// 5980/6060/6140/6220/6300/6380 MHz) — phone hotspots increasingly land
/// on 6 GHz and are invisible to channel-lists that omit it.
pub const HOP_FREQS_ALL: &[u16] = &[
    // 2.4 GHz ch 1..13
    2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447, 2452, 2457, 2462, 2467, 2472,
    // 5 GHz ch 36..64 and 100..140
    5180, 5200, 5220, 5240, 5260, 5280, 5300, 5320, 5500, 5520, 5540, 5560, 5580, 5600, 5620,
    5640, 5660, 5680, 5700,
    // 6 GHz: ONLY the phy-advertised 20 MHz channel grid (5955 + 20n,
    // ch 1/5/9/…/85). PSC channel centers (5980/6060/…) are NOT advertised
    // by iwlwifi and the kernel rejects them with "Unknown channel".
    5955, 5975, 5995, 6015, 6035, 6055, 6075, 6095, 6115, 6135, 6155, 6175, 6195, 6215, 6235,
    6255, 6275, 6295, 6315, 6335, 6355, 6375, 6395, 6415,
];

/// Commands the UI process sends to the privileged service
/// (`--privileged-worker` child), serialized as one `serde_json` line each
/// on the child's stdin.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Cmd {
    /// Switch `ifname` to monitor mode and start the channel-hopping
    /// scanner. `ifname` is saved as the interface to restore on
    /// StopScan/Shutdown.
    StartScan {
        ifname: String,
        /// Optional static channel list (diagnostics: park on one channel
        /// instead of hopping). `None`/empty = full hop list.
        #[serde(default)]
        channels: Option<Vec<u8>>,
        /// Pcap spool file for the scan: every received raw frame (with
        /// radiotap header) is appended to it. `None` = no spooling.
        #[serde(default)]
        spool: Option<std::path::PathBuf>,
        /// Truncate the spool file on scan start (`false` = append if it
        /// exists). UI sets `true` on a fresh scan from toggle_monitor,
        /// `false` when re-parking channels mid-scan.
        #[serde(default)]
        fresh_spool: bool,
    },
    /// Stop the scanner, restore managed mode.
    StopScan,
    /// Blast `count` deauth rounds per `(bssid, channel)` entry at
    /// `target` (broadcast allowed). Multiple entries cover dual-band
    /// networks: the worker walks the list sequentially (one channel at a
    /// time is all a single radio can do).
    Deauth {
        aps: Vec<(MacAddr, u8)>,
        target: MacAddr,
        count: u32,
    },
    /// Deauth every client of one AP at once: pins the channel, blasts
    /// `count` rounds at each target in `targets`, then one broadcast
    /// blast. `ap` is also recorded so the service's foreign-deauth
    /// detector suppresses its own frames.
    DeauthAll {
        ap: MacAddr,
        channel: u8,
        targets: Vec<MacAddr>,
        count: u32,
    },
    /// Clientless PMKID grab against `ap`.
    Pmkid {
        ap: MacAddr,
        channel: u8,
        essid: String,
    },
    /// Track 4-way handshakes of every BSSID in `targets` (dual-band
    /// networks send the exchange on whichever band the client chose — the
    /// parked SCANNER hops the union of channels, so a single listen
    /// covers all bands). One channel → the worker pins it itself.
    CaptureHs {
        targets: Vec<(MacAddr, u8)>,
        essid: String,
    },
    /// Stop NetworkManager/wpa_supplicant so they stop pinning the radio.
    StopNetworkManager,
    /// Stop all workers, restore the interface, exit the service.
    Shutdown,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ap_obj() -> AccessPoint {
        AccessPoint {
            bssid: MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            ssid: "parafin".into(),
            channel: 6,
            security: Security::Wpa2,
            rssi_dbm: -42,
            beacons: 7,
            last_seen_ms: 123_456,
            akms: vec![Akm::Psk],
        }
    }

    fn client_obj() -> ClientInfo {
        ClientInfo {
            mac: MacAddr([0x11; 6]),
            ap: Some(MacAddr([0xaa; 6])),
            rssi_dbm: -55,
            frames: 3,
            last_seen_ms: 654_321,
            connected: true,
            ident_group: Some(7),
            ident_conf: Some(IdentConfidence::Strong),
        }
    }

    fn handshake_obj() -> HandshakeCapture {
        HandshakeCapture::new(
            MacAddr([1; 6]),
            MacAddr([2; 6]),
            "labnet".into(),
            [3u8; 32],
            [4u8; 32],
            [5u8; 16],
            vec![6u8; 99],
            2,
        )
    }

    fn pmkid_obj() -> PmkidCapture {
        PmkidCapture {
            ap: MacAddr([7; 6]),
            client: MacAddr([8; 6]),
            essid: "corp".into(),
            pmkid: [9u8; 16],
        }
    }

    fn roundtrip<T>(value: &T) -> T
    where
        T: Serialize + for<'de> Deserialize<'de> + std::fmt::Debug,
    {
        let json = serde_json::to_string(value).expect("serialize");
        serde_json::from_str(&json).unwrap_or_else(|e| panic!("deserialize {json}: {e}"))
    }

    #[test]
    fn now_ms_is_monotonic_and_ms_scale() {
        let a = now_ms();
        let b = now_ms();
        assert!(b >= a);
        // Same-process sanity: first deref happens at most a few hundred ms
        // before this test runs (process start); elapsed must stay small.
        assert!(a < 120_000, "process-local epoch ms implausibly large: {a}");
    }

    #[test]
    fn event_json_roundtrips() {
        let cases: Vec<Event> = vec![
            Event::ApUpdated(ap_obj()),
            Event::ApLost(MacAddr::BROADCAST),
            Event::ClientUpdated(client_obj()),
            Event::HandshakeProgress {
                ap: MacAddr([1; 6]),
                client: MacAddr([2; 6]),
                have: 0b1011,
            },
            Event::HandshakeComplete(Box::new(handshake_obj())),
            Event::PmkidCaptured(pmkid_obj()),
            Event::DeauthSent {
                ap: MacAddr([1; 6]),
                target: MacAddr::BROADCAST,
                count: 64,
            },
            Event::CrackProgress { done: 1000, hps: 1234.5, total: Some(5000) },
            Event::CrackFound {
                password: "hunter2".into(),
            },
            Event::CrackStopped { found: true },
            Event::CrackStopped { found: false },
            Event::RainbowProgress { done: 42, hps: 9.5, total: None },
            Event::RainbowBuilt {
                path: "/tmp/t.pmk".into(),
                entries: 7,
            },
            Event::Log("hello".into()),
            Event::Error("boom".into()),
            Event::ChannelStats(vec![
                ChannelStat { channel: 6, frames: 1234, beacons: 56 },
                ChannelStat { channel: 36, frames: 78, beacons: 9 },
            ]),
            Event::ProbeObserved(ProbeInfo {
                client: MacAddr([0x42; 6]),
                ssid: Some("HOME-WIFI".into()),
                rssi_dbm: -61,
                at_ms: 987_654,
            }),
            Event::DeauthAlert {
                source: MacAddr([0xde; 6]),
                target: MacAddr::BROADCAST,
                count: 17,
            },
            Event::CaptureImported(ImportedCapture::Handshake(Box::new(handshake_obj()))),
            Event::ClientIdent {
                mac: MacAddr([0x02, 0xa0, 0xb1, 0xc2, 0xd3, 0xe4]),
                group: 42,
                confidence: IdentConfidence::Exact,
            },
            Event::BenchmarkDone { gpu_hps: Some(1_250_000.0), cpu_hps: 310_000.0 },
        ];
        for ev in &cases {
            let json = serde_json::to_string(ev).expect("serialize");
            let back: Event = serde_json::from_str(&json)
                .unwrap_or_else(|e| panic!("deserialize {json}: {e}"));
            assert_eq!(format!("{ev:?}"), format!("{back:?}"));
        }
    }

    #[test]
    fn handshake_json_roundtrip_is_lossless() {
        // PartialEq on the struct itself (not just Debug) — the Box in
        // Event::HandshakeComplete must survive the wire.
        let ev = Event::HandshakeComplete(Box::new(handshake_obj()));
        let json = serde_json::to_string(&ev).expect("serialize");
        let Event::HandshakeComplete(back) =
            serde_json::from_str(&json).expect("deserialize")
        else {
            panic!("variant changed shape: {json}");
        };
        assert_eq!(*back, handshake_obj());
        let pm = Event::PmkidCaptured(pmkid_obj());
        let json = serde_json::to_string(&pm).expect("serialize");
        let Event::PmkidCaptured(back) = serde_json::from_str(&json).expect("deserialize")
        else {
            panic!("variant changed shape: {json}");
        };
        assert_eq!(back, pmkid_obj());
    }

    #[test]
    fn cmd_json_roundtrips() {
        let cases: Vec<Cmd> = vec![
            Cmd::StartScan {
                ifname: "wlp14s0".into(),
                channels: None,
                spool: None,
                fresh_spool: false,
            },
            Cmd::StopScan,
            Cmd::Deauth {
                aps: vec![(MacAddr([1; 6]), 6)],
                target: MacAddr::BROADCAST,
                count: 16,
            },
            Cmd::Pmkid {
                ap: MacAddr([2; 6]),
                channel: 36,
                essid: "corp-wpa3".into(),
            },
            Cmd::CaptureHs {
                targets: vec![(MacAddr([3; 6]), 11), (MacAddr([4; 6]), 60)],
                essid: "coffeeshop".into(),
            },
            Cmd::StopNetworkManager,
            Cmd::Shutdown,
            Cmd::DeauthAll {
                ap: MacAddr([5; 6]),
                channel: 44,
                targets: vec![MacAddr([6; 6]), MacAddr([7; 6])],
                count: 8,
            },
        ];
        for cmd in &cases {
            let json = serde_json::to_string(cmd).expect("serialize");
            let back: Cmd = serde_json::from_str(&json)
                .unwrap_or_else(|e| panic!("deserialize {json}: {e}"));
            assert_eq!(*cmd, back);
        }
        assert_eq!(roundtrip(&cases[0]), cases[0]);
    }
}
