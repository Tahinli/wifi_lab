//! Shared domain types — the contract between radio, attack, crypto and UI
//! layers, AND the wire format between the UI process and the privileged
//! service (`--privileged-worker` child): every type here (plus [`Cmd`])
//! serializes through `serde_json` lines. Signatures and field meanings are
//! FIXED; implementations must conform exactly. Times are `last_seen_ms`
//! (millis since the process-local epoch, see [`now_ms`]), RSSI in dBm.

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

/// Events flowing from worker threads to the UI. In the real architecture
/// the privileged service serializes them as `serde_json` lines on the
/// child's stdout; in mock mode a thread pushes them onto a
/// `crossbeam_channel::Sender<Event>` directly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Event {
    ApUpdated(AccessPoint),
    ApLost(MacAddr),
    ClientUpdated(ClientInfo),
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
    /// Candidates checked so far (`done`) and current throughput (`hps`)
    /// of a running crack job.
    CrackProgress { done: u64, hps: f64 },
    /// A crack job recovered the passphrase.
    CrackFound { password: String },
    /// The active crack job ended: `found` distinguishes success from
    /// exhaustion/user-stop (emitted after [`Event::CrackFound`] too).
    CrackStopped { found: bool },
    Log(String),
    Error(String),
}

/// Channel list for hopper: all enabled 2.4 GHz + 5 GHz UNII channels of the
/// lab card (keep conservative, driver validates anyway).
pub const HOP_CHANNELS_24: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
pub const HOP_CHANNELS_5: &[u8] = &[36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128];

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
    },
    /// Stop the scanner, restore managed mode.
    StopScan,
    /// Blast `count` deauth rounds at `target` (broadcast allowed) from
    /// `ap`, after tuning to `channel`.
    Deauth {
        ap: MacAddr,
        target: MacAddr,
        channel: u8,
        count: u32,
    },
    /// Clientless PMKID grab against `ap`.
    Pmkid {
        ap: MacAddr,
        channel: u8,
        essid: String,
    },
    /// Park on `ap`'s channel and track its 4-way handshakes.
    CaptureHs {
        ap: MacAddr,
        channel: u8,
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
        }
    }

    fn client_obj() -> ClientInfo {
        ClientInfo {
            mac: MacAddr([0x11; 6]),
            ap: Some(MacAddr([0xaa; 6])),
            rssi_dbm: -55,
            frames: 3,
            last_seen_ms: 654_321,
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
            Event::CrackProgress { done: 1000, hps: 1234.5 },
            Event::CrackFound {
                password: "hunter2".into(),
            },
            Event::CrackStopped { found: true },
            Event::CrackStopped { found: false },
            Event::Log("hello".into()),
            Event::Error("boom".into()),
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
            },
            Cmd::StopScan,
            Cmd::Deauth {
                ap: MacAddr([1; 6]),
                target: MacAddr::BROADCAST,
                channel: 6,
                count: 16,
            },
            Cmd::Pmkid {
                ap: MacAddr([2; 6]),
                channel: 36,
                essid: "corp-wpa3".into(),
            },
            Cmd::CaptureHs {
                ap: MacAddr([3; 6]),
                channel: 11,
                essid: "coffeeshop".into(),
            },
            Cmd::StopNetworkManager,
            Cmd::Shutdown,
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
