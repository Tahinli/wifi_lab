//! Shared domain types — the contract between radio, attack, crypto and UI
//! layers. Signatures and field meanings here are FIXED; implementations must
//! conform exactly. All times are `std::time::Instant`, RSSI in dBm.

use std::fmt;
use std::time::Instant;

/// 6-octet 802.11 MAC address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug)]
pub struct AccessPoint {
    pub bssid: MacAddr,
    pub ssid: String,
    pub channel: u8,
    pub security: Security,
    pub rssi_dbm: i8,
    pub beacons: u64,
    pub last_seen: Instant,
}

/// A discovered client station.
#[derive(Clone, Debug)]
pub struct ClientInfo {
    pub mac: MacAddr,
    /// BSSID of the AP this station is talking to, if determinable.
    pub ap: Option<MacAddr>,
    pub rssi_dbm: i8,
    pub frames: u64,
    pub last_seen: Instant,
}

/// A complete, crackable WPA 4-way handshake capture (M1+M2 minimum).
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
pub struct PmkidCapture {
    pub ap: MacAddr,
    pub client: MacAddr, // the station we impersonated (our MAC)
    pub essid: String,
    pub pmkid: [u8; 16],
}

/// Events flowing from worker threads (scanner/capture/attacks/cracker) to
/// the UI over a `crossbeam_channel::Sender<Event>`.
#[derive(Clone, Debug)]
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
