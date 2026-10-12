//! Mock backend: fabricates the event stream the real radio/attack/cracker
//! threads will eventually produce. Delete this module — and the env-flag
//! branch in `run_app` — when the backend lands.

use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::Sender;

use crate::common::{
    AccessPoint, ClientInfo, Event, HandshakeCapture, MacAddr, PmkidCapture, Security,
};

/// Salted deterministic PRNG (xorshift64) — no rand crate, values only need
/// to *look* like radio noise.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// Inclusive low, exclusive high.
    fn below(&mut self, high: u64) -> u64 {
        self.next() % high.max(1)
    }
}

/// The mock interface, also what the header picker offers.
pub const MOCK_IFACE: &str = "wlp14s0";

pub const MOCK_BSSID: MacAddr = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

pub const MOCK_CLIENTS: [MacAddr; 4] = [
    MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
    MacAddr([0x22, 0x33, 0x44, 0x55, 0x66, 0x77]),
    MacAddr([0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
    MacAddr([0x44, 0x55, 0x66, 0x77, 0x88, 0x99]),
];

fn seed_aps() -> Vec<AccessPoint> {
    let now = Instant::now();
    let ap = |mac: [u8; 6], ssid: &str, channel, security, rssi| AccessPoint {
        bssid: MacAddr(mac),
        ssid: ssid.to_string(),
        channel,
        security,
        rssi_dbm: rssi,
        beacons: 200,
        last_seen: now,
    };
    vec![
        ap([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], "parafin", 6, Security::Wpa2, -42),
        ap([0x02, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e], "labnet", 1, Security::Wpa2, -55),
        ap([0x02, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e], "coffeeshop", 11, Security::Wpa2, -68),
        ap([0x02, 0xff, 0xee, 0xdd, 0xcc, 0xbb], "corp-wpa3", 36, Security::Wpa3, -61),
        ap([0x02, 0xde, 0xad, 0xbe, 0xef, 0x00], "legacy-prn", 3, Security::Wep, -80),
        ap([0x02, 0x00, 0x11, 0x22, 0x33, 0x44], "open-wifi", 6, Security::Open, -72),
    ]
}

fn seed_clients() -> Vec<ClientInfo> {
    let now = Instant::now();
    let cl = |mac: MacAddr, ap: MacAddr, rssi| ClientInfo {
        mac,
        ap: Some(ap),
        rssi_dbm: rssi,
        frames: 40,
        last_seen: now,
    };
    vec![
        cl(MOCK_CLIENTS[0], MOCK_BSSID, -44),
        cl(MOCK_CLIENTS[1], MOCK_BSSID, -51),
        cl(MOCK_CLIENTS[2], MacAddr([0x02, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]), -60),
        cl(MOCK_CLIENTS[3], MacAddr([0x02, 0xff, 0xee, 0xdd, 0xcc, 0xbb]), -63),
    ]
}

/// Deterministic filler byte for fabricated crypto material.
fn fill(byte: u64) -> u8 {
    (byte % 251) as u8
}

/// Fabricate a syntactically valid-looking WPA1/WPA2 capture (dummy nonces,
/// dummy MIC, dummy M2 EAPOL frame). The cracker would reject these, but the
/// UI only displays and exports them.
pub fn fabricate_handshake(ap: MacAddr, client: MacAddr, essid: &str, salt: u64) -> HandshakeCapture {
    let mut anonce = [0u8; 32];
    let mut snonce = [0u8; 32];
    let mut mic = [0u8; 16];
    let mut rng = Rng(salt | 1);
    for i in 0..32 {
        anonce[i] = fill(rng.next() + i as u64);
        snonce[i] = fill(rng.next() + 7 * i as u64);
    }
    for i in 0..16 {
        mic[i] = fill(rng.next() + 11 * i as u64);
    }
    // EAPOL v1, type Key, 95-byte key descriptor + empty key data: laid out
    // so the exporter's MIC-field offset (81..97) lands inside real bytes.
    let mut eapol_m2 = vec![0u8; 4 + 95];
    eapol_m2[0] = 1; // EAPOL version
    eapol_m2[1] = 3; // type: Key
    eapol_m2[2] = 0;
    eapol_m2[3] = 95; // length
    eapol_m2[4] = 2; // descriptor: RSN
    eapol_m2[5] = 0x01; // key info: M2, pairwise, MIC set
    eapol_m2[6] = 0x0a;
    let mut rng = Rng(salt ^ 0x5a5a);
    for b in eapol_m2.iter_mut().skip(7) {
        *b = fill(rng.next());
    }
    // SNonce rides at key-descriptor offset 13 (EAPOL offset 17).
    eapol_m2[17..17 + 32].copy_from_slice(&snonce);
    // MIC field at EAPOL offset 81..97.
    eapol_m2[81..97].copy_from_slice(&mic);
    HandshakeCapture::new(ap, client, essid.to_string(), anonce, snonce, mic, eapol_m2, 2)
}

/// Fabricate a PMKID capture against `ap`, impersonating `client`.
pub fn fabricate_pmkid(ap: MacAddr, client: MacAddr, essid: &str, salt: u64) -> PmkidCapture {
    let mut pmkid = [0u8; 16];
    let mut rng = Rng(salt ^ 0xa5a5);
    for b in &mut pmkid {
        *b = fill(rng.next());
    }
    PmkidCapture {
        ap,
        client,
        essid: essid.to_string(),
        pmkid,
    }
}

/// Spawn the mock generator thread. Sends forever until the channel closes
/// (app exit) — error sends are simply dropped.
pub fn spawn_mock(tx: Sender<Event>) {
    thread::Builder::new()
        .name("wifilab-mock".into())
        .spawn(move || run(tx))
        .expect("mock thread");
}

fn run(tx: Sender<Event>) {
    let _ = tx.send(Event::Log(format!(
        "mock: scanning on {MOCK_IFACE} (6 APs, 4 clients)"
    )));

    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut aps = seed_aps();
    let mut clients = seed_clients();
    for ap in &aps {
        let _ = tx.send(Event::ApUpdated(ap.clone()));
    }
    for cl in &clients {
        let _ = tx.send(Event::ClientUpdated(cl.clone()));
    }

    let started = Instant::now();
    let mut stage = 0usize;
    const LOG_LINES: &[&str] = &[
        "hop: ch 1 → ch 6",
        "probe request from 11:22:33:44:55:66 (\"labnet\")",
        "hop: ch 6 → ch 11",
        "beacon: corp-wpa3 on ch 36 (SAE)",
        "hop: ch 36 → ch 44",
        "data frame burst on parafin (297 fps)",
        "probe response coffeeshop (WPA2-PSK)",
    ];

    loop {
        thread::sleep(Duration::from_millis(200));
        let t = started.elapsed().as_secs_f32();
        let now = Instant::now();

        // RSSI drift + beacon/frame counters on every tick.
        for ap in &mut aps {
            ap.rssi_dbm = (ap.rssi_dbm + (rng.below(5) as i8 - 2)).clamp(-90, -30);
            ap.beacons += rng.below(3);
            ap.last_seen = now;
            let _ = tx.send(Event::ApUpdated(ap.clone()));
        }
        for cl in &mut clients {
            cl.rssi_dbm = (cl.rssi_dbm + (rng.below(3) as i8 - 1)).clamp(-90, -30);
            cl.frames += rng.below(12);
            cl.last_seen = now;
            let _ = tx.send(Event::ClientUpdated(cl.clone()));
        }

        // Milestones, roughly one per few seconds.
        let milestone_at = |stage: usize| t >= [2.0, 5.0, 8.0, 9.0, 11.0, 14.0][stage];
        while stage < 4 && milestone_at(stage) {
            match stage {
                0 => {
                    let _ = tx.send(Event::Log(format!(
                        "locking onto parafin ({MOCK_BSSID}, ch 6)"
                    )));
                }
                1 => {
                    let _ = tx.send(Event::HandshakeProgress {
                        ap: MOCK_BSSID,
                        client: MOCK_CLIENTS[0],
                        have: 0b0001,
                    });
                }
                2 => {
                    let _ = tx.send(Event::HandshakeProgress {
                        ap: MOCK_BSSID,
                        client: MOCK_CLIENTS[0],
                        have: 0b0011,
                    });
                }
                3 => {
                    let cap =
                        fabricate_handshake(MOCK_BSSID, MOCK_CLIENTS[0], "parafin", 0x1234_5678);
                    let _ = tx.send(Event::HandshakeComplete(Box::new(cap)));
                    stage += 1;
                    break;
                }
                _ => unreachable!(),
            }
            stage += 1;
        }

        if stage == 4 && t >= 14.0 {
            let cap = fabricate_pmkid(
                MacAddr([0x02, 0xff, 0xee, 0xdd, 0xcc, 0xbb]),
                MOCK_CLIENTS[3],
                "corp-wpa3",
                0xdead_beef,
            );
            let _ = tx.send(Event::PmkidCaptured(cap));
            stage += 1;
        }

        if stage >= 5 && (rng.next() % 20 == 0) {
            let _ = tx.send(Event::Log(format!(
                "{}",
                LOG_LINES[(rng.below(LOG_LINES.len() as u64)) as usize]
            )));
        }

        // Occasionally nudge deauth stats so the log feels alive.
        if stage >= 5 && t > 20.0 && rng.next() % 40 == 0 {
            let _ = tx.send(Event::DeauthSent {
                ap: MOCK_BSSID,
                target: MOCK_CLIENTS[1],
                count: 8,
            });
        }
    }
}
