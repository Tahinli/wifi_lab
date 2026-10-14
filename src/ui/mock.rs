//! Mock backend: fabricates the event stream the real radio/attack/cracker
//! threads will eventually produce. Delete this module — and the env-flag
//! branch in `run_app` — when the backend lands.

use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::Sender;

use crate::common::{
    AccessPoint, Akm, ChannelStat, ClientInfo, Event, HandshakeCapture, MacAddr, PmkidCapture,
    ProbeInfo, Security, now_ms,
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

/// Locally-administered MACs the mock pairs into one device group (the
/// MAC-randomization storyline: ROT1 visible from start, ROT2 "rotates in").
pub const MOCK_ROT1: MacAddr = MacAddr([0x02, 0xa0, 0xb1, 0xc2, 0xd3, 0xe4]);
pub const MOCK_ROT2: MacAddr = MacAddr([0x06, 0x5f, 0x4e, 0x3d, 0x2c, 0x1b]);

fn seed_aps() -> Vec<AccessPoint> {
    let now = now_ms();
    let ap = |mac: [u8; 6], ssid: &str, channel, security, rssi, akms: Vec<Akm>| AccessPoint {
        bssid: MacAddr(mac),
        ssid: ssid.to_string(),
        channel,
        security,
        rssi_dbm: rssi,
        beacons: 200,
        last_seen_ms: now,
        akms,
    };
    vec![
        ap(
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            "parafin",
            6,
            Security::Wpa2,
            -42,
            vec![Akm::Psk],
        ),
        ap(
            [0x02, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e],
            "labnet",
            1,
            Security::Wpa2,
            -55,
            vec![Akm::Psk],
        ),
        ap(
            [0x02, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e],
            "coffeeshop",
            11,
            Security::Wpa2,
            -68,
            vec![Akm::Psk],
        ),
        ap(
            [0x02, 0xff, 0xee, 0xdd, 0xcc, 0xbb],
            "corp-wpa3",
            36,
            Security::Wpa3,
            -61,
            vec![Akm::Psk, Akm::Sae],
        ),
        ap(
            [0x02, 0xde, 0xad, 0xbe, 0xef, 0x00],
            "legacy-prn",
            3,
            Security::Wep,
            -80,
            Vec::new(),
        ),
        ap(
            [0x02, 0x00, 0x11, 0x22, 0x33, 0x44],
            "open-wifi",
            6,
            Security::Open,
            -72,
            Vec::new(),
        ),
        // Same SSID as `parafin` but OPEN + different BSSID: trips the
        // UI's rogue-AP detection so the warning path is visible in mock.
        ap(
            [0x02, 0x66, 0x66, 0x66, 0x66, 0x66],
            "parafin",
            11,
            Security::Open,
            -77,
            Vec::new(),
        ),
    ]
}

fn seed_clients() -> Vec<ClientInfo> {
    let now = now_ms();
    let cl = |mac: MacAddr, ap: MacAddr, rssi, connected: bool| ClientInfo {
        mac,
        ap: Some(ap),
        rssi_dbm: rssi,
        frames: 40,
        last_seen_ms: now,
        connected,
        ident_group: None,
        ident_conf: None,
    };
    vec![
        cl(MOCK_CLIENTS[0], MOCK_BSSID, -44, true),
        cl(MOCK_CLIENTS[1], MOCK_BSSID, -51, true),
        cl(MOCK_CLIENTS[2], MacAddr([0x02, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]), -60, true),
        // Locally-administered (randomized) MAC — the ROT2 milestone below
        // pairs it with ROT1 as one physical radio.
        cl(MOCK_ROT1, MOCK_BSSID, -48, true),
        // Deauth-flagged so the disconnected state is visible in mock mode.
        cl(
            MOCK_CLIENTS[3],
            MacAddr([0x02, 0xff, 0xee, 0xdd, 0xcc, 0xbb]),
            -63,
            false,
        ),
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
        "mock: scanning on {MOCK_IFACE} (7 APs, 4 clients)"
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
    let mut tick = 0u64;
    // Drifting cumulative per-channel counters for the ChannelStats feed.
    let mut chan_frames: [u64; 4] = [120, 980, 340, 60];
    let mut chan_beacons: [u64; 4] = [40, 210, 90, 12];
    // Probe-request feed cycles these (client, ssid) pairs.
    const PROBE_FEED: &[(MacAddr, Option<&str>)] = &[
        (MOCK_CLIENTS[0], Some("HOME-WIFI")),
        (MOCK_CLIENTS[1], Some("labnet")),
        (MOCK_CLIENTS[2], None),
        (MOCK_CLIENTS[3], Some("coffeeshop")),
        (MOCK_CLIENTS[1], None),
    ];
    let mut probe_step = 0usize;
    let mut ident_fed = false;
    let mut deauth_alert_sent = false;
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
        tick += 1;
        let t = started.elapsed().as_secs_f32();
        let now = now_ms();

        // Per-channel activity snapshot every ~2 s (10 ticks).
        if tick % 10 == 0 {
            let mut stats = Vec::with_capacity(4);
            for (i, ch) in [1u8, 6, 11, 36].iter().enumerate() {
                chan_frames[i] += 20 + rng.below(180);
                chan_beacons[i] += rng.below(6);
                stats.push(ChannelStat {
                    channel: *ch,
                    frames: chan_frames[i],
                    beacons: chan_beacons[i],
                });
            }
            let _ = tx.send(Event::ChannelStats(stats));
        }

        // Probe-request feed every ~3 s (15 ticks).
        if tick % 15 == 0 {
            let (client, ssid) = PROBE_FEED[probe_step % PROBE_FEED.len()];
            probe_step += 1;
            let _ = tx.send(Event::ProbeObserved(ProbeInfo {
                client,
                ssid: ssid.map(str::to_string),
                rssi_dbm: -(40 + rng.below(45) as i8),
                at_ms: now,
            }));
        }

        // MAC-rotation storyline at ~6 s: a new randomized MAC appears and
        // the correlator pairs both into device group #1.
        if !ident_fed && t >= 6.0 {
            ident_fed = true;
            let _ = tx.send(Event::ClientIdent {
                mac: MOCK_ROT1,
                group: 1,
                confidence: crate::common::IdentConfidence::Strong,
            });
            let _ = tx.send(Event::ClientUpdated(ClientInfo {
                mac: MOCK_ROT2,
                ap: Some(MOCK_BSSID),
                rssi_dbm: -46,
                frames: 3,
                last_seen_ms: now,
                connected: true,
                ident_group: None,
                ident_conf: None,
            }));
            let _ = tx.send(Event::ClientIdent {
                mac: MOCK_ROT2,
                group: 1,
                confidence: crate::common::IdentConfidence::Strong,
            });
        }

        // One foreign-deauth storm milestone at ~12 s.
        if !deauth_alert_sent && t >= 12.0 {
            deauth_alert_sent = true;
            let _ = tx.send(Event::DeauthAlert {
                source: MOCK_BSSID,
                target: MacAddr::BROADCAST,
                count: 64,
            });
        }

        // RSSI drift + beacon/frame counters on every tick.
        for ap in &mut aps {
            ap.rssi_dbm = (ap.rssi_dbm + (rng.below(5) as i8 - 2)).clamp(-90, -30);
            ap.beacons += rng.below(3);
            ap.last_seen_ms = now;
            let _ = tx.send(Event::ApUpdated(ap.clone()));
        }
        for cl in &mut clients {
            cl.rssi_dbm = (cl.rssi_dbm + (rng.below(3) as i8 - 1)).clamp(-90, -30);
            cl.frames += rng.below(12);
            cl.last_seen_ms = now;
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
