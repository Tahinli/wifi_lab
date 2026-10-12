//! Zero-copy radiotap header parser + TX injection header.
//!
//! Radiotap layout: version(1) pad(1) it_len(2 LE) it_present(4 LE, possibly
//! extended via bit 31 into further 32-bit words), then a field area whose
//! entries obey per-field alignment *relative to the start of the radiotap
//! header*. We only decode the fields we consume (channel frequency, antenna
//! signal) but walk the full known-table so unknown-but-known-size fields are
//! skipped correctly. Unknown extension bits beyond the table (vendor
//! namespaces vs. future standards): degrade gracefully and rely on it_len
//! to locate the 802.11 payload.

/// Parsed metadata from an RX radiotap header.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RxMeta {
    pub rssi_dbm: i8,  // antenna signal, 0 if absent
    pub freq_mhz: u16, // channel frequency, 0 if absent
}

/// Radiotap header prepended to injected frames: version 0, pad 0, len 8,
/// no fields present.
pub const INJECT_HDR: [u8; 8] = [0, 0, 8, 0, 0, 0, 0, 0];

// Present-bit → (alignment, size) for the well-known fields, per the
// radiotap spec. Variable-size fields (TLVs, vendor namespaces) have no
// fixed entry and terminate the field walk.
fn field_spec(bit: u32) -> Option<(usize, usize)> {
    Some(match bit {
        0 => (8, 8),   // TSFT
        1 => (1, 1),   // Flags
        2 => (1, 1),   // Rate
        3 => (2, 4),   // Channel (freq u16 + flags u16)
        4 => (2, 2),   // FHSS
        5 => (1, 1),   // Antenna signal, dBm (i8)
        6 => (1, 1),   // Antenna noise, dBm
        7 => (2, 2),   // Lock quality
        8 => (2, 2),   // TX attenuation
        9 => (2, 2),   // dB TX attenuation
        10 => (1, 1),  // dBm TX power
        11 => (1, 1),  // Antenna
        12 => (1, 1),  // dB antenna signal
        13 => (1, 1),  // dB antenna noise
        14 => (2, 2),  // RX flags
        15 => (2, 2),  // TX flags
        16 => (1, 1),  // RTS retries
        17 => (1, 1),  // Data retries
        18 => (4, 8),  // XChannel
        19 => (1, 3),  // MCS
        20 => (4, 8),  // A-MPDU status
        21 => (2, 12), // VHT
        22 => (8, 12), // timestamp
        23 => (2, 12), // HE
        24 => (2, 12), // HE-MU
        25 => (1, 0),  // 0-length PSDU
        26 => (2, 4),  // L-SIG
        _ => return None,
    })
}

const MAX_PRESENT_WORDS: usize = 8;

/// Parse radiotap; returns (meta, remaining 802.11 frame bytes).
/// Returns None if the buffer is not a well-formed radiotap header.
pub fn strip(frame: &[u8]) -> Option<(RxMeta, &[u8])> {
    if frame.len() < 8 || frame[0] != 0 {
        return None;
    }
    let it_len = u16::from_le_bytes([frame[2], frame[3]]) as usize;
    if it_len < 8 || it_len > frame.len() {
        return None;
    }

    // Walk the present bitmap words (bit 31 = another word follows).
    let mut words = [0u32; MAX_PRESENT_WORDS];
    let mut n_words = 0usize;
    let mut word_off = 4usize;
    loop {
        if word_off + 4 > it_len {
            return None; // bitmap truncated inside the header
        }
        let w = u32::from_le_bytes([
            frame[word_off],
            frame[word_off + 1],
            frame[word_off + 2],
            frame[word_off + 3],
        ]);
        if n_words < MAX_PRESENT_WORDS {
            words[n_words] = w;
            n_words += 1;
        }
        word_off += 4;
        if w & 0x8000_0000 == 0 {
            break;
        }
    }
    let fields_start = word_off;

    let mut meta = RxMeta::default();
    let mut pos = fields_start;
    'fields: for (wi, &w) in words[..n_words].iter().enumerate() {
        for bit in 0..32u32 {
            if bit == 31 || w & (1 << bit) == 0 {
                continue;
            }
            let gbit = wi as u32 * 32 + bit;
            let Some((align, size)) = field_spec(gbit) else {
                // Variable-size or unknown field: cannot walk past it.
                // Graceful degradation — it_len still bounds the payload.
                break 'fields;
            };
            pos = pos.next_multiple_of(align);
            if pos + size > it_len {
                break 'fields; // field sticks out of the header: malformed
            }
            match gbit {
                3 => meta.freq_mhz = u16::from_le_bytes([frame[pos], frame[pos + 1]]),
                5 => meta.rssi_dbm = frame[pos] as i8,
                _ => {}
            }
            pos += size;
        }
    }

    Some((meta, &frame[it_len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_header(present: &[u32], fields: &[u8], tail: &[u8]) -> Vec<u8> {
        let it_len = 4 + present.len() * 4 + fields.len();
        let mut v = vec![0u8, 0, (it_len & 0xff) as u8, (it_len >> 8) as u8];
        for w in present {
            v.extend_from_slice(&w.to_le_bytes());
        }
        v.extend_from_slice(fields);
        v.extend_from_slice(tail);
        v
    }

    #[test]
    fn inject_hdr_roundtrips_as_empty_header() {
        let payload = [0x80u8, 0x00, 0x00, 0x00];
        let mut f = INJECT_HDR.to_vec();
        f.extend_from_slice(&payload);
        let (meta, rest) = strip(&f).expect("inject header parses");
        assert_eq!(meta, RxMeta::default());
        assert_eq!(rest, &payload);
    }

    #[test]
    fn channel_and_antenna_signal_parsed() {
        // present: bit3 (channel, align 2) | bit5 (antenna signal, align 1)
        let mut fields = [0u8; 5];
        fields[0..2].copy_from_slice(&2417u16.to_le_bytes()); // 2417 MHz = ch 2
        fields[2..4].copy_from_slice(&0x00a0u16.to_le_bytes());
        fields[4] = (-42i8) as u8;
        let tail = [0xde, 0xad];
        let f = build_header(&[0x28], &fields, &tail);
        let (meta, rest) = strip(&f).unwrap();
        assert_eq!(meta.freq_mhz, 2417);
        assert_eq!(meta.rssi_dbm, -42);
        assert_eq!(rest, &tail);
    }

    #[test]
    fn tsft_honors_8_byte_alignment() {
        // present: bit0 (TSFT, align 8) | bit5 (antenna signal). Fields start
        // at offset 8 so TSFT lands unaligned only when fields_start != 8; add
        // one extension word to shift fields_start to 12 → TSFT aligns to 16.
        let mut f = vec![0u8, 0, 0, 0, 0x21, 0x00, 0x00, 0x80]; // present w0: tsft|antenna|ext
        f.extend_from_slice(&0u32.to_le_bytes()); // present w1: empty, ends bitmap
        let fields_start = f.len(); // 12
        let pad = (fields_start + 7) / 8 * 8 - fields_start;
        f.resize(fields_start + pad + 8 + 1, 0u8);
        let rssi_at = fields_start + pad + 8;
        f[rssi_at] = (-30i8) as u8;
        let it_len = f.len() as u16;
        f[2..4].copy_from_slice(&it_len.to_le_bytes());
        f.extend_from_slice(&[0xaa, 0xbb]);
        let (meta, rest) = strip(&f).unwrap();
        assert_eq!(meta.rssi_dbm, -30);
        assert_eq!(rest, &[0xaa, 0xbb]);
    }

    #[test]
    fn unknown_extension_bit_degrades_to_it_len() {
        // present w0: rate (bit2) | ext; w1: unknown bit 13 (global 45).
        // Rate consumed, unknown field stops the walk; payload still at it_len.
        let present0 = 0x8000_0004u32;
        let present1 = 0x0000_2000u32;
        let fields = [0x0cu8, 0x00, 0x00, 0x00]; // rate + opaque bytes
        let tail = [0x55u8; 4];
        let f = build_header(&[present0, present1], &fields, &tail);
        let (meta, rest) = strip(&f).unwrap();
        assert_eq!(meta, RxMeta::default());
        assert_eq!(rest, &tail);
    }

    #[test]
    fn malformed_headers_rejected() {
        assert!(strip(&[]).is_none());
        assert!(strip(&[0, 0, 4]).is_none()); // too short
        // version != 0
        assert!(strip(&[1, 0, 8, 0, 0, 0, 0, 0]).is_none());
        // it_len < 8
        assert!(strip(&[0, 0, 7, 0, 0, 0, 0, 0, 0]).is_none());
        // it_len beyond frame
        assert!(strip(&[0, 0, 64, 0, 0, 0, 0, 0]).is_none());
    }
}
