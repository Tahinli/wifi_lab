//! CPU reference implementation of WPA2-PSK cryptographic primitives:
//! PBKDF2-SHA1 PMK derivation, 802.11 §12.7.1.2 PRF-512 PTK expansion,
//! EAPOL-Key MIC (HMAC-SHA1-128 and hand-rolled AES-128-CMAC), PMKID hash,
//! verification and hashcat 22000 line parsing.

use anyhow::{Context, Result, anyhow, bail};

use crate::common::{HandshakeCapture, MacAddr, PmkidCapture};

/// Something the cracker can attack: a 4-way handshake or a PMKID.
#[derive(Clone, Debug)]
pub enum CrackTarget {
    Handshake(HandshakeCapture),
    Pmkid(PmkidCapture),
}

impl CrackTarget {
    pub fn essid(&self) -> &str {
        match self {
            CrackTarget::Handshake(h) => &h.essid,
            CrackTarget::Pmkid(p) => &p.essid,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            CrackTarget::Handshake(h) => format!(
                "handshake ap={} sta={} essid=\"{}\" key_ver={}",
                h.ap, h.client, h.essid, h.key_ver
            ),
            CrackTarget::Pmkid(p) => {
                format!("pmkid ap={} sta={} essid=\"{}\"", p.ap, p.client, p.essid)
            }
        }
    }
}

/// PBKDF2-HMAC-SHA1 with a 20-byte digest per block. Implemented by hand so
/// we don't depend on the pbkdf2 crate re-exports lining up with the local
/// sha1/hmac versions (digest 0.10 vs 0.11 drift); c=4096 is the caller's
/// problem, this version is generic.
pub fn pbkdf2_hmac_sha1(pass: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    use hmac::{Hmac, Mac};
    for (i, chunk) in out.chunks_mut(20).enumerate() {
        let idx = (i + 1) as u32;
        let mut mac = <Hmac<sha1::Sha1> as Mac>::new_from_slice(pass)
            .expect("HMAC-SHA1 accepts any key length");
        mac.update(salt);
        mac.update(&idx.to_be_bytes());
        let mut u = mac.finalize().into_bytes();
        let mut t = u;
        for _ in 1..iterations {
            let mut mac = <Hmac<sha1::Sha1> as Mac>::new_from_slice(pass).expect("hmac");
            mac.update(&u);
            u = mac.finalize().into_bytes();
            for (tb, ub) in t.iter_mut().zip(u.iter()) {
                *tb ^= ub;
            }
        }
        let n = chunk.len();
        chunk.copy_from_slice(&t[..n]);
    }
}

/// PMK = PBKDF2-HMAC-SHA1(pass, ssid, 4096, 32).
pub fn pmk(pass: &[u8], ssid: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2_hmac_sha1(pass, ssid, 4096, &mut out);
    out
}

/// PRF message stem ("Pairwise key expansion" || 0x00 || A || B, 99
/// bytes): A = min(ap,sta)||max(ap,sta), B = min(anonce,snonce)||
/// max(anonce,snonce). Shared by [`ptk`] and the GPU kernel's per-target
/// KCK message (which appends counter byte 0x01).
pub(crate) fn prf_stem(
    ap: &MacAddr,
    sta: &MacAddr,
    anonce: &[u8; 32],
    snonce: &[u8; 32],
) -> Vec<u8> {
    let mut a_pair = [0u8; 12];
    if ap.0 <= sta.0 {
        a_pair[..6].copy_from_slice(&ap.0);
        a_pair[6..].copy_from_slice(&sta.0);
    } else {
        a_pair[..6].copy_from_slice(&sta.0);
        a_pair[6..].copy_from_slice(&ap.0);
    }
    let mut b_pair = [0u8; 64];
    if anonce <= snonce {
        b_pair[..32].copy_from_slice(anonce);
        b_pair[32..].copy_from_slice(snonce);
    } else {
        b_pair[..32].copy_from_slice(snonce);
        b_pair[32..].copy_from_slice(anonce);
    }

    let mut msg = Vec::with_capacity(22 + 1 + 12 + 64);
    msg.extend_from_slice(b"Pairwise key expansion");
    msg.push(0u8);
    msg.extend_from_slice(&a_pair);
    msg.extend_from_slice(&b_pair);
    msg
}

/// PTK derivation per 802.11-2016 §12.7.1.2 (PRF-512):
/// HMAC-SHA1(pmk, "Pairwise key expansion" || 0x00 || A || B || i) for i in 1..,
/// with A = min(ap,sta)||max(ap,sta), B = min(anonce,snonce)||max(anonce,snonce).
pub fn ptk(
    pmk: &[u8; 32],
    ap: &MacAddr,
    sta: &MacAddr,
    anonce: &[u8; 32],
    snonce: &[u8; 32],
) -> [u8; 64] {
    use hmac::{Hmac, Mac};

    let mut msg = prf_stem(ap, sta, anonce, snonce);
    let stem_len = msg.len();
    msg.push(0u8); // PRF counter byte, rewritten per round below

    let mut out = [0u8; 64];
    for (i, chunk) in out.chunks_mut(20).enumerate() {
        msg[stem_len] = (i + 1) as u8;
        let mut mac = <Hmac<sha1::Sha1> as Mac>::new_from_slice(pmk)
            .expect("HMAC-SHA1 accepts any key length");
        mac.update(&msg);
        let digest = mac.finalize().into_bytes();
        chunk.copy_from_slice(&digest[..chunk.len()]);
    }
    out
}

/// EAPOL frame with its MIC field zeroed (bytes 81..97; short frames stay
/// untouched). The zeroed frame is CONSTANT across all candidates of one
/// capture — crack loops compute it once and call [`mic_on_zeroed`] per
/// candidate instead of re-copying the frame every time.
pub fn zeroed_eapol(eapol: &[u8]) -> Vec<u8> {
    let mut data = eapol.to_vec();
    const MIC_OFF: usize = 81;
    const MIC_LEN: usize = 16;
    if data.len() >= MIC_OFF + MIC_LEN {
        data[MIC_OFF..MIC_OFF + MIC_LEN].fill(0);
    }
    data
}

/// MIC over an already-MIC-zeroed frame (see [`zeroed_eapol`]). No
/// allocation — the hot path of the cracker's per-candidate check.
pub fn mic_on_zeroed(ptk: &[u8; 64], zeroed: &[u8], key_ver: u8) -> [u8; 16] {
    use hmac::{Hmac, Mac};

    if key_ver == 3 {
        // key_mic_len = 16 → blk_key = IGTK||0x00*8. EAPOL frames are never
        // zero-length (header is 4 bytes), but the multi-block path covers
        // len ≡ 0 mod 16 correctly either way.
        let mut key = [0u8; 16];
        key[..8].copy_from_slice(&ptk[48..56]);
        cmac_aes128(&key, zeroed)
    } else {
        let mut mac =
            <Hmac<sha1::Sha1> as Mac>::new_from_slice(&ptk[..16]).expect("KCK is 16 bytes");
        mac.update(zeroed);
        let digest = mac.finalize().into_bytes();
        let mut out = [0u8; 16];
        out.copy_from_slice(&digest[..16]);
        out
    }
}

/// EAPOL-Key MIC. Zeroes bytes 81..97 of a copy of `eapol` (the MIC field
/// offset in a well-formed EAPOL-Key frame; short frames are left untouched),
/// then: key_ver 1|2 → HMAC-SHA1 keyed with KCK and truncated to 16 bytes,
/// key_ver 3 → AES-128-CMAC over IGTK||0^64||frame.
pub fn mic(ptk: &[u8; 64], eapol: &[u8], key_ver: u8) -> [u8; 16] {
    mic_on_zeroed(ptk, &zeroed_eapol(eapol), key_ver)
}

/// PMKID = HMAC-SHA1-128(pmk, "PMK Name" || ap || sta).
pub fn pmkid_hash(pmk: &[u8; 32], ap: &MacAddr, sta: &MacAddr) -> [u8; 16] {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<sha1::Sha1> as Mac>::new_from_slice(pmk).expect("PMK is 32 bytes");
    mac.update(b"PMK Name");
    mac.update(&ap.0);
    mac.update(&sta.0);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// Constant-time equality of 16-byte buffers.
pub fn ct_eq16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Verify `pass` against the capture. Handshake MICs compare in constant
/// time.
pub fn verify(target: &CrackTarget, pass: &[u8]) -> bool {
    let key = pmk(pass, target.essid().as_bytes());
    match target {
        CrackTarget::Handshake(h) => {
            let dk = ptk(&key, &h.ap, &h.client, &h.anonce, &h.snonce);
            let got = mic(&dk, &h.eapol_m2, h.key_ver);
            ct_eq16(&got, h.mic())
        }
        CrackTarget::Pmkid(p) => {
            let got = pmkid_hash(&key, &p.ap, &p.client);
            ct_eq16(&got, &p.pmkid)
        }
    }
}

fn unhex_field(s: &str, name: &str) -> Result<Vec<u8>> {
    if s.is_empty() || s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("{name}: not even-length hex");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(anyhow::Error::from))
        .collect::<Result<Vec<u8>, _>>()
        .with_context(|| format!("{name}: bad hex"))
}

fn unhex_array<const N: usize>(s: &str, name: &str) -> Result<[u8; N]> {
    let v = unhex_field(s, name)?;
    <[u8; N]>::try_from(v.as_slice()).map_err(|_| anyhow!("{name}: expected {N} bytes"))
}

fn parse_mac(s: &str) -> Result<MacAddr> {
    Ok(MacAddr(unhex_array::<6>(s, "mac")?))
}

/// Parse one hashcat -m 22000 line:
///   01*PMKID*MAC_AP*MAC_CLIENT*ESSID(hex)***   (PMKID)
///   02*MIC*MAC_AP*MAC_CLIENT*ESSID(hex)*ANONCE*EAPOL(hex)*...  (EAPOL)
pub fn parse_hc22000(line: &str) -> Result<CrackTarget> {
    let line = line.trim();
    let fields: Vec<&str> = line.split('*').collect();
    if fields.len() < 5 {
        bail!("hc22000: too few fields");
    }
    match fields[0] {
        "01" => {
            let pmkid = unhex_array::<16>(fields[1], "pmkid")?;
            let ap = parse_mac(fields[2])?;
            let client = parse_mac(fields[3])?;
            let essid_bytes = unhex_field(fields[4], "essid")?;
            let essid =
                String::from_utf8(essid_bytes).context("hc22000: essid not valid utf-8")?;
            Ok(CrackTarget::Pmkid(PmkidCapture {
                ap,
                client,
                essid,
                pmkid,
            }))
        }
        "02" => {
            if fields.len() < 7 {
                bail!("hc22000 type 02: need mic*ap*client*essid*anonce*eapol");
            }
            let mic_bytes = unhex_array::<16>(fields[1], "mic")?;
            let ap = parse_mac(fields[2])?;
            let client = parse_mac(fields[3])?;
            let essid_bytes = unhex_field(fields[4], "essid")?;
            let essid =
                String::from_utf8(essid_bytes).context("hc22000: essid not valid utf-8")?;
            let anonce = unhex_array::<32>(fields[5], "anonce")?;
            let eapol = unhex_field(fields[6], "eapol")?;
            if eapol.len() < 99 {
                bail!("hc22000: eapol frame too short to carry key data");
            }
            // Recover snonce (offset 17..49 of EAPOL-Key frame) and key MIC
            // version (low bits of big-endian key_info at 5..7).
            let snonce = <[u8; 32]>::try_from(&eapol[17..49]).expect("slice checked");
            let key_info = u16::from_be_bytes([eapol[5], eapol[6]]);
            let key_ver = (key_info & 0x7) as u8;
            Ok(CrackTarget::Handshake(HandshakeCapture::new(
                ap, client, essid, anonce, snonce, mic_bytes, eapol, key_ver,
            )))
        }
        other => bail!("hc22000: unsupported message pair type {other}"),
    }
}

// ---------------------------------------------------------------------------
// AES-128 + CMAC (RFC 4493), hand-rolled. The S-box is derived arithmetically
// in GF(2^8) via log/exp tables for generator 0x03 (multiplicative inverse,
// then the AES affine transform) — no 256-entry constant to typo.
// MixColumns uses xtime-based constant multiples.
// ---------------------------------------------------------------------------

struct AesTables {
    sbox: [u8; 256],
    mul2: [u8; 256],
    mul3: [u8; 256],
}

fn xtime(x: u8) -> u8 {
    let x2 = x << 1;
    if x & 0x80 != 0 { x2 ^ 0x1b } else { x2 }
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut r = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            r ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    r
}

impl AesTables {
    fn new() -> Self {
        let mut exp = [0u8; 256];
        let mut log = [0u8; 256];
        let mut v = 1u8;
        // 0x03 is a generator of GF(2^8) under AES reduction.
        for i in 0..255usize {
            exp[i] = v;
            log[v as usize] = i as u8;
            v = gf_mul(v, 0x03);
        }
        exp[255] = 1; // generator cycle has length 255; wrap entry

        let mut sbox = [0u8; 256];
        for (x, slot) in sbox.iter_mut().enumerate() {
            let inv = if x == 0 {
                0u8
            } else {
                exp[(255usize - log[x] as usize) % 255]
            };
            *slot = inv
                ^ inv.rotate_left(1)
                ^ inv.rotate_left(2)
                ^ inv.rotate_left(3)
                ^ inv.rotate_left(4)
                ^ 0x63;
        }

        let mut t = AesTables {
            sbox,
            mul2: [0u8; 256],
            mul3: [0u8; 256],
        };
        for x in 0..256usize {
            t.mul2[x] = gf_mul(x as u8, 2);
            t.mul3[x] = gf_mul(x as u8, 3);
        }
        t
    }
}

struct Aes128 {
    rk: [u8; 176],
    t: AesTables,
}

impl Aes128 {
    fn new(key: &[u8; 16]) -> Self {
        let t = AesTables::new();
        let mut rk = [0u8; 176];
        rk[..16].copy_from_slice(key);
        let mut i = 4usize; // words generated
        while i < 44 {
            let mut w = [
                rk[4 * i - 4],
                rk[4 * i - 3],
                rk[4 * i - 2],
                rk[4 * i - 1],
            ];
            if i % 4 == 0 {
                // RotWord + SubWord + Rcon
                w.rotate_left(1);
                for b in w.iter_mut() {
                    *b = t.sbox[*b as usize];
                }
                w[0] ^= rcon_for_round(i / 4);
            }
            for j in 0..4 {
                rk[4 * i + j] = rk[4 * (i - 4) + j] ^ w[j];
            }
            i += 1;
        }
        Aes128 { rk, t }
    }

    fn encrypt_block(&self, input: &[u8; 16]) -> [u8; 16] {
        let mut s = *input;
        add_round_key(&mut s, &self.rk[0..16]);
        for r in 1..10 {
            sub_bytes(&mut s, &self.t.sbox);
            shift_rows(&mut s);
            mix_columns(&mut s, &self.t);
            add_round_key(&mut s, &self.rk[16 * r..16 * r + 16]);
        }
        sub_bytes(&mut s, &self.t.sbox);
        shift_rows(&mut s);
        add_round_key(&mut s, &self.rk[160..176]);
        s
    }
}

fn rcon_for_round(round: usize) -> u8 {
    // Rcon[1..=10] = 01,02,04,08,10,20,40,80,1b,36
    const RCON: [u8; 11] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    RCON[round]
}

fn add_round_key(s: &mut [u8; 16], rk: &[u8]) {
    for i in 0..16 {
        s[i] ^= rk[i];
    }
}

fn sub_bytes(s: &mut [u8; 16], sbox: &[u8; 256]) {
    for b in s.iter_mut() {
        *b = sbox[*b as usize];
    }
}

fn shift_rows(s: &mut [u8; 16]) {
    // state is column-major: s[c*4 + r]
    let t = *s;
    for r in 1..4 {
        for c in 0..4 {
            s[c * 4 + r] = t[((c + r) % 4) * 4 + r];
        }
    }
}

fn mix_columns(s: &mut [u8; 16], t: &AesTables) {
    for c in 0..4 {
        let i = c * 4;
        let (a0, a1, a2, a3) = (s[i], s[i + 1], s[i + 2], s[i + 3]);
        s[i] = t.mul2[a0 as usize] ^ t.mul3[a1 as usize] ^ a2 ^ a3;
        s[i + 1] = a0 ^ t.mul2[a1 as usize] ^ t.mul3[a2 as usize] ^ a3;
        s[i + 2] = a0 ^ a1 ^ t.mul2[a2 as usize] ^ t.mul3[a3 as usize];
        s[i + 3] = t.mul3[a0 as usize] ^ a1 ^ a2 ^ t.mul2[a3 as usize];
    }
}

/// AES-128-CMAC per RFC 4493.
pub fn cmac_aes128(key: &[u8; 16], msg: &[u8]) -> [u8; 16] {
    let aes = Aes128::new(key);
    let l = aes.encrypt_block(&[0u8; 16]);
    let k1 = dbl(l);
    let k2 = dbl(k1);

    let n = msg.len().div_ceil(16).max(1);
    let complete = !msg.is_empty() && msg.len() % 16 == 0;

    let mut m_last = [0u8; 16];
    if complete {
        m_last.copy_from_slice(&msg[16 * (n - 1)..]);
        for i in 0..16 {
            m_last[i] ^= k1[i];
        }
    } else {
        let rem = if msg.is_empty() { 0 } else { msg.len() % 16 };
        let start = if msg.is_empty() { 0 } else { msg.len() - rem };
        m_last[..rem].copy_from_slice(&msg[start..]);
        m_last[rem] = 0x80;
        for i in 0..16 {
            m_last[i] ^= k2[i];
        }
    }

    let mut x = [0u8; 16];
    for i in 0..n - 1 {
        let block = &msg[16 * i..16 * i + 16];
        for j in 0..16 {
            x[j] ^= block[j];
        }
        x = aes.encrypt_block(&x);
    }
    for j in 0..16 {
        x[j] ^= m_last[j];
    }
    aes.encrypt_block(&x)
}

fn dbl(b: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let msb = b[0] & 0x80 != 0;
    let mut carry = 0u8;
    for i in (0..16).rev() {
        let new_carry = (b[i] >> 7) & 1;
        out[i] = (b[i] << 1) | carry;
        carry = new_carry;
    }
    if msb {
        out[15] ^= 0x87;
    }
    out
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pmk_rfc6070_c4096() {
        // RFC 6070 PBKDF2-HMAC-SHA1: P="password" S="salt" c=4096 dkLen=20.
        let mut out20 = [0u8; 20];
        pbkdf2_hmac_sha1(b"password", b"salt", 4096, &mut out20);
        assert_eq!(hex(&out20), "4b007901b765489abead49d926f721d065a429c1");

        // RFC 6070 fast checks: c=1 and c=2 vectors anchor the block-1 chain.
        let mut o1 = [0u8; 20];
        pbkdf2_hmac_sha1(b"password", b"salt", 1, &mut o1);
        assert_eq!(hex(&o1), "0c60c80f961f0e71f3a9b524af6012062fe037a6");
        pbkdf2_hmac_sha1(b"password", b"salt", 2, &mut o1);
        assert_eq!(hex(&o1), "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");

        // Known WPA2 PMK vector (used by aircrack/hashcat test suites):
        // ssid "IEEE", pass "password".
        let k = pmk(b"password", b"IEEE");
        assert_eq!(
            hex(&k),
            "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"
        );
    }

    #[test]
    fn gf_sanity() {
        // AES xtime known sample: 0x57 * 0x13 = 0xfe (FIPS-197 example).
        assert_eq!(gf_mul(0x57, 0x13), 0xfe);
        let t = AesTables::new();
        // S-box spot values (FIPS-197 Table 4/5): S(0x00)=0x63, S(0x53)=0xed.
        assert_eq!(t.sbox[0x00], 0x63);
        assert_eq!(t.sbox[0x53], 0xed);
        assert_eq!(t.sbox[0x01], 0x7c);
        assert_eq!(t.sbox[0xff], 0x16);
        // The S-box must be a bijection.
        let mut seen = [false; 256];
        for &v in t.sbox.iter() {
            assert!(!seen[v as usize], "s-box collides");
            seen[v as usize] = true;
        }
        // MixColumns constants: 2 and 3 tables agree with xtime.
        // 0x80*2 = 0x1b; 0xdb*2 = (0xdb<<1)^0x1b = 0xb6^0x1b = 0xad;
        // 0xdb*3 = 0xdb ^ 0xad = 0x76.
        assert_eq!(t.mul2[0x80], 0x1b);
        assert_eq!(t.mul2[0xdb], 0xad);
        assert_eq!(t.mul3[0xdb], 0x76);
    }

    #[test]
    fn aes128_fips197() {
        // FIPS-197 Appendix B / C.1 test vector.
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let pt = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let aes = Aes128::new(&key);
        let ct = aes.encrypt_block(&pt);
        assert_eq!(
            hex(&ct),
            "69c4e0d86a7b0430d8cdb78070b4c55a"
        );
    }

    #[test]
    fn cmac_rfc4493() {
        let k = unhex_field("2b7e151628aed2a6abf7158809cf4f3c", "k").unwrap();
        let key: [u8; 16] = k.try_into().unwrap();

        let m0: [u8; 0] = [];
        assert_eq!(
            hex(&cmac_aes128(&key, &m0)),
            "bb1d6929e95937287fa37d129b756746"
        );

        let m16 = unhex_field("6bc1bee22e409f96e93d7e117393172a", "m").unwrap();
        assert_eq!(
            hex(&cmac_aes128(&key, &m16)),
            "070a16b46b4d4144f79bdd9dd04a287c"
        );

        let m40 = unhex_field(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
            "m",
        )
        .unwrap();
        assert_eq!(
            hex(&cmac_aes128(&key, &m40)),
            "dfa66747de9ae63030ca32611497c827"
        );

        let m64 = unhex_field(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
            "m",
        )
        .unwrap();
        assert_eq!(
            hex(&cmac_aes128(&key, &m64)),
            "51f0bebf7e3b9d92fc49741779363cfe"
        );
    }

    /// Build a minimal EAPOL-Key (WPA2 descriptor) message-2 frame with the
    /// MIC field zeroed, exactly 99 bytes.
    fn build_eapol_m2(key_ver: u8, snonce: &[u8; 32], replay: u64) -> Vec<u8> {
        let mut f = Vec::with_capacity(99);
        f.push(0x02); // EAPOL version 2
        f.push(0x03); // type: EAPOL-Key
        f.extend_from_slice(&95u16.to_be_bytes()); // body length
        f.push(0x02); // descriptor type: RSN
        let info: u16 = 0x0100 | 0x0080 | (key_ver as u16 & 0x7); // pairwise|mic|ver
        f.extend_from_slice(&info.to_be_bytes());
        f.extend_from_slice(&16u16.to_be_bytes()); // key length
        f.extend_from_slice(&replay.to_be_bytes());
        f.extend_from_slice(snonce);
        f.extend_from_slice(&[0u8; 16]); // key IV
        f.extend_from_slice(&[0u8; 8]); // key RSC
        f.extend_from_slice(&[0u8; 8]); // key ID
        f.extend_from_slice(&[0u8; 16]); // MIC (zeroed)
        f.extend_from_slice(&0u16.to_be_bytes()); // key data len
        assert_eq!(f.len(), 99);
        f
    }

    fn synthetic_target(ssid: &str, pass: &[u8], key_ver: u8) -> (CrackTarget, [u8; 32]) {
        let ap = "aa:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap();
        let sta = "11:22:33:44:55:66".parse::<MacAddr>().unwrap();
        let anonce: [u8; 32] = [0x5a; 32];
        let snonce: [u8; 32] = [0xc3; 32];
        let key = pmk(pass, ssid.as_bytes());
        let dk = ptk(&key, &ap, &sta, &anonce, &snonce);
        let frame = build_eapol_m2(key_ver, &snonce, 1);
        let m = mic(&dk, &frame, key_ver);
        let cap = HandshakeCapture::new(
            ap,
            sta,
            ssid.to_string(),
            anonce,
            snonce,
            m,
            frame,
            key_ver,
        );
        (CrackTarget::Handshake(cap), key)
    }

    #[test]
    fn synthetic_handshake_sha1_mic() {
        let (target, _) = synthetic_target("parafin", b"sup3r-secret", 2);
        assert!(verify(&target, b"sup3r-secret"));
        assert!(!verify(&target, b"sup3r-wrong"));
        // Tampered MIC must not verify.
        if let CrackTarget::Handshake(mut h) = target.clone() {
            h.eapol_m2[10] ^= 1; // flip a nonce bit → MIC mismatch
            assert!(!verify(&CrackTarget::Handshake(h), b"sup3r-secret"));
        }
    }

    #[test]
    fn synthetic_handshake_cmac_mic() {
        let (target, _) = synthetic_target("parafin", b"sup3r-secret", 3);
        assert!(verify(&target, b"sup3r-secret"));
        assert!(!verify(&target, b"sup3r-wrong"));
    }

    #[test]
    fn pmkid_roundtrip() {
        let ap = "aa:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap();
        let sta = "11:22:33:44:55:66".parse::<MacAddr>().unwrap();
        let key = pmk(b"sup3r-secret", b"parafin");
        let id = pmkid_hash(&key, &ap, &sta);
        let cap = PmkidCapture {
            ap,
            client: sta,
            essid: "parafin".to_string(),
            pmkid: id,
        };
        let target = CrackTarget::Pmkid(cap);
        assert!(verify(&target, b"sup3r-secret"));
        assert!(!verify(&target, b"another-pass"));
    }

    /// Export a handshake exactly like handshake::handshake_hc22000 does:
    /// 02*MIC*MAC_AP*MAC_CLIENT*ESSID(hex)*ANONCE*EAPOL(hex)*00
    fn export_handshake(h: &HandshakeCapture) -> String {
        let mut s = String::new();
        s.push_str("02*");
        s.push_str(&hex(h.mic()));
        s.push('*');
        for b in h.ap.0 {
            s.push_str(&format!("{b:02x}"));
        }
        s.push('*');
        for b in h.client.0 {
            s.push_str(&format!("{b:02x}"));
        }
        s.push('*');
        for b in h.essid.as_bytes() {
            s.push_str(&format!("{b:02x}"));
        }
        s.push('*');
        for b in h.anonce {
            s.push_str(&format!("{b:02x}"));
        }
        s.push('*');
        for b in &h.eapol_m2 {
            s.push_str(&format!("{b:02x}"));
        }
        s.push_str("*00");
        s
    }

    /// Export a PMKID capture: 01*PMKID*MAC_AP*MAC_CLIENT*ESSID(hex)***
    fn export_pmkid(p: &PmkidCapture) -> String {
        let mut s = String::from("01*");
        s.push_str(&hex(&p.pmkid));
        s.push('*');
        for b in p.ap.0 {
            s.push_str(&format!("{b:02x}"));
        }
        s.push('*');
        for b in p.client.0 {
            s.push_str(&format!("{b:02x}"));
        }
        s.push('*');
        for b in p.essid.as_bytes() {
            s.push_str(&format!("{b:02x}"));
        }
        s.push_str("***");
        s
    }

    #[test]
    fn hc22000_handshake_roundtrip() {
        let (target, _key) = synthetic_target("parafin", b"sup3r-secret", 2);
        let h = match &target {
            CrackTarget::Handshake(h) => h.clone(),
            _ => unreachable!(),
        };
        let line = export_handshake(&h);
        let parsed = parse_hc22000(&line).unwrap();
        match &parsed {
            CrackTarget::Handshake(p) => {
                assert_eq!(p.ap, h.ap);
                assert_eq!(p.client, h.client);
                assert_eq!(p.essid, h.essid);
                assert_eq!(&p.anonce, &h.anonce);
                // GPU verification path must take snonce from parsed eapol.
                assert_eq!(&p.snonce, &h.snonce);
                assert_eq!(p.mic(), h.mic());
                assert_eq!(p.eapol_m2, h.eapol_m2);
                assert_eq!(p.key_ver, 2);
            }
            _ => panic!("wrong target type"),
        }
        assert!(verify(&parsed, b"sup3r-secret"));
        assert!(!verify(&parsed, b"nope-nope"));
    }

    #[test]
    fn hc22000_pmkid_roundtrip() {
        let ap = "aa:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap();
        let sta = "11:22:33:44:55:66".parse::<MacAddr>().unwrap();
        let key = pmk(b"hunter2!!", b"parafin");
        let cap = PmkidCapture {
            ap,
            client: sta,
            essid: "parafin".to_string(),
            pmkid: pmkid_hash(&key, &ap, &sta),
        };
        let line = export_pmkid(&cap);
        assert!(line.ends_with("***"));
        let parsed = parse_hc22000(&line).unwrap();
        assert!(verify(&parsed, b"hunter2!!"));
        assert!(!verify(&parsed, b"hunter3!!"));
    }

    #[test]
    fn hc22000_rejections() {
        assert!(parse_hc22000("").is_err());
        assert!(parse_hc22000("03*aa*bb").is_err());
        assert!(parse_hc22000("01*zz*aabbccddeeff*112233445566*70617261***").is_err());
        // odd-length hex
        assert!(parse_hc22000("01*abc*aabbccddeeff*112233445566*70***").is_err());
        // type 02 missing eapol field
        assert!(
            parse_hc22000("02*070a16b46b4d4144f79bdd9dd04a287c*aabbccddeeff*112233445566*70617261*abcd")
                .is_err()
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}

