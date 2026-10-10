// PBKDF2-HMAC-SHA1 full-pipeline kernel for WPA2-PSK cracking (WGSL).
//
// Per candidate the shader does EVERYTHING (host only packs raw bytes):
//   1. HMAC key midstates from the passphrase (2 compresses),
//   2. U1/U2 for both PBKDF2 blocks from host-precomputed padded messages
//      (salt||INT32BE(1|2) — constant across candidates, passed via params),
//   3. the 4095-iteration chained HMAC loop (registers only),
//   4. the verify epilogue: PTK-KCK HMAC + EAPOL MIC compare (handshake)
//      or PMKID compare — hit slot readback instead of streaming PMKs.
//
// Verify messages arrive PRE-PADDED in params (they are constant per
// target): sha1 padding appended AFTER an implicit 64-byte HMAC pad
// prefix, i.e. total message length = 64 + msg_len.
//
// Candidate wire format: 16 u32 per candidate, the password bytes packed
// big-endian and zero-padded (passphrases are 8..=63 so they never spill
// the 64-byte HMAC key block).

struct Params {
    flags: u32,      // (iteration_count << 1)
    is_pmkid: u32,   // 1 = compare blk1 HMAC against mic (PMKID path)
    n_blk1: u32,     // padded 64-byte blocks in blk1
    n_blk2: u32,     // padded blocks in blk2 (handshake MIC message)
    n: u32,          // candidate count in this dispatch
    pad0: u32,
    pad1: u32,
    pad2: u32,
    u1_msg: array<u32, 16>,
    u2_msg: array<u32, 16>,
    blk1: array<u32, 48>,  // PMKID msg (1 blk) or PTK-PRF msg (2 blk)
    blk2: array<u32, 48>,  // zeroed EAPOL frame (2..3 blk); unused for PMKID
    mic: array<u32, 4>,    // target MIC / PMKID words (BE)
}

@group(0) @binding(0) var<storage, read> params: Params;
@group(0) @binding(1) var<storage, read> candidates: array<u32>;      // 16 u32 / cand
@group(0) @binding(2) var<storage, read_write> outputs: array<u32>;   // 10 u32 / cand (pmk_out only)
@group(0) @binding(3) var<storage, read_write> hits: array<atomic<u32>>; // [0]=flag [1]=gid

const IV: array<u32, 5u> = array<u32, 5u>(0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u);

// One SHA1 compression: state (5×u32) over exactly one 64-byte block.
// All 80 rounds unrolled (dynamic indexing would demote w[] to scratch).
// Round functions use hashcat's minimal-op forms; the message schedule
// uses the doubled-step (rotl2) recurrence for t>=32 — bit-identical to
// the standard recurrence but with roughly half the serial depth.
fn sha1_compress(state_in: ptr<function, array<u32, 5u>>, block: ptr<function, array<u32, 16u>>) {
    let w0 = (*block)[0];
    let w1 = (*block)[1];
    let w2 = (*block)[2];
    let w3 = (*block)[3];
    let w4 = (*block)[4];
    let w5 = (*block)[5];
    let w6 = (*block)[6];
    let w7 = (*block)[7];
    let w8 = (*block)[8];
    let w9 = (*block)[9];
    let w10 = (*block)[10];
    let w11 = (*block)[11];
    let w12 = (*block)[12];
    let w13 = (*block)[13];
    let w14 = (*block)[14];
    let w15 = (*block)[15];
    let w16 = (((w13 ^ w8 ^ w2 ^ w0) << 1u) | ((w13 ^ w8 ^ w2 ^ w0) >> 31u));
    let w17 = (((w14 ^ w9 ^ w3 ^ w1) << 1u) | ((w14 ^ w9 ^ w3 ^ w1) >> 31u));
    let w18 = (((w15 ^ w10 ^ w4 ^ w2) << 1u) | ((w15 ^ w10 ^ w4 ^ w2) >> 31u));
    let w19 = (((w16 ^ w11 ^ w5 ^ w3) << 1u) | ((w16 ^ w11 ^ w5 ^ w3) >> 31u));
    let w20 = (((w17 ^ w12 ^ w6 ^ w4) << 1u) | ((w17 ^ w12 ^ w6 ^ w4) >> 31u));
    let w21 = (((w18 ^ w13 ^ w7 ^ w5) << 1u) | ((w18 ^ w13 ^ w7 ^ w5) >> 31u));
    let w22 = (((w19 ^ w14 ^ w8 ^ w6) << 1u) | ((w19 ^ w14 ^ w8 ^ w6) >> 31u));
    let w23 = (((w20 ^ w15 ^ w9 ^ w7) << 1u) | ((w20 ^ w15 ^ w9 ^ w7) >> 31u));
    let w24 = (((w21 ^ w16 ^ w10 ^ w8) << 1u) | ((w21 ^ w16 ^ w10 ^ w8) >> 31u));
    let w25 = (((w22 ^ w17 ^ w11 ^ w9) << 1u) | ((w22 ^ w17 ^ w11 ^ w9) >> 31u));
    let w26 = (((w23 ^ w18 ^ w12 ^ w10) << 1u) | ((w23 ^ w18 ^ w12 ^ w10) >> 31u));
    let w27 = (((w24 ^ w19 ^ w13 ^ w11) << 1u) | ((w24 ^ w19 ^ w13 ^ w11) >> 31u));
    let w28 = (((w25 ^ w20 ^ w14 ^ w12) << 1u) | ((w25 ^ w20 ^ w14 ^ w12) >> 31u));
    let w29 = (((w26 ^ w21 ^ w15 ^ w13) << 1u) | ((w26 ^ w21 ^ w15 ^ w13) >> 31u));
    let w30 = (((w27 ^ w22 ^ w16 ^ w14) << 1u) | ((w27 ^ w22 ^ w16 ^ w14) >> 31u));
    let w31 = (((w28 ^ w23 ^ w17 ^ w15) << 1u) | ((w28 ^ w23 ^ w17 ^ w15) >> 31u));
    let w32 = (((w26 ^ w16 ^ w4 ^ w0) << 2u) | ((w26 ^ w16 ^ w4 ^ w0) >> 30u));
    let w33 = (((w27 ^ w17 ^ w5 ^ w1) << 2u) | ((w27 ^ w17 ^ w5 ^ w1) >> 30u));
    let w34 = (((w28 ^ w18 ^ w6 ^ w2) << 2u) | ((w28 ^ w18 ^ w6 ^ w2) >> 30u));
    let w35 = (((w29 ^ w19 ^ w7 ^ w3) << 2u) | ((w29 ^ w19 ^ w7 ^ w3) >> 30u));
    let w36 = (((w30 ^ w20 ^ w8 ^ w4) << 2u) | ((w30 ^ w20 ^ w8 ^ w4) >> 30u));
    let w37 = (((w31 ^ w21 ^ w9 ^ w5) << 2u) | ((w31 ^ w21 ^ w9 ^ w5) >> 30u));
    let w38 = (((w32 ^ w22 ^ w10 ^ w6) << 2u) | ((w32 ^ w22 ^ w10 ^ w6) >> 30u));
    let w39 = (((w33 ^ w23 ^ w11 ^ w7) << 2u) | ((w33 ^ w23 ^ w11 ^ w7) >> 30u));
    let w40 = (((w34 ^ w24 ^ w12 ^ w8) << 2u) | ((w34 ^ w24 ^ w12 ^ w8) >> 30u));
    let w41 = (((w35 ^ w25 ^ w13 ^ w9) << 2u) | ((w35 ^ w25 ^ w13 ^ w9) >> 30u));
    let w42 = (((w36 ^ w26 ^ w14 ^ w10) << 2u) | ((w36 ^ w26 ^ w14 ^ w10) >> 30u));
    let w43 = (((w37 ^ w27 ^ w15 ^ w11) << 2u) | ((w37 ^ w27 ^ w15 ^ w11) >> 30u));
    let w44 = (((w38 ^ w28 ^ w16 ^ w12) << 2u) | ((w38 ^ w28 ^ w16 ^ w12) >> 30u));
    let w45 = (((w39 ^ w29 ^ w17 ^ w13) << 2u) | ((w39 ^ w29 ^ w17 ^ w13) >> 30u));
    let w46 = (((w40 ^ w30 ^ w18 ^ w14) << 2u) | ((w40 ^ w30 ^ w18 ^ w14) >> 30u));
    let w47 = (((w41 ^ w31 ^ w19 ^ w15) << 2u) | ((w41 ^ w31 ^ w19 ^ w15) >> 30u));
    let w48 = (((w42 ^ w32 ^ w20 ^ w16) << 2u) | ((w42 ^ w32 ^ w20 ^ w16) >> 30u));
    let w49 = (((w43 ^ w33 ^ w21 ^ w17) << 2u) | ((w43 ^ w33 ^ w21 ^ w17) >> 30u));
    let w50 = (((w44 ^ w34 ^ w22 ^ w18) << 2u) | ((w44 ^ w34 ^ w22 ^ w18) >> 30u));
    let w51 = (((w45 ^ w35 ^ w23 ^ w19) << 2u) | ((w45 ^ w35 ^ w23 ^ w19) >> 30u));
    let w52 = (((w46 ^ w36 ^ w24 ^ w20) << 2u) | ((w46 ^ w36 ^ w24 ^ w20) >> 30u));
    let w53 = (((w47 ^ w37 ^ w25 ^ w21) << 2u) | ((w47 ^ w37 ^ w25 ^ w21) >> 30u));
    let w54 = (((w48 ^ w38 ^ w26 ^ w22) << 2u) | ((w48 ^ w38 ^ w26 ^ w22) >> 30u));
    let w55 = (((w49 ^ w39 ^ w27 ^ w23) << 2u) | ((w49 ^ w39 ^ w27 ^ w23) >> 30u));
    let w56 = (((w50 ^ w40 ^ w28 ^ w24) << 2u) | ((w50 ^ w40 ^ w28 ^ w24) >> 30u));
    let w57 = (((w51 ^ w41 ^ w29 ^ w25) << 2u) | ((w51 ^ w41 ^ w29 ^ w25) >> 30u));
    let w58 = (((w52 ^ w42 ^ w30 ^ w26) << 2u) | ((w52 ^ w42 ^ w30 ^ w26) >> 30u));
    let w59 = (((w53 ^ w43 ^ w31 ^ w27) << 2u) | ((w53 ^ w43 ^ w31 ^ w27) >> 30u));
    let w60 = (((w54 ^ w44 ^ w32 ^ w28) << 2u) | ((w54 ^ w44 ^ w32 ^ w28) >> 30u));
    let w61 = (((w55 ^ w45 ^ w33 ^ w29) << 2u) | ((w55 ^ w45 ^ w33 ^ w29) >> 30u));
    let w62 = (((w56 ^ w46 ^ w34 ^ w30) << 2u) | ((w56 ^ w46 ^ w34 ^ w30) >> 30u));
    let w63 = (((w57 ^ w47 ^ w35 ^ w31) << 2u) | ((w57 ^ w47 ^ w35 ^ w31) >> 30u));
    let w64 = (((w58 ^ w48 ^ w36 ^ w32) << 2u) | ((w58 ^ w48 ^ w36 ^ w32) >> 30u));
    let w65 = (((w59 ^ w49 ^ w37 ^ w33) << 2u) | ((w59 ^ w49 ^ w37 ^ w33) >> 30u));
    let w66 = (((w60 ^ w50 ^ w38 ^ w34) << 2u) | ((w60 ^ w50 ^ w38 ^ w34) >> 30u));
    let w67 = (((w61 ^ w51 ^ w39 ^ w35) << 2u) | ((w61 ^ w51 ^ w39 ^ w35) >> 30u));
    let w68 = (((w62 ^ w52 ^ w40 ^ w36) << 2u) | ((w62 ^ w52 ^ w40 ^ w36) >> 30u));
    let w69 = (((w63 ^ w53 ^ w41 ^ w37) << 2u) | ((w63 ^ w53 ^ w41 ^ w37) >> 30u));
    let w70 = (((w64 ^ w54 ^ w42 ^ w38) << 2u) | ((w64 ^ w54 ^ w42 ^ w38) >> 30u));
    let w71 = (((w65 ^ w55 ^ w43 ^ w39) << 2u) | ((w65 ^ w55 ^ w43 ^ w39) >> 30u));
    let w72 = (((w66 ^ w56 ^ w44 ^ w40) << 2u) | ((w66 ^ w56 ^ w44 ^ w40) >> 30u));
    let w73 = (((w67 ^ w57 ^ w45 ^ w41) << 2u) | ((w67 ^ w57 ^ w45 ^ w41) >> 30u));
    let w74 = (((w68 ^ w58 ^ w46 ^ w42) << 2u) | ((w68 ^ w58 ^ w46 ^ w42) >> 30u));
    let w75 = (((w69 ^ w59 ^ w47 ^ w43) << 2u) | ((w69 ^ w59 ^ w47 ^ w43) >> 30u));
    let w76 = (((w70 ^ w60 ^ w48 ^ w44) << 2u) | ((w70 ^ w60 ^ w48 ^ w44) >> 30u));
    let w77 = (((w71 ^ w61 ^ w49 ^ w45) << 2u) | ((w71 ^ w61 ^ w49 ^ w45) >> 30u));
    let w78 = (((w72 ^ w62 ^ w50 ^ w46) << 2u) | ((w72 ^ w62 ^ w50 ^ w46) >> 30u));
    let w79 = (((w73 ^ w63 ^ w51 ^ w47) << 2u) | ((w73 ^ w63 ^ w51 ^ w47) >> 30u));
    var a = (*state_in)[0];
    var b = (*state_in)[1];
    var c = (*state_in)[2];
    var d = (*state_in)[3];
    var e = (*state_in)[4];
    { let tmp = ((a << 5u) | (a >> 27u)) + (d ^ (b & (c ^ d))) + e + 0x5a827999u + w0; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (d ^ (b & (c ^ d))) + e + 0x5a827999u + w1; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (d ^ (b & (c ^ d))) + e + 0x5a827999u + w2; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (d ^ (b & (c ^ d))) + e + 0x5a827999u + w3; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (d ^ (b & (c ^ d))) + e + 0x5a827999u + w4; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (d ^ (b & (c ^ d))) + e + 0x5a827999u + w5; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (d ^ (b & (c ^ d))) + e + 0x5a827999u + w6; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (d ^ (b & (c ^ d))) + e + 0x5a827999u + w7; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (d ^ (b & (c ^ d))) + e + 0x5a827999u + w8; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (d ^ (b & (c ^ d))) + e + 0x5a827999u + w9; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (d ^ (b & (c ^ d))) + e + 0x5a827999u + w10; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (d ^ (b & (c ^ d))) + e + 0x5a827999u + w11; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (d ^ (b & (c ^ d))) + e + 0x5a827999u + w12; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (d ^ (b & (c ^ d))) + e + 0x5a827999u + w13; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (d ^ (b & (c ^ d))) + e + 0x5a827999u + w14; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (d ^ (b & (c ^ d))) + e + 0x5a827999u + w15; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (d ^ (b & (c ^ d))) + e + 0x5a827999u + w16; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (d ^ (b & (c ^ d))) + e + 0x5a827999u + w17; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (d ^ (b & (c ^ d))) + e + 0x5a827999u + w18; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (d ^ (b & (c ^ d))) + e + 0x5a827999u + w19; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0x6ed9eba1u + w20; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0x6ed9eba1u + w21; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0x6ed9eba1u + w22; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0x6ed9eba1u + w23; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0x6ed9eba1u + w24; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0x6ed9eba1u + w25; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0x6ed9eba1u + w26; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0x6ed9eba1u + w27; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0x6ed9eba1u + w28; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0x6ed9eba1u + w29; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0x6ed9eba1u + w30; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0x6ed9eba1u + w31; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0x6ed9eba1u + w32; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0x6ed9eba1u + w33; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0x6ed9eba1u + w34; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0x6ed9eba1u + w35; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0x6ed9eba1u + w36; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0x6ed9eba1u + w37; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0x6ed9eba1u + w38; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0x6ed9eba1u + w39; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) ^ (d & (b ^ c))) + e + 0x8f1bbcdcu + w40; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) ^ (d & (b ^ c))) + e + 0x8f1bbcdcu + w41; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) ^ (d & (b ^ c))) + e + 0x8f1bbcdcu + w42; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) ^ (d & (b ^ c))) + e + 0x8f1bbcdcu + w43; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) ^ (d & (b ^ c))) + e + 0x8f1bbcdcu + w44; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) ^ (d & (b ^ c))) + e + 0x8f1bbcdcu + w45; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) ^ (d & (b ^ c))) + e + 0x8f1bbcdcu + w46; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) ^ (d & (b ^ c))) + e + 0x8f1bbcdcu + w47; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) ^ (d & (b ^ c))) + e + 0x8f1bbcdcu + w48; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) ^ (d & (b ^ c))) + e + 0x8f1bbcdcu + w49; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) ^ (d & (b ^ c))) + e + 0x8f1bbcdcu + w50; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) ^ (d & (b ^ c))) + e + 0x8f1bbcdcu + w51; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) ^ (d & (b ^ c))) + e + 0x8f1bbcdcu + w52; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) ^ (d & (b ^ c))) + e + 0x8f1bbcdcu + w53; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) ^ (d & (b ^ c))) + e + 0x8f1bbcdcu + w54; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) ^ (d & (b ^ c))) + e + 0x8f1bbcdcu + w55; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) ^ (d & (b ^ c))) + e + 0x8f1bbcdcu + w56; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) ^ (d & (b ^ c))) + e + 0x8f1bbcdcu + w57; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) ^ (d & (b ^ c))) + e + 0x8f1bbcdcu + w58; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) ^ (d & (b ^ c))) + e + 0x8f1bbcdcu + w59; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0xca62c1d6u + w60; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0xca62c1d6u + w61; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0xca62c1d6u + w62; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0xca62c1d6u + w63; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0xca62c1d6u + w64; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0xca62c1d6u + w65; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0xca62c1d6u + w66; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0xca62c1d6u + w67; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0xca62c1d6u + w68; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0xca62c1d6u + w69; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0xca62c1d6u + w70; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0xca62c1d6u + w71; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0xca62c1d6u + w72; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0xca62c1d6u + w73; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0xca62c1d6u + w74; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0xca62c1d6u + w75; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0xca62c1d6u + w76; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0xca62c1d6u + w77; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0xca62c1d6u + w78; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + (b ^ c ^ d) + e + 0xca62c1d6u + w79; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    (*state_in)[0] = (*state_in)[0] + a;
    (*state_in)[1] = (*state_in)[1] + b;
    (*state_in)[2] = (*state_in)[2] + c;
    (*state_in)[3] = (*state_in)[3] + d;
    (*state_in)[4] = (*state_in)[4] + e;
}

// Build the standard outer-leg block for HMAC whose inner digest is `h`:
// h[0..5] || 0x80 || zeros || bitlen (always 672 = (64+20)*8 here).
fn outer_block(h: array<u32, 5u>) -> array<u32, 16u> {
    return array<u32, 16u>(h[0], h[1], h[2], h[3], h[4], 0x80000000u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 672u);
}

// U1/U2: inner compress over the host-precomputed padded salt||counter
// message from the ipad midstate, outer over the opad midstate.
fn hmac_first(ipad: array<u32, 5u>, opad: array<u32, 5u>, msg: array<u32, 16u>) -> array<u32, 5u> {
    var st = ipad;
    var m = msg;
    sha1_compress(&st, &m);
    var st2 = opad;
    var ob = outer_block(st);
    sha1_compress(&st2, &ob);
    return st2;
}

// One chained PBKDF2 iteration: U = HMAC(U) via the pad midstates.
fn hmac_mid(u: ptr<function, array<u32, 5u>>, ipad: ptr<function, array<u32, 5u>>, opad: ptr<function, array<u32, 5u>>) {
    var st = *ipad;
    var m = outer_block(*u);
    sha1_compress(&st, &m);
    var st2 = *opad;
    var ob = outer_block(st);
    sha1_compress(&st2, &ob);
    *u = st2;
}

// HMAC over host-pre-padded message blocks (`which`: 0 = params.blk1,
// 1 = params.blk2), starting from the pad midstates. `n` <= 3.
fn hmac_padded(ipad: array<u32, 5u>, opad: array<u32, 5u>, which: u32, n: u32) -> array<u32, 5u> {
    var st = ipad;
    for (var b = 0u; b < n; b = b + 1u) {
        var m: array<u32, 16u>;
        for (var j = 0u; j < 16u; j = j + 1u) {
            m[j] = select(params.blk1[b * 16u + j], params.blk2[b * 16u + j], which == 1u);
        }
        sha1_compress(&st, &m);
    }
    var st2 = opad;
    var ob = outer_block(st);
    sha1_compress(&st2, &ob);
    return st2;
}

// Per-candidate HMAC pad midstates from the raw password key block.
fn key_midstates(base: u32) -> array<array<u32, 5u>, 2u> {
    var ib: array<u32, 16u>;
    var ob: array<u32, 16u>;
    for (var i = 0u; i < 16u; i = i + 1u) {
        let kb = candidates[base + i];
        ib[i] = kb ^ 0x36363636u;
        ob[i] = kb ^ 0x5c5c5c5cu;
    }
    var ipad = IV;
    sha1_compress(&ipad, &ib);
    var opad = IV;
    sha1_compress(&opad, &ob);
    return array<array<u32, 5u>, 2u>(ipad, opad);
}

// HMAC pad midstates for an 8-word key (the PMK) or 4-word key (KCK):
// key words in w[0..word_count), rest of the 64-byte block zero — both
// folded into the pad XOR (x ^ 0 == x).
fn short_key_midstates(w0: u32, w1: u32, w2: u32, w3: u32, word_count: u32) -> array<array<u32, 5u>, 2u> {
    var ib: array<u32, 16u>;
    var ob: array<u32, 16u>;
    let ws = array<u32, 4u>(w0, w1, w2, w3);
    for (var i = 0u; i < 16u; i = i + 1u) {
        var kb = 0u;
        if i < word_count {
            kb = ws[i];
        }
        ib[i] = kb ^ 0x36363636u;
        ob[i] = kb ^ 0x5c5c5c5cu;
    }
    var ipad = IV;
    sha1_compress(&ipad, &ib);
    var opad = IV;
    sha1_compress(&opad, &ob);
    return array<array<u32, 5u>, 2u>(ipad, opad);
}

// The PBKDF2 core: midstates -> U1/U2 -> 4095 chained iterations.
// Returns PMK words (BE): t1[0..5] || t2[0..3] packed in a 16-word block.
fn pbkdf2_chain(base: u32) -> array<u32, 16u> {
    let mids = key_midstates(base);
    var ipad = mids[0];
    var opad = mids[1];
    var u1 = hmac_first(ipad, opad, params.u1_msg);
    var u2 = hmac_first(ipad, opad, params.u2_msg);

    var t1 = u1;
    var t2 = u2;
    let iterations = params.flags >> 1u;
    for (var i = 1u; i < iterations; i = i + 1u) {
        hmac_mid(&u1, &ipad, &opad);
        t1[0] = t1[0] ^ u1[0];
        t1[1] = t1[1] ^ u1[1];
        t1[2] = t1[2] ^ u1[2];
        t1[3] = t1[3] ^ u1[3];
        t1[4] = t1[4] ^ u1[4];
        hmac_mid(&u2, &ipad, &opad);
        // Tail cut: PMK needs only t2[10..12] bytes → never accumulate
        // t2[3]/t2[4] (u2 itself stays complete for the chain).
        t2[0] = t2[0] ^ u2[0];
        t2[1] = t2[1] ^ u2[1];
        t2[2] = t2[2] ^ u2[2];
    }
    var pk: array<u32, 16u>;
    for (var i = 0u; i < 5u; i = i + 1u) { pk[i] = t1[i]; }
    for (var i = 0u; i < 3u; i = i + 1u) { pk[5u + i] = t2[i]; }
    for (var i = 8u; i < 16u; i = i + 1u) { pk[i] = 0u; }
    return pk;
}

@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let idx = gid.x;
    if idx >= params.n {
        return;
    }
    let base = idx * 16u;
    var pk = pbkdf2_chain(base);

    // Epilogue: match the candidate's PMK against the capture on-device.
    // PMK midstates (32-byte key: all 8 words of pk[0..8]).
    var pk_ib: array<u32, 16u>;
    var pk_ob: array<u32, 16u>;
    for (var i = 0u; i < 16u; i = i + 1u) {
        var kb = 0u;
        if i < 8u {
            kb = pk[i];
        }
        pk_ib[i] = kb ^ 0x36363636u;
        pk_ob[i] = kb ^ 0x5c5c5c5cu;
    }
    var pk_ipad = IV;
    sha1_compress(&pk_ipad, &pk_ib);
    var pk_opad = IV;
    sha1_compress(&pk_opad, &pk_ob);

    let val1 = hmac_padded(pk_ipad, pk_opad, 0u, params.n_blk1);

    var matched = false;
    if params.is_pmkid == 1u {
        matched = val1[0] == params.mic[0] && val1[1] == params.mic[1]
            && val1[2] == params.mic[2] && val1[3] == params.mic[3];
    } else {
        // KCK = first 4 words; MIC = HMAC-SHA1(KCK, zeroed EAPOL).
        let kmids = short_key_midstates(val1[0], val1[1], val1[2], val1[3], 4u);
        let mval = hmac_padded(kmids[0], kmids[1], 1u, params.n_blk2);
        matched = mval[0] == params.mic[0] && mval[1] == params.mic[1]
            && mval[2] == params.mic[2] && mval[3] == params.mic[3];
    }
    if matched {
        // Recoverable word is whatever the flag write publishes; the host
        // reads both words after full dispatch completion (no torn race).
        atomicStore(&hits[1u], idx);
        atomicStore(&hits[0u], 1u);
    }
}

// Rainbow-build entry: PMK out (no verify epilogue).
@compute @workgroup_size(256)
fn pmk_out(@builtin(global_invocation_id) gid: vec3<u32>) {
    let idx = gid.x;
    if idx >= params.n {
        return;
    }
    let base = idx * 16u;
    let pk = pbkdf2_chain(base);
    let base_out = idx * 10u;
    for (var i = 0u; i < 8u; i = i + 1u) {
        outputs[base_out + i] = pk[i];
    }
}
