// PBKDF2-HMAC-SHA1 inner-loop kernel for WPA2-PSK cracking (WGSL).
//
// The host precomputes, per candidate passphrase P and fixed salt (ESSID):
//   ipad_state = SHA1 state after absorbing (P^ipad) || salt    (5×u32)
//   opad_state = SHA1 state after absorbing (P^opad) || 0x00*44 (5×u32)
//   u1  = digest words of HMAC(P, salt||INT32BE(1))   (5×u32, BE)
//   u2  = digest words of HMAC(P, salt||INT32BE(2))   (5×u32, BE)
//
// Each invocation continues the PBKDF2 loop from iteration 2 to 4096 for both
// 20-byte blocks:
//   U_i = HMAC_via_midstates(U_{i-1}); T ^= U_i
// HMAC_via_midstates(x) with a 20-byte message is exactly two SHA1 compresses:
//   inner = compress(ipad_state, x||0x80||0x00*35||0x000002dc)
//   outer = compress(opad_state, inner||0x80||0x00*35||0x00000294)
// Emit per candidate 40 bytes: T1||T2 (PBKDF2 dkLen=40); the host slices
// PMK = T1 || T2[0..12].

struct Params {
    // (iteration_count << 1) | cmac_flag. iteration_count is the PBKDF2 c
    // value (4096); the kernel runs c-1 chained rounds after U1/U2.
    // cmac_flag is informational (host uses it to pick the reference path in
    // tests); MIC computation always happens on the host.
    flags: u32,
    pad0: u32,
    pad1: u32,
    pad2: u32,
}

@group(0) @binding(0) var<uniform> params: Params;
@group(0) @binding(1) var<storage, read> midstates: array<u32>; // 20 u32 / candidate
@group(0) @binding(2) var<storage, read_write> outputs: array<u32>; // 10 u32 / candidate

// One SHA1 compression: state (5×u32) over exactly one 64-byte block.
// All 80 rounds are unrolled: dynamic array indexing would demote
// w[80] to scratch memory and multiply every compress by memory ops.
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
    let w32 = (((w29 ^ w24 ^ w18 ^ w16) << 1u) | ((w29 ^ w24 ^ w18 ^ w16) >> 31u));
    let w33 = (((w30 ^ w25 ^ w19 ^ w17) << 1u) | ((w30 ^ w25 ^ w19 ^ w17) >> 31u));
    let w34 = (((w31 ^ w26 ^ w20 ^ w18) << 1u) | ((w31 ^ w26 ^ w20 ^ w18) >> 31u));
    let w35 = (((w32 ^ w27 ^ w21 ^ w19) << 1u) | ((w32 ^ w27 ^ w21 ^ w19) >> 31u));
    let w36 = (((w33 ^ w28 ^ w22 ^ w20) << 1u) | ((w33 ^ w28 ^ w22 ^ w20) >> 31u));
    let w37 = (((w34 ^ w29 ^ w23 ^ w21) << 1u) | ((w34 ^ w29 ^ w23 ^ w21) >> 31u));
    let w38 = (((w35 ^ w30 ^ w24 ^ w22) << 1u) | ((w35 ^ w30 ^ w24 ^ w22) >> 31u));
    let w39 = (((w36 ^ w31 ^ w25 ^ w23) << 1u) | ((w36 ^ w31 ^ w25 ^ w23) >> 31u));
    let w40 = (((w37 ^ w32 ^ w26 ^ w24) << 1u) | ((w37 ^ w32 ^ w26 ^ w24) >> 31u));
    let w41 = (((w38 ^ w33 ^ w27 ^ w25) << 1u) | ((w38 ^ w33 ^ w27 ^ w25) >> 31u));
    let w42 = (((w39 ^ w34 ^ w28 ^ w26) << 1u) | ((w39 ^ w34 ^ w28 ^ w26) >> 31u));
    let w43 = (((w40 ^ w35 ^ w29 ^ w27) << 1u) | ((w40 ^ w35 ^ w29 ^ w27) >> 31u));
    let w44 = (((w41 ^ w36 ^ w30 ^ w28) << 1u) | ((w41 ^ w36 ^ w30 ^ w28) >> 31u));
    let w45 = (((w42 ^ w37 ^ w31 ^ w29) << 1u) | ((w42 ^ w37 ^ w31 ^ w29) >> 31u));
    let w46 = (((w43 ^ w38 ^ w32 ^ w30) << 1u) | ((w43 ^ w38 ^ w32 ^ w30) >> 31u));
    let w47 = (((w44 ^ w39 ^ w33 ^ w31) << 1u) | ((w44 ^ w39 ^ w33 ^ w31) >> 31u));
    let w48 = (((w45 ^ w40 ^ w34 ^ w32) << 1u) | ((w45 ^ w40 ^ w34 ^ w32) >> 31u));
    let w49 = (((w46 ^ w41 ^ w35 ^ w33) << 1u) | ((w46 ^ w41 ^ w35 ^ w33) >> 31u));
    let w50 = (((w47 ^ w42 ^ w36 ^ w34) << 1u) | ((w47 ^ w42 ^ w36 ^ w34) >> 31u));
    let w51 = (((w48 ^ w43 ^ w37 ^ w35) << 1u) | ((w48 ^ w43 ^ w37 ^ w35) >> 31u));
    let w52 = (((w49 ^ w44 ^ w38 ^ w36) << 1u) | ((w49 ^ w44 ^ w38 ^ w36) >> 31u));
    let w53 = (((w50 ^ w45 ^ w39 ^ w37) << 1u) | ((w50 ^ w45 ^ w39 ^ w37) >> 31u));
    let w54 = (((w51 ^ w46 ^ w40 ^ w38) << 1u) | ((w51 ^ w46 ^ w40 ^ w38) >> 31u));
    let w55 = (((w52 ^ w47 ^ w41 ^ w39) << 1u) | ((w52 ^ w47 ^ w41 ^ w39) >> 31u));
    let w56 = (((w53 ^ w48 ^ w42 ^ w40) << 1u) | ((w53 ^ w48 ^ w42 ^ w40) >> 31u));
    let w57 = (((w54 ^ w49 ^ w43 ^ w41) << 1u) | ((w54 ^ w49 ^ w43 ^ w41) >> 31u));
    let w58 = (((w55 ^ w50 ^ w44 ^ w42) << 1u) | ((w55 ^ w50 ^ w44 ^ w42) >> 31u));
    let w59 = (((w56 ^ w51 ^ w45 ^ w43) << 1u) | ((w56 ^ w51 ^ w45 ^ w43) >> 31u));
    let w60 = (((w57 ^ w52 ^ w46 ^ w44) << 1u) | ((w57 ^ w52 ^ w46 ^ w44) >> 31u));
    let w61 = (((w58 ^ w53 ^ w47 ^ w45) << 1u) | ((w58 ^ w53 ^ w47 ^ w45) >> 31u));
    let w62 = (((w59 ^ w54 ^ w48 ^ w46) << 1u) | ((w59 ^ w54 ^ w48 ^ w46) >> 31u));
    let w63 = (((w60 ^ w55 ^ w49 ^ w47) << 1u) | ((w60 ^ w55 ^ w49 ^ w47) >> 31u));
    let w64 = (((w61 ^ w56 ^ w50 ^ w48) << 1u) | ((w61 ^ w56 ^ w50 ^ w48) >> 31u));
    let w65 = (((w62 ^ w57 ^ w51 ^ w49) << 1u) | ((w62 ^ w57 ^ w51 ^ w49) >> 31u));
    let w66 = (((w63 ^ w58 ^ w52 ^ w50) << 1u) | ((w63 ^ w58 ^ w52 ^ w50) >> 31u));
    let w67 = (((w64 ^ w59 ^ w53 ^ w51) << 1u) | ((w64 ^ w59 ^ w53 ^ w51) >> 31u));
    let w68 = (((w65 ^ w60 ^ w54 ^ w52) << 1u) | ((w65 ^ w60 ^ w54 ^ w52) >> 31u));
    let w69 = (((w66 ^ w61 ^ w55 ^ w53) << 1u) | ((w66 ^ w61 ^ w55 ^ w53) >> 31u));
    let w70 = (((w67 ^ w62 ^ w56 ^ w54) << 1u) | ((w67 ^ w62 ^ w56 ^ w54) >> 31u));
    let w71 = (((w68 ^ w63 ^ w57 ^ w55) << 1u) | ((w68 ^ w63 ^ w57 ^ w55) >> 31u));
    let w72 = (((w69 ^ w64 ^ w58 ^ w56) << 1u) | ((w69 ^ w64 ^ w58 ^ w56) >> 31u));
    let w73 = (((w70 ^ w65 ^ w59 ^ w57) << 1u) | ((w70 ^ w65 ^ w59 ^ w57) >> 31u));
    let w74 = (((w71 ^ w66 ^ w60 ^ w58) << 1u) | ((w71 ^ w66 ^ w60 ^ w58) >> 31u));
    let w75 = (((w72 ^ w67 ^ w61 ^ w59) << 1u) | ((w72 ^ w67 ^ w61 ^ w59) >> 31u));
    let w76 = (((w73 ^ w68 ^ w62 ^ w60) << 1u) | ((w73 ^ w68 ^ w62 ^ w60) >> 31u));
    let w77 = (((w74 ^ w69 ^ w63 ^ w61) << 1u) | ((w74 ^ w69 ^ w63 ^ w61) >> 31u));
    let w78 = (((w75 ^ w70 ^ w64 ^ w62) << 1u) | ((w75 ^ w70 ^ w64 ^ w62) >> 31u));
    let w79 = (((w76 ^ w71 ^ w65 ^ w63) << 1u) | ((w76 ^ w71 ^ w65 ^ w63) >> 31u));
    var a = (*state_in)[0];
    var b = (*state_in)[1];
    var c = (*state_in)[2];
    var d = (*state_in)[3];
    var e = (*state_in)[4];
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (~b & d)) + e + 0x5a827999u + w0; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (~b & d)) + e + 0x5a827999u + w1; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (~b & d)) + e + 0x5a827999u + w2; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (~b & d)) + e + 0x5a827999u + w3; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (~b & d)) + e + 0x5a827999u + w4; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (~b & d)) + e + 0x5a827999u + w5; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (~b & d)) + e + 0x5a827999u + w6; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (~b & d)) + e + 0x5a827999u + w7; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (~b & d)) + e + 0x5a827999u + w8; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (~b & d)) + e + 0x5a827999u + w9; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (~b & d)) + e + 0x5a827999u + w10; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (~b & d)) + e + 0x5a827999u + w11; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (~b & d)) + e + 0x5a827999u + w12; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (~b & d)) + e + 0x5a827999u + w13; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (~b & d)) + e + 0x5a827999u + w14; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (~b & d)) + e + 0x5a827999u + w15; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (~b & d)) + e + 0x5a827999u + w16; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (~b & d)) + e + 0x5a827999u + w17; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (~b & d)) + e + 0x5a827999u + w18; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (~b & d)) + e + 0x5a827999u + w19; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
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
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (b & d) | (c & d)) + e + 0x8f1bbcdcu + w40; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (b & d) | (c & d)) + e + 0x8f1bbcdcu + w41; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (b & d) | (c & d)) + e + 0x8f1bbcdcu + w42; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (b & d) | (c & d)) + e + 0x8f1bbcdcu + w43; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (b & d) | (c & d)) + e + 0x8f1bbcdcu + w44; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (b & d) | (c & d)) + e + 0x8f1bbcdcu + w45; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (b & d) | (c & d)) + e + 0x8f1bbcdcu + w46; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (b & d) | (c & d)) + e + 0x8f1bbcdcu + w47; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (b & d) | (c & d)) + e + 0x8f1bbcdcu + w48; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (b & d) | (c & d)) + e + 0x8f1bbcdcu + w49; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (b & d) | (c & d)) + e + 0x8f1bbcdcu + w50; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (b & d) | (c & d)) + e + 0x8f1bbcdcu + w51; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (b & d) | (c & d)) + e + 0x8f1bbcdcu + w52; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (b & d) | (c & d)) + e + 0x8f1bbcdcu + w53; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (b & d) | (c & d)) + e + 0x8f1bbcdcu + w54; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (b & d) | (c & d)) + e + 0x8f1bbcdcu + w55; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (b & d) | (c & d)) + e + 0x8f1bbcdcu + w56; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (b & d) | (c & d)) + e + 0x8f1bbcdcu + w57; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (b & d) | (c & d)) + e + 0x8f1bbcdcu + w58; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
    { let tmp = ((a << 5u) | (a >> 27u)) + ((b & c) | (b & d) | (c & d)) + e + 0x8f1bbcdcu + w59; e = d; d = c; c = ((b << 30u) | (b >> 2u)); b = a; a = tmp; }
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

// Message block layout for HMAC of a 20-byte value after a 64-byte presalt
// midstate/absorbed prefix: x[0..5] || 0x80 || zeros || 32-bit BE bit-length.
fn hmac_block(u: ptr<function, array<u32, 5u>>, bitlen: u32) -> array<u32, 16u> {
    var blk: array<u32, 16u>;
    blk[0] = (*u)[0];
    blk[1] = (*u)[1];
    blk[2] = (*u)[2];
    blk[3] = (*u)[3];
    blk[4] = (*u)[4];
    blk[5] = 0x80000000u;
    for (var i = 6u; i < 15u; i = i + 1u) {
        blk[i] = 0u;
    }
    blk[15] = bitlen;
    return blk;
}

// U = HMAC(pad midstates, U) — two compressions. The message seen by each leg
// (after the absorbed 64-byte pad prefix) is 64 + 20 = 84 bytes = 672 bits.
fn hmac_mid(u: ptr<function, array<u32, 5u>>, ipad: ptr<function, array<u32, 5u>>, opad: ptr<function, array<u32, 5u>>) {
    var in_state: array<u32, 5u> = *ipad;
    var blk = hmac_block(u, 672u);
    sha1_compress(&in_state, &blk);

    var out_state: array<u32, 5u> = *opad;
    var blk2 = hmac_block(&in_state, 672u);
    sha1_compress(&out_state, &blk2);

    *u = out_state;
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let idx = gid.x;
    if idx >= arrayLength(&outputs) / 10u {
        return;
    }

    let base_in = idx * 20u;
    var ipad: array<u32, 5u>;
    var opad: array<u32, 5u>;
    var u1: array<u32, 5u>;
    var u2: array<u32, 5u>;
    for (var i = 0u; i < 5u; i = i + 1u) {
        ipad[i] = midstates[base_in + i];
        opad[i] = midstates[base_in + 5u + i];
        u1[i] = midstates[base_in + 10u + i];
        u2[i] = midstates[base_in + 15u + i];
    }

    let iterations = params.flags >> 1u;

    var t1 = u1;
    var t2 = u2;
    for (var i = 1u; i < iterations; i = i + 1u) {
        hmac_mid(&u1, &ipad, &opad);
        t1[0] = t1[0] ^ u1[0];
        t1[1] = t1[1] ^ u1[1];
        t1[2] = t1[2] ^ u1[2];
        t1[3] = t1[3] ^ u1[3];
        t1[4] = t1[4] ^ u1[4];
        hmac_mid(&u2, &ipad, &opad);
        t2[0] = t2[0] ^ u2[0];
        t2[1] = t2[1] ^ u2[1];
        t2[2] = t2[2] ^ u2[2];
        t2[3] = t2[3] ^ u2[3];
        t2[4] = t2[4] ^ u2[4];
    }

    let base_out = idx * 10u;
    for (var i = 0u; i < 5u; i = i + 1u) {
        outputs[base_out + i] = t1[i];
    }
    for (var i = 0u; i < 5u; i = i + 1u) {
        outputs[base_out + 5u + i] = t2[i];
    }
}
