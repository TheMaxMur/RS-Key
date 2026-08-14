// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! SLIP-0039 Shamir share encoding for a 256-bit seed, on-device.
//!
//! The trusted display shows the recovery seed as `T`-of-`N` Shamir shares derived **on the
//! device**, so the seed never crosses USB. This is the *generate* direction only
//! (secret → share mnemonics): the host keeps the combine/restore path (its
//! `shamir_mnemonic` library). The two must agree exactly, which a deterministic host-vector
//! test pins byte-for-byte.
//!
//! Every parameter mirrors the host `rsk backup export --scheme slip39`, i.e.
//! `generate_mnemonics(1, [(T, N)], seed, b"", extendable=False, iteration_exponent=1)`:
//! a single group, group threshold 1, **non-extendable** backup (customization string
//! `"shamir"`), iteration exponent 1, empty passphrase. A 256-bit secret encodes to
//! [`WORDS_PER_SHARE`] (= 33) words per share.
//!
//! `no_std`, no alloc. The generated word indices reconstruct the seed (any `T` of them), so
//! they are secret — the **caller zeroizes** the output once the shares are rendered.

#![no_std]

mod wordlist;
// The raw table stays crate-internal; [`word`] is the only public accessor (no external
// consumer needs the whole list, and a tighter surface is better for a security-key crate).
pub(crate) use wordlist::WORDS;

use zeroize::Zeroize;

/// The master-secret length this crate splits (256-bit seed).
pub const SECRET_LEN: usize = 32;
/// Words per share for a 256-bit secret: metadata (7) + value (26). See `VALUE_WORDS`.
pub const WORDS_PER_SHARE: usize = 33;
/// `MAX_SHARE_COUNT` from SLIP-0039 — the most shares one group can hold.
pub const MAX_SHARES: usize = 16;

const ITER_EXP_BITS: u32 = 4;
const EXTENDABLE_BITS: u32 = 1;
const ID_EXP_WORDS: usize = 2; // bits_to_words(15 id + 1 ext + 4 iter) = 2
const CHECKSUM_WORDS: usize = 3;
const VALUE_WORDS: usize = 26; // bits_to_words(256)
const DIGEST_LEN: usize = 4;
const RANDOM_PART_LEN: usize = SECRET_LEN - DIGEST_LEN; // 28
const SECRET_X: u8 = 255; // SECRET_INDEX
const DIGEST_X: u8 = 254; // DIGEST_INDEX

// extendable = false → the original customization string (also the PBKDF2 salt prefix) and
// iteration exponent 1, matching the host call. Both are baked in: the device only ever
// produces shares the host `rsk backup restore` can recombine, so they are not configurable.
const ITER_EXP: u32 = 1;
const CUSTOMIZATION: [u8; 6] = *b"shamir";
const BASE_ITERATIONS: u32 = 10000;
const ROUNDS: usize = 4;
/// PBKDF2 iterations per Feistel round: `(BASE_ITERATION_COUNT << e) / ROUND_COUNT`.
const ITERS_PER_ROUND: u32 = (BASE_ITERATIONS << ITER_EXP) / ROUNDS as u32; // 5000

const _: () = {
    // The share layout the word count assumes: id_exp(2) + params(2) + value(26) + cksum(3).
    assert!(ID_EXP_WORDS + 2 + VALUE_WORDS + CHECKSUM_WORDS == WORDS_PER_SHARE);
    assert!(ITERS_PER_ROUND == 5000);
    assert!(DIGEST_LEN + RANDOM_PART_LEN == SECRET_LEN);
};

/// Why [`generate`] refused — all caught before any randomness or work is consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// `threshold` is 0, or exceeds `count`.
    BadThreshold,
    /// `count` is 0, or exceeds [`MAX_SHARES`].
    BadCount,
}

/// One generated share: its [`WORDS_PER_SHARE`] ten-bit word indices (each `< 1024`, so it
/// always indexes `WORDS` in bounds — proven by the `indices_in_range` Kani harness). The
/// shares are secret (any `threshold` of them reconstruct the seed); zeroize after rendering.
pub type ShareWords = [u16; WORDS_PER_SHARE];

/// The SLIP-39 word for `index` (`0..1024`). Indices from [`generate`] are always in range;
/// an out-of-range index panics (a programming error).
pub fn word(index: u16) -> &'static str {
    WORDS[index as usize]
}

/// Split a 256-bit `secret` into `threshold`-of-`count` SLIP-39 shares, writing each share's
/// word indices into `out[..count]`. Bit-for-bit compatible with the host
/// `rsk backup ... --scheme slip39` (single group, non-extendable, iteration exponent 1,
/// empty passphrase), so the host can recombine the shares the device shows.
///
/// `rng` fills a buffer with cryptographic randomness; it is consumed in the host's exact
/// order — the 15-bit identifier first (2 bytes), then the member split's random data — so a
/// deterministic source reproduces a known vector (see the host-vector tests).
pub fn generate<F: FnMut(&mut [u8])>(
    secret: &[u8; SECRET_LEN],
    threshold: u8,
    count: u8,
    rng: &mut F,
    out: &mut [ShareWords; MAX_SHARES],
) -> Result<(), Error> {
    if count == 0 || count as usize > MAX_SHARES {
        return Err(Error::BadCount);
    }
    if threshold == 0 || threshold > count {
        return Err(Error::BadThreshold);
    }

    // 15-bit random identifier (the first randomness the host draws), so vectors line up.
    let mut idb = [0u8; 2];
    rng(&mut idb);
    let identifier = (((idb[0] as u16) << 8) | idb[1] as u16) & ((1 << 15) - 1);
    idb.zeroize();

    // Encrypt the master secret (4-round Feistel), then split the ciphertext. With group
    // threshold 1 and a single group, the group layer is the identity (group secret =
    // ciphertext), so the device only performs the member split.
    let mut ems = cipher_encrypt(secret, identifier);

    let mut data = [[0u8; SECRET_LEN]; MAX_SHARES];
    split_secret(threshold, count as usize, &ems, rng, &mut data);

    for (i, o) in out.iter_mut().enumerate().take(count as usize) {
        *o = encode_share(identifier, threshold, i as u8, &data[i]);
    }

    ems.zeroize();
    data.zeroize();
    Ok(())
}

// === Shamir secret sharing over GF(256) ===

/// GF(256) exp/log tables (reducing polynomial `x^8 + x^4 + x^3 + x + 1`, generator `x + 1`),
/// computed exactly as the SLIP-0039 reference `_precompute_exp_log`.
const fn gf_tables() -> ([u8; 255], [u8; 256]) {
    let mut exp = [0u8; 255];
    let mut log = [0u8; 256];
    let mut poly: u16 = 1;
    let mut i = 0;
    while i < 255 {
        exp[i] = poly as u8;
        log[poly as usize] = i as u8;
        poly = (poly << 1) ^ poly; // multiply by (x + 1)
        if poly & 0x100 != 0 {
            poly ^= 0x11b; // reduce
        }
        i += 1;
    }
    (exp, log)
}
static EXP: [u8; 255] = gf_tables().0;
static LOG: [u8; 256] = gf_tables().1;

/// A Shamir point `(x, y)` over GF(256), `y` a 32-byte field-vector. Internal to the split;
/// the member shares' `x` are just their array index, so the public output drops `x`.
type Point = (u8, [u8; SECRET_LEN]);

/// Lagrange interpolation: `f(x)` given points `(x_i, y_i)`, byte-wise over GF(256). Mirrors
/// the reference `_interpolate`. `x` is never one of the `x_i` in this crate's use (members
/// and the secret/digest indices are disjoint), but the direct-hit branch is kept for safety.
fn interpolate(shares: &[Point], x: u8) -> [u8; SECRET_LEN] {
    for s in shares {
        if s.0 == x {
            return s.1;
        }
    }
    let mut log_prod: i32 = 0;
    for s in shares {
        log_prod += LOG[(s.0 ^ x) as usize] as i32;
    }
    let mut result = [0u8; SECRET_LEN];
    for s in shares {
        let mut inner: i32 = 0;
        for o in shares {
            inner += LOG[(s.0 ^ o.0) as usize] as i32;
        }
        let log_basis =
            (log_prod - LOG[(s.0 ^ x) as usize] as i32 - inner).rem_euclid(255) as usize;
        for (r, &v) in result.iter_mut().zip(s.1.iter()) {
            if v != 0 {
                *r ^= EXP[(LOG[v as usize] as usize + log_basis) % 255];
            }
        }
    }
    result
}

/// HMAC-SHA256(random_part, secret) truncated to 4 bytes — the reference `_create_digest`,
/// the integrity check folded into the digest share so a recombine catches a corrupt share.
fn create_digest(
    random_part: &[u8; RANDOM_PART_LEN],
    secret: &[u8; SECRET_LEN],
) -> [u8; DIGEST_LEN] {
    let mut mac = rsk_crypto::hmac_sha256(random_part, secret);
    let mut d = [0u8; DIGEST_LEN];
    d.copy_from_slice(&mac[..DIGEST_LEN]);
    mac.zeroize(); // a MAC over the secret — wipe the full output, not just the kept prefix
    d
}

/// Split a 32-byte `secret` into `count` member shares (threshold `threshold`), writing each
/// member's value into `data[i]` — the member's `x` is its index `i`. Mirrors `_split_secret`:
/// `threshold - 2` random shares, a digest share, and the secret share form the base set; the
/// remaining members are interpolated from it. `threshold == 1` returns the secret verbatim.
fn split_secret<F: FnMut(&mut [u8])>(
    threshold: u8,
    count: usize,
    secret: &[u8; SECRET_LEN],
    rng: &mut F,
    data: &mut [[u8; SECRET_LEN]; MAX_SHARES],
) {
    if threshold == 1 {
        for slot in data.iter_mut().take(count) {
            *slot = *secret;
        }
        return;
    }
    let random_count = (threshold - 2) as usize;
    for slot in data.iter_mut().take(random_count) {
        rng(slot);
    }
    let mut random_part = [0u8; RANDOM_PART_LEN];
    rng(&mut random_part);
    let digest = create_digest(&random_part, secret);

    // Base set: the random members, then the digest share (x=254) and secret share (x=255).
    let mut base = [(0u8, [0u8; SECRET_LEN]); MAX_SHARES];
    let mut nb = 0;
    for (i, d) in data.iter().enumerate().take(random_count) {
        base[nb] = (i as u8, *d);
        nb += 1;
    }
    let mut digest_share = [0u8; SECRET_LEN];
    digest_share[..DIGEST_LEN].copy_from_slice(&digest);
    digest_share[DIGEST_LEN..].copy_from_slice(&random_part);
    base[nb] = (DIGEST_X, digest_share);
    nb += 1;
    base[nb] = (SECRET_X, *secret);
    nb += 1;

    for (i, slot) in data.iter_mut().enumerate().take(count).skip(random_count) {
        *slot = interpolate(&base[..nb], i as u8);
    }

    random_part.zeroize();
    digest_share.zeroize();
    for p in base.iter_mut() {
        p.1.zeroize();
    }
}

// === Feistel cipher (PBKDF2-HMAC-SHA256 round function) ===

/// One Feistel round function: PBKDF2-HMAC-SHA256 with password `[i] ‖ ""`, salt `salt ‖ r`,
/// [`ITERS_PER_ROUND`] iterations, 16-byte output. dklen (16) ≤ HMAC width (32), so a single
/// PBKDF2 block suffices: `T_1 = U_1 ⊕ … ⊕ U_c`, truncated.
fn round_function(i: u8, salt: &[u8; 8], r: &[u8; 16]) -> [u8; 16] {
    let mut msg = [0u8; 8 + 16 + 4];
    msg[..8].copy_from_slice(salt);
    msg[8..24].copy_from_slice(r);
    msg[24..].copy_from_slice(&1u32.to_be_bytes()); // PBKDF2 block index INT(1)
    let pw = [i];
    let mut u = rsk_crypto::hmac_sha256(&pw, &msg);
    let mut acc = u;
    let mut n = 1;
    while n < ITERS_PER_ROUND {
        u = rsk_crypto::hmac_sha256(&pw, &u);
        for (a, b) in acc.iter_mut().zip(u.iter()) {
            *a ^= *b;
        }
        n += 1;
    }
    msg.zeroize();
    u.zeroize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&acc[..16]);
    acc.zeroize();
    out
}

/// The 8-byte PBKDF2 salt for the non-extendable backup: `"shamir" ‖ identifier(2, BE)`.
fn salt_of(identifier: u16) -> [u8; 8] {
    let mut s = [0u8; 8];
    s[..6].copy_from_slice(&CUSTOMIZATION);
    s[6..].copy_from_slice(&identifier.to_be_bytes());
    s
}

/// Encrypt the master secret with the 4-round Feistel network (the reference `cipher.encrypt`,
/// passphrase empty, `extendable=False`). Returns the ciphertext (the EMS) that is then split.
fn cipher_encrypt(secret: &[u8; SECRET_LEN], identifier: u16) -> [u8; SECRET_LEN] {
    let salt = salt_of(identifier);
    let mut l = [0u8; 16];
    let mut r = [0u8; 16];
    l.copy_from_slice(&secret[..16]);
    r.copy_from_slice(&secret[16..]);
    for i in 0..ROUNDS as u8 {
        let mut f = round_function(i, &salt, &r);
        let mut new_r = l;
        for (a, b) in new_r.iter_mut().zip(f.iter()) {
            *a ^= *b;
        }
        f.zeroize();
        l = r;
        r = new_r;
        // `r = new_r` copied the bytes (Copy); wipe the source slot so no half-block lingers.
        new_r.zeroize();
    }
    let mut out = [0u8; SECRET_LEN];
    out[..16].copy_from_slice(&r);
    out[16..].copy_from_slice(&l);
    l.zeroize();
    r.zeroize();
    out
}

// === Share → word-index encoding ===

/// Encode a member share `(index, value)` into its [`WORDS_PER_SHARE`] word indices: the
/// id/exp prefix, the 4-bit packed share parameters, the 26-word value, and the RS1024
/// checksum. Mirrors `Share.words` for a single non-extendable group (group index/threshold/
/// count all fixed at 0/1/1).
fn encode_share(identifier: u16, threshold: u8, index: u8, value: &[u8; SECRET_LEN]) -> ShareWords {
    let mut w = [0u16; WORDS_PER_SHARE];

    // id_exp: identifier(15) ‖ extendable(0) ‖ iteration_exponent → 20 bits → 2 words.
    let id_exp: u32 = ((identifier as u32) << (ITER_EXP_BITS + EXTENDABLE_BITS))
        | (0 << ITER_EXP_BITS)
        | ITER_EXP;
    w[0] = ((id_exp >> 10) & 0x3ff) as u16;
    w[1] = (id_exp & 0x3ff) as u16;

    // share params: group_index(0) ‖ group_threshold-1(0) ‖ group_count-1(0) ‖ index ‖
    // member_threshold-1, 4 bits each → 20 bits → 2 words.
    let params: u32 = ((index as u32) << 4) | ((threshold as u32 - 1) & 0xf);
    w[2] = ((params >> 10) & 0x3ff) as u16;
    w[3] = (params & 0x3ff) as u16;

    // value: the 256-bit big-endian integer, zero-padded on the high end to 260 bits, read
    // MSB-first in 10-bit groups (4 leading pad bits, then the 256 value bits).
    let bit = |b: usize| -> u16 {
        if b < 4 {
            0
        } else {
            let vb = b - 4;
            ((value[vb / 8] >> (7 - (vb % 8))) & 1) as u16
        }
    };
    let mut k = 0;
    while k < VALUE_WORDS {
        let mut v = 0u16;
        let mut j = 0;
        while j < 10 {
            v = (v << 1) | bit(k * 10 + j);
            j += 1;
        }
        w[4 + k] = v;
        k += 1;
    }

    let cks = rs1024_checksum(&w[..ID_EXP_WORDS + 2 + VALUE_WORDS]);
    w[30..33].copy_from_slice(&cks);
    w
}

/// RS1024 (the SLIP-0039 checksum over GF(1024)). `create_checksum` from the reference: the
/// customization string, the share data words, and three zero placeholders run through the
/// polymod; the result XOR 1 yields the three checksum words.
fn rs1024_checksum(data: &[u16]) -> [u16; CHECKSUM_WORDS] {
    const GEN: [u32; 10] = [
        0x00E0_E040,
        0x01C1_C080,
        0x0383_8100,
        0x0707_0200,
        0x0E0E_0009,
        0x1C0C_2412,
        0x3808_6C24,
        0x3090_FC48,
        0x21B1_F890,
        0x03F3_F120,
    ];
    let mut chk: u32 = 1;
    let feed = |chk: &mut u32, v: u32| {
        let b = *chk >> 20;
        *chk = ((*chk & 0xF_FFFF) << 10) ^ v;
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 != 0 {
                *chk ^= *g;
            }
        }
    };
    for &c in CUSTOMIZATION.iter() {
        feed(&mut chk, c as u32);
    }
    for &d in data {
        feed(&mut chk, d as u32);
    }
    for _ in 0..CHECKSUM_WORDS {
        feed(&mut chk, 0);
    }
    chk ^= 1;
    [
        ((chk >> 20) & 1023) as u16,
        ((chk >> 10) & 1023) as u16,
        (chk & 1023) as u16,
    ]
}

#[cfg(kani)]
#[path = "kani.rs"]
mod proofs;

#[cfg(test)]
mod tests;
