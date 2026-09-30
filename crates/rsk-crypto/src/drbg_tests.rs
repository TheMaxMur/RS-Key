// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn stream<const N: usize>(d: &mut HmacDrbg) -> [u8; N] {
    let mut b = [0u8; N];
    d.fill(&mut b);
    b
}

#[test]
fn deterministic_for_a_seed() {
    let mut a = HmacDrbg::new(b"seed material xyz");
    let mut b = HmacDrbg::new(b"seed material xyz");
    assert_eq!(stream::<64>(&mut a), stream::<64>(&mut b));
}

#[test]
fn seed_sensitive() {
    let mut a = HmacDrbg::new(b"seed-A");
    let mut b = HmacDrbg::new(b"seed-B");
    assert_ne!(stream::<64>(&mut a), stream::<64>(&mut b));
}

#[test]
fn successive_draws_differ() {
    let mut d = HmacDrbg::new(b"seed");
    assert_ne!(stream::<32>(&mut d), stream::<32>(&mut d));
}

#[test]
fn reseed_changes_stream() {
    let mut a = HmacDrbg::new(b"seed");
    let mut b = HmacDrbg::new(b"seed");
    b.reseed(b"fresh entropy");
    assert_ne!(stream::<32>(&mut a), stream::<32>(&mut b));
}

#[test]
fn fills_arbitrary_lengths() {
    // A request spanning many 32-byte blocks must be fully written (no zeros tail).
    let mut d = HmacDrbg::new(b"seed");
    let mut big = [0u8; 200];
    d.fill(&mut big);
    assert!(big.iter().any(|&x| x != 0));
    assert!(big[160..].iter().any(|&x| x != 0)); // last block written
}

#[test]
fn matches_sp800_90a_via_verified_hmac() {
    // KAT: pin the byte output to the SP 800-90A 10.1.2 formulas expressed
    // directly through the RFC-4231-verified `hmac_sha256`. This proves the DRBG
    // state machine matches the spec (HMAC itself is already KAT-tested), and is
    // immune to CAVP-vector transcription error.
    use crate::mac::hmac_sha256;
    let seed = b"DRBG known-answer seed";

    // Instantiate: K = 0x00.., V = 0x01.., then Update(seed) (provided non-empty
    // → both K/V pairs).
    let k0 = [0x00u8; 32];
    let v0 = [0x01u8; 32];
    let cat = |v: &[u8; 32], byte: u8| {
        let mut m = std::vec::Vec::with_capacity(33 + seed.len());
        m.extend_from_slice(v);
        m.push(byte);
        m.extend_from_slice(seed);
        m
    };
    let k1 = hmac_sha256(&k0, &cat(&v0, 0x00));
    let v1 = hmac_sha256(&k1, &v0);
    let k2 = hmac_sha256(&k1, &cat(&v1, 0x01));
    let v2 = hmac_sha256(&k2, &v1);

    // First Generate block (no additional input) = HMAC(K2, V2).
    let expected = hmac_sha256(&k2, &v2);

    let mut d = HmacDrbg::new(seed);
    let mut out = [0u8; 32];
    d.fill(&mut out);
    assert_eq!(out, expected);
}

#[test]
fn scrub_wipes_both_halves_of_the_state() {
    // The reboot path scrubs a *live* generator, and K and V are secret jointly:
    // V is the chaining value the next Generate hashes, K the key it hashes it
    // under — leave either behind and the hand-off keeps half the keystream.
    let mut d = HmacDrbg::new(b"seed material xyz");
    stream::<32>(&mut d);
    assert!(
        d.k.expose().iter().any(|&x| x != 0),
        "K is live before the scrub"
    );
    assert!(
        d.v.expose().iter().any(|&x| x != 0),
        "V is live before the scrub"
    );
    d.scrub();
    assert!(d.k.expose().iter().all(|&x| x == 0), "K survived the scrub");
    assert!(d.v.expose().iter().all(|&x| x == 0), "V survived the scrub");
}

/// The RP2350 TRNG's block: its 192-bit EHR, which `blocking_fill_bytes` copies
/// into a buffer in order from its start.
const BLOCK: usize = 24;

/// A draw with an all-zero block is a stuck or unfinished source, and a DRBG seeded
/// from it is seeded from a constant. Each such draw is drawn again, and the first
/// clean one is what the caller gets.
#[test]
fn a_draw_with_an_all_zero_block_is_drawn_again() {
    let good = [0x5Au8; 48];
    for (name, bad) in [
        ("the first block zero", 0..BLOCK),
        ("the second block zero", BLOCK..2 * BLOCK),
        ("all of it zero", 0..2 * BLOCK),
    ] {
        let mut calls = 0;
        let mut buf = [0u8; 48];
        let r = draw_entropy(&mut buf, BLOCK, |b| {
            calls += 1;
            b.copy_from_slice(&good);
            if calls == 1 {
                b[bad.clone()].fill(0);
            }
        });
        assert_eq!((r, calls, buf), (Ok(()), 2, good), "{name}");
    }
}

/// A source that never answers a clean draw is given [`ENTROPY_TRIES`] draws and no
/// more, and the caller is told: it fails closed rather than seed from what it got.
/// The reseed's 32 bytes end in an 8-byte block, which counts as one.
#[test]
fn a_source_that_answers_only_zero_blocks_fails_closed() {
    for (len, zero) in [(48usize, 24..48), (32, 24..32), (32, 0..24)] {
        let mut calls = 0;
        let mut buf = std::vec![0u8; len];
        let r = draw_entropy(&mut buf, BLOCK, |b| {
            calls += 1;
            b.fill(0xA5);
            b[zero.clone()].fill(0);
        });
        assert_eq!(
            (r, calls),
            (Err(EntropyFault), ENTROPY_TRIES),
            "{len}/{zero:?}"
        );
    }
}

/// The check finds a stuck block and nothing more: one set bit per block passes, and
/// a clean draw is taken the first time.
#[test]
fn a_block_with_one_set_bit_is_not_a_stuck_one() {
    let mut sparse = [0u8; 48];
    sparse[0] = 0x01;
    sparse[47] = 0x80;
    let mut calls = 0;
    let mut buf = [0u8; 48];
    let r = draw_entropy(&mut buf, BLOCK, |b| {
        calls += 1;
        b.copy_from_slice(&sparse);
    });
    assert_eq!((r, calls, buf), (Ok(()), 1, sparse));
}
