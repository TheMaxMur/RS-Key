// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use num_bigint_dig::BigUint;

#[test]
fn self_test_passes_on_host() {
    assert!(self_test());
}

fn le32(hex: &str) -> Vec<u8> {
    // Parse a big-endian hex string into a 32-byte little-endian buffer.
    let be: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let mut le = vec![0u8; 32];
    for (i, b) in be.iter().rev().enumerate() {
        le[i] = *b;
    }
    le
}

#[test]
fn mod_small_matches_biguint() {
    let n = le32("f00dcafe0123456789abcdef00000000000000000000000000000000deadbeef");
    let bn = BigUint::from_bytes_le(&n);
    for m in [3u32, 5, 7, 65537, 1_000_003] {
        assert_eq!(BigUint::from(mod_small(&n, m)), &bn % m, "mod {m}");
    }
}

fn a_prime_le() -> Vec<u8> {
    // A real 256-bit prime: next_prime above a fixed seed.
    let seed = BigUint::from_bytes_le(&[
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2,
        0xe1, 0xf0,
    ]);
    let mut le = num_bigint_dig::prime::next_prime(&seed).to_bytes_le();
    le.resize(32, 0);
    le
}

#[test]
fn small_factor_detection() {
    let mut n = [0u8; 32];
    n[0] = 0x09; // 9 = 3²  → divisible by 3
    assert!(has_small_factor(&n));
    // A 256-bit prime has no small factor.
    assert!(!has_small_factor(&a_prime_le()));
}

#[test]
fn incremental_matches_flat() {
    // The running sieve's verdict must equal the flat has_small_factor on
    // the exact same candidate, every step, across reseeds — for both the
    // 1024-bit (128 B) and 2048-bit (256 B) candidate lengths.
    for half in [128usize, 256] {
        let mut sieve = IncrementalSieve::new();
        let mut seed = vec![0u8; half];
        let mut state = 0x9E3779B97F4A7C15u64 ^ (half as u64);
        let mut checked = 0;
        let mut reseeds = 0;
        while checked < 6000 {
            if sieve.needs_seed() {
                for b in seed.iter_mut() {
                    state = state
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    *b = (state >> 33) as u8;
                }
                sieve.reseed(half, &seed);
                reseeds += 1;
                continue;
            }
            match sieve.step() {
                None => continue, // window ended; loop reseeds
                Some(passes) => {
                    let cand = sieve.candidate();
                    assert_eq!(
                        passes,
                        !has_small_factor(cand),
                        "verdict mismatch at half={half}"
                    );
                    // A passing candidate must be odd with the top two bits set.
                    if passes {
                        assert_eq!(cand[0] & 1, 1);
                        assert_eq!(cand[half - 1] & 0xC0, 0xC0);
                    }
                    checked += 1;
                }
            }
        }
        assert!(reseeds >= 1, "expected at least one window for half={half}");
    }
}

#[test]
fn incremental_steps_by_two() {
    // Consecutive candidates differ by exactly 2 within a window.
    let mut sieve = IncrementalSieve::new();
    let seed = [0x11u8; 128];
    sieve.reseed(128, &seed);
    sieve.step().unwrap();
    let a = BigUint::from_bytes_le(sieve.candidate());
    sieve.step().unwrap();
    let b = BigUint::from_bytes_le(sieve.candidate());
    assert_eq!(b - a, BigUint::from(2u32));
}

#[test]
fn sieve_depth_scales_with_length() {
    // 2003 and 3001 are both primes past the 256th (1619): a candidate that
    // is their product has no factor a 256-deep sieve can see, but the
    // 448-deep sieve a 128-byte (RSA-2048) candidate gets does catch 2003.
    let n = BigUint::from(2003u32) * BigUint::from(3001u32);
    let mut le = n.to_bytes_le();
    le.resize(128, 0); // RSA-2048 half → sieve_count 448
    assert!(has_small_factor(&le), "128 B sieve must reach 2003");
    le.truncate(64); // ≤64 B → sieve_count 256 (≤1619), misses both factors
    assert!(!has_small_factor(&le), "64 B sieve must miss 2003·3001");
}

#[test]
fn modexp_matches_biguint() {
    let modulus = le32("e3a1b5c70000000000000000000000000000000000000000000000000000be25");
    let base = [7u8]; // little-endian 7
    let exp_be = [0x01u8, 0x00, 0x01]; // 65537, big-endian
    let mut out = [0u8; 32];
    modexp_priv(&base, &exp_be, &modulus, &mut out);
    let expect =
        BigUint::from(7u32).modpow(&BigUint::from(65537u32), &BigUint::from_bytes_le(&modulus));
    let mut want = expect.to_bytes_le();
    want.resize(32, 0);
    assert_eq!(&out[..], &want[..]);
}

#[test]
fn strong_mr_matches_num_bigint() {
    use num_bigint_dig::prime::probably_prime_miller_rabin;
    // Differential: our strong MR against num-bigint-dig's, single round,
    // forced base 2 — over random odd top-bit-set candidates (the keygen's
    // draw shape). Any divergence is a bug in one of the two.
    let mut state = 0x243F_6A88_85A3_08D3u64;
    for i in 0..300 {
        let mut v = [0u8; 32];
        for b in v.iter_mut() {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (state >> 33) as u8;
        }
        v[0] |= 1;
        v[31] |= 0x80;
        let n = BigUint::from_bytes_le(&v);
        assert_eq!(
            passes_strong_mr_base2(&v),
            probably_prime_miller_rabin(&n, 1, true),
            "differential mismatch at iteration {i} for {n}"
        );
    }
}

#[test]
fn strong_mr_pseudoprime_families() {
    use num_bigint_dig::prime::probably_prime_lucas;
    // The first strong pseudoprimes to base 2 (OEIS A001262) MUST pass the
    // Miller-Rabin half — Baillie-PSW kills them with the Lucas half.
    for psp in [2047u32, 3277, 4033, 4681, 8321, 15841] {
        let mut le = vec![0u8; 32];
        le[..4].copy_from_slice(&psp.to_le_bytes());
        assert!(
            passes_strong_mr_base2(&le),
            "2-SPSP {psp} must pass strong MR"
        );
        assert!(
            !probably_prime_lucas(&BigUint::from(psp)),
            "Lucas must reject the 2-SPSP {psp}"
        );
    }
    // Ordinary Carmichael numbers fail the strong test outright.
    for c in [561u32, 1105, 1729, 6601] {
        let mut le = vec![0u8; 32];
        le[..4].copy_from_slice(&c.to_le_bytes());
        assert!(
            !passes_strong_mr_base2(&le),
            "Carmichael {c} must fail strong MR"
        );
    }
    // And the upgrade over the old filter in one number: 341 = 11·31 is a
    // Fermat base-2 pseudoprime but not a strong one.
    let mut le = vec![0u8; 32];
    le[..2].copy_from_slice(&341u16.to_le_bytes());
    assert!(passes_fermat_base2(&le));
    assert!(!passes_strong_mr_base2(&le));
}

#[test]
fn strong_mr_accepts_real_primes() {
    let p_le = a_prime_le();
    assert!(passes_strong_mr_base2(&p_le));
    assert!(passes_strong_mr_base2(&KAT_PRIME_LE));
    assert!(!passes_strong_mr_base2(&KAT_COMPOSITE_LE));
}

#[test]
fn fermat_accepts_prime_rejects_composite() {
    use num_bigint_dig::prime::probably_prime;
    let p_le = a_prime_le();
    assert!(probably_prime(&BigUint::from_bytes_le(&p_le), 20)); // sanity
    assert!(passes_fermat_base2(&p_le), "a prime must pass Fermat");

    // An odd composite: prime + 2 (almost surely composite); skip if it is prime.
    let comp = BigUint::from_bytes_le(&p_le) + 2u32;
    if !probably_prime(&comp, 20) {
        let mut c_le = comp.to_bytes_le();
        c_le.resize(32, 0);
        assert!(!passes_fermat_base2(&c_le), "a composite must fail Fermat");
    }
}

/// A second distinct 256-bit prime (different seed from [`a_prime_le`]).
fn another_prime_le() -> Vec<u8> {
    let seed = BigUint::from_bytes_le(&[
        0xf1, 0xe2, 0xd3, 0xc4, 0xb5, 0xa6, 0x97, 0x88, 0x79, 0x6a, 0x5b, 0x4c, 0x3d, 0x2e, 0x1f,
        0x00, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45,
        0x23, 0xf1,
    ]);
    let mut le = num_bigint_dig::prime::next_prime(&seed).to_bytes_le();
    le.resize(32, 0);
    le
}

/// Big-endian, zero-padded to `len` bytes.
fn to_be_fixed(x: &BigUint, len: usize) -> Vec<u8> {
    let be = x.to_bytes_be();
    let mut out = vec![0u8; len];
    out[len - be.len()..].copy_from_slice(&be);
    out
}

#[test]
fn sign_crt_matches_biguint() {
    use num_bigint_dig::ModInverse;
    let half = 32; // two 256-bit primes → a 512-bit modulus
    let p = BigUint::from_bytes_le(&a_prime_le());
    let q = BigUint::from_bytes_le(&another_prime_le());
    assert_ne!(p, q);
    let e = BigUint::from(65_537u32);
    let n = &p * &q;
    let p1 = &p - 1u32;
    let q1 = &q - 1u32;
    let d = e
        .clone()
        .mod_inverse(&p1 * &q1)
        .unwrap()
        .to_biguint()
        .unwrap();
    let dp = &d % &p1;
    let dq = &d % &q1;
    let qinv = q.clone().mod_inverse(&p).unwrap().to_biguint().unwrap();

    let m = BigUint::from_bytes_be(b"an RSA CRT signing round-trip check!") % &n;
    let s_ref = m.modpow(&d, &n);

    let mut base_le = vec![0u8; 2 * half];
    let mb = m.to_bytes_le();
    base_le[..mb.len()].copy_from_slice(&mb);
    let mut out = vec![0u8; 2 * half];
    sign_crt(
        &base_le,
        &dp.to_bytes_be(),
        &dq.to_bytes_be(),
        &to_be_fixed(&p, half),
        &to_be_fixed(&q, half),
        &to_be_fixed(&qinv, half),
        &mut out,
    );
    assert_eq!(
        BigUint::from_bytes_le(&out),
        s_ref,
        "CRT sign must equal m^d mod n"
    );
}

#[test]
fn modexp_pub_matches_biguint() {
    // base^65537 mod n over a 512-bit odd modulus (a two-prime product).
    let n = BigUint::from_bytes_le(&a_prime_le()) * BigUint::from_bytes_le(&another_prime_le());
    let mlen = 64;
    let base = BigUint::from_bytes_be(b"public-exponent modexp round-trip check!") % &n;
    let want = base.modpow(&BigUint::from(65_537u32), &n);
    let mut base_le = vec![0u8; mlen];
    let bb = base.to_bytes_le();
    base_le[..bb.len()].copy_from_slice(&bb);
    let mut n_le = vec![0u8; mlen];
    let nb = n.to_bytes_le();
    n_le[..nb.len()].copy_from_slice(&nb);
    let mut out = vec![0u8; mlen];
    assert!(modexp_pub(&base_le, &[0x01, 0x00, 0x01], &n_le, &mut out));
    assert_eq!(BigUint::from_bytes_le(&out), want, "base^e mod n mismatch");
}
