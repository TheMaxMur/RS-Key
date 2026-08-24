// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::RSA_PUB_EXP_BE;
use crate::fixtures::{N_HEX, P_HEX, Q_HEX, SeqRng, hex};

#[test]
fn import_rejects_degenerate_primes() {
    // A zero-valued prime MPI must be rejected, not panic num-bigint's unsigned
    // subtraction inside from_p_q (a device-halt on import). The applet's
    // is_empty() guard misses a non-empty `00`, so rsa_from_pqe fails closed itself.
    let e = [0x01, 0x00, 0x01];
    assert!(rsa_from_pqe(&e, &[], &hex(Q_HEX)).is_none());
    assert!(rsa_from_pqe(&e, &hex(P_HEX), &[]).is_none());
    assert!(rsa_from_pqe(&e, &[0x00], &hex(Q_HEX)).is_none());
    assert!(rsa_from_pqe(&e, &hex(P_HEX), &[0x00]).is_none());
    assert!(rsa_from_pqe(&e, &[0x01], &hex(Q_HEX)).is_none()); // p = 1 rejected too
}

#[test]
fn rsa_pub_exp_be_is_65537() {
    // The PIV metadata path hardcodes RSA_PUB_EXP_BE; it must serialize the same
    // 65537 the keygen puts in every key it assembles.
    assert_eq!(
        RSA_PUB_EXP_BE,
        BigUint::from(RSA_E).to_bytes_be().as_slice()
    );
}

#[test]
fn keygen_pool_assembles_in_either_order() {
    // The dual-core search feeds primes through `offer` in whatever order the
    // cores find them — both orders must assemble the same modulus.
    let p = BigUint::from_bytes_be(&hex(P_HEX));
    let q = BigUint::from_bytes_be(&hex(Q_HEX));
    for (first, second) in [(p.clone(), q.clone()), (q, p)] {
        let mut kg = RsaKeygen::new(2048);
        assert!(kg.usable());
        assert_eq!(kg.half_bytes(), 128);
        assert!(matches!(kg.offer(first), RsaStep::More));
        match kg.offer(second) {
            RsaStep::Done(k) => assert_eq!(k.n().to_bytes_be(), hex(N_HEX)),
            _ => panic!("two distinct primes must complete the key"),
        }
    }
}

#[test]
fn keygen_pool_le_transport() {
    // The inter-core transport: primes as little-endian bytes, scrubbed on use.
    let (mut p_le, mut q_le) = (hex(P_HEX), hex(Q_HEX));
    p_le.reverse();
    q_le.reverse();
    let mut kg = RsaKeygen::new(2048);
    assert!(matches!(kg.offer_le(&mut p_le), RsaStep::More));
    assert!(
        p_le.iter().all(|&b| b == 0),
        "transport buffer not scrubbed"
    );
    match kg.offer_le(&mut q_le) {
        RsaStep::Done(k) => assert_eq!(k.n().to_bytes_be(), hex(N_HEX)),
        _ => panic!("two distinct primes must complete the key"),
    }
}

#[test]
fn try_candidate_le_finds_exact_half() {
    // Smallest asm-eligible half (32 bytes = RSA-512) so the host search is
    // quick; a find must fill the half exactly, odd and with the top bits set.
    let mut rng = SeqRng(42);
    let mut sieve = IncrementalSieve::new();
    let mut out = [0u8; 32];
    let mut tries = 0;
    let len = loop {
        tries += 1;
        assert!(tries < 200_000, "prime search did not converge");
        if let Some(n) = RsaKeygen::try_candidate_le(&mut sieve, &mut rng, 32, &mut out) {
            break n;
        }
    };
    assert_eq!(len, 32);
    assert_eq!(out[31] & 0xC0, 0xC0);
    assert_eq!(out[0] & 1, 1);
}

#[test]
fn keygen_bpsw_split_matches_library() {
    // try_candidate's accept = strong-MR(asm) + strong-Lucas. Any prime it
    // produces must satisfy the library's own one-call Baillie-PSW — the
    // split changed backends, not the test.
    use num_bigint_dig::prime::probably_prime;
    let mut rng = SeqRng(7);
    let mut sieve = IncrementalSieve::new();
    let (mut found, mut tries) = (0, 0);
    while found < 2 {
        tries += 1;
        assert!(tries < 200_000, "prime search did not converge");
        if let Some(p) = RsaKeygen::try_candidate(&mut sieve, &mut rng, 32) {
            assert!(
                probably_prime(&p, 0),
                "split BPSW accepted what the library rejects"
            );
            found += 1;
        }
    }
}

#[test]
fn keygen_pool_le_rejects_wrong_size_prime() {
    // Belt-and-suspenders: a wrong-length byte-transport find (a stale prime from
    // a prior different-size job) must be dropped and scrubbed, leaving the pool
    // intact — feeding it would corrupt the modulus.
    let mut kg = RsaKeygen::new(2048); // half = 128 bytes
    assert_eq!(kg.half_bytes(), 128);
    let mut under = hex(P_HEX);
    under.truncate(64); // 64 < 128: an under-size stale prime
    assert!(matches!(kg.offer_le(&mut under), RsaStep::More));
    assert!(
        under.iter().all(|&b| b == 0),
        "rejected buffer not scrubbed"
    );
    // …and an over-size stale prime — pins the guard at `!=`, not `<`.
    let mut over = hex(P_HEX);
    over.extend_from_slice(&hex(Q_HEX)[..64]); // 192 > 128
    assert!(matches!(kg.offer_le(&mut over), RsaStep::More));
    assert!(over.iter().all(|&b| b == 0), "rejected buffer not scrubbed");
    // Pool untouched: a correct-size pair still assembles the exact modulus. (Were
    // either wrong prime pooled, this first offer would already return Done.)
    let (mut p_le, mut q_le) = (hex(P_HEX), hex(Q_HEX));
    p_le.reverse();
    q_le.reverse();
    assert!(matches!(kg.offer_le(&mut p_le), RsaStep::More));
    match kg.offer_le(&mut q_le) {
        RsaStep::Done(k) => assert_eq!(k.n().to_bytes_be(), hex(N_HEX)),
        _ => panic!("correct-size primes must complete the key after a reject"),
    }
}

#[test]
fn keygen_pool_rejects_duplicate_prime() {
    let p = BigUint::from_bytes_be(&hex(P_HEX));
    let mut kg = RsaKeygen::new(2048);
    assert!(matches!(kg.offer(p.clone()), RsaStep::More));
    // The same prime again must not assemble a broken p == q key…
    assert!(matches!(kg.offer(p), RsaStep::More));
    // …and the held prime survives: a distinct second one completes the key.
    let q = BigUint::from_bytes_be(&hex(Q_HEX));
    assert!(matches!(kg.offer(q), RsaStep::Done(_)));
}

#[test]
fn generate_rsa_refuses_an_unusable_size() {
    // A half-width the asm CRT core cannot take never reaches a prime search —
    // it returns `Failed`, which the applets answer `EXEC_ERROR` to.
    assert_eq!(
        generate_rsa(&mut SeqRng(1), 1000).err(),
        Some(RsaError::Failed)
    );
}
