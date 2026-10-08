// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::params::{ML_DSA_44, ML_DSA_65, ML_DSA_87};
use crate::testutil::{Rng, unhex};
use crate::testvectors::{KEYGEN, SIGGEN, SIGVER};

#[test]
fn self_verify_and_tamper_rejects() {
    let mut rng = Rng::new(7);
    let mut xi = [0u8; 32];
    rng.fill(&mut xi);
    let mut rnd = [0u8; 32];
    rng.fill(&mut rnd);
    let key = ExpandedKey::<6, 5>::from_seed(&ML_DSA_65, &xi);
    let mut pk = [0u8; 1952];
    key.write_public_key(&ML_DSA_65, &mut pk);
    let msg = b"presence-and-sign";
    let mut sig = [0u8; 3309];
    key.sign(&ML_DSA_65, msg, &[], &rnd, &mut sig);

    assert!(verify::<6, 5>(&ML_DSA_65, &pk, msg, &[], &sig));
    let mut z_tampered = sig;
    z_tampered[100] ^= 0x01;
    assert!(
        !verify::<6, 5>(&ML_DSA_65, &pk, msg, &[], &z_tampered),
        "tampered z must reject"
    );
    assert!(
        !verify::<6, 5>(&ML_DSA_65, &pk, b"wrong-msg", &[], &sig),
        "wrong message must reject"
    );
}

// ---- NIST ACVP KATs: independent ground truth ----

#[test]
fn acvp_keygen_pk_exact() {
    assert_eq!(KEYGEN.len(), 75, "ACVP keyGen cases");
    for kat in KEYGEN.iter() {
        let mut xi = [0u8; 32];
        xi.copy_from_slice(&unhex(kat.seed));
        let pk = match kat.set {
            44 => {
                let key = ExpandedKey::<4, 4>::from_seed(&ML_DSA_44, &xi);
                let mut pk = vec![0u8; 1312];
                key.write_public_key(&ML_DSA_44, &mut pk);
                pk
            }
            65 => {
                let key = ExpandedKey::<6, 5>::from_seed(&ML_DSA_65, &xi);
                let mut pk = vec![0u8; 1952];
                key.write_public_key(&ML_DSA_65, &mut pk);
                pk
            }
            87 => {
                let key = ExpandedKey::<8, 7>::from_seed(&ML_DSA_87, &xi);
                let mut pk = vec![0u8; 2592];
                key.write_public_key(&ML_DSA_87, &mut pk);
                pk
            }
            s => panic!("unexpected param set {s}"),
        };
        let (tc, set) = (kat.tc_id, kat.set);
        assert!(
            pk == unhex(kat.pk),
            "ACVP keyGen pk, tcId {tc} (ML-DSA-{set})"
        );
    }
}

/// keyGen's `sk`, which the `pk` check never reads, and nothing else does: sigGen
/// signs from the vector's own `sk`, so `K` and the secret vectors the seed
/// expansion derives went unchecked. The key holds those only as NTT/Montgomery
/// precomputes, so both keys are compared there, mod q.
#[test]
fn acvp_keygen_sk_matches_the_expansion() {
    assert_eq!(KEYGEN.len(), 75, "ACVP keyGen cases");
    for kat in KEYGEN.iter() {
        let mut xi = [0u8; 32];
        xi.copy_from_slice(&unhex(kat.seed));
        let sk = unhex(kat.sk);
        let same = match kat.set {
            44 => same_secret(
                &ExpandedKey::<4, 4>::from_seed(&ML_DSA_44, &xi),
                &ExpandedKey::<4, 4>::from_sk_bytes(&ML_DSA_44, &sk),
            ),
            65 => same_secret(
                &ExpandedKey::<6, 5>::from_seed(&ML_DSA_65, &xi),
                &ExpandedKey::<6, 5>::from_sk_bytes(&ML_DSA_65, &sk),
            ),
            87 => same_secret(
                &ExpandedKey::<8, 7>::from_seed(&ML_DSA_87, &xi),
                &ExpandedKey::<8, 7>::from_sk_bytes(&ML_DSA_87, &sk),
            ),
            s => panic!("unexpected param set {s}"),
        };
        let (tc, set) = (kat.tc_id, kat.set);
        assert!(same, "ACVP keyGen sk, tcId {tc} (ML-DSA-{set})");
    }
}

fn same_secret<const K: usize, const L: usize>(
    a: &ExpandedKey<K, L>,
    b: &ExpandedKey<K, L>,
) -> bool {
    let mod_q = |v: &[Poly]| {
        v.iter()
            .flat_map(|p| p.0)
            .map(|c| c.rem_euclid(Q))
            .collect::<Vec<_>>()
    };
    a.rho == b.rho
        && a.cap_k == b.cap_k
        && a.tr == b.tr
        && mod_q(&a.s1_hat_mont) == mod_q(&b.s1_hat_mont)
        && mod_q(&a.s2_hat_mont) == mod_q(&b.s2_hat_mont)
        && mod_q(&a.t0_hat_mont) == mod_q(&b.t0_hat_mont)
}

#[test]
fn acvp_siggen_signature_exact() {
    assert_eq!(SIGGEN.len(), 90, "ACVP sigGen cases");
    for kat in SIGGEN.iter() {
        let sk = unhex(kat.sk);
        let msg = unhex(kat.msg);
        let ctx = unhex(kat.ctx);
        let mut rnd = [0u8; 32];
        rnd.copy_from_slice(&unhex(kat.rnd));
        let sig = match kat.set {
            44 => {
                let key = ExpandedKey::<4, 4>::from_sk_bytes(&ML_DSA_44, &sk);
                let mut sig = vec![0u8; 2420];
                key.sign(&ML_DSA_44, &msg, &ctx, &rnd, &mut sig);
                sig
            }
            65 => {
                let key = ExpandedKey::<6, 5>::from_sk_bytes(&ML_DSA_65, &sk);
                let mut sig = vec![0u8; 3309];
                key.sign(&ML_DSA_65, &msg, &ctx, &rnd, &mut sig);
                sig
            }
            87 => {
                let key = ExpandedKey::<8, 7>::from_sk_bytes(&ML_DSA_87, &sk);
                let mut sig = vec![0u8; 4627];
                key.sign(&ML_DSA_87, &msg, &ctx, &rnd, &mut sig);
                sig
            }
            s => panic!("unexpected param set {s}"),
        };
        let (tc, set) = (kat.tc_id, kat.set);
        assert!(
            sig == unhex(kat.sig),
            "ACVP sigGen, tcId {tc} (ML-DSA-{set})"
        );
    }
}

/// Manual stack-floor probe: runs keygen+sign on a thread with a bounded stack
/// so the on-device main-stack budget can be sized. One size per invocation
/// (a stack overflow aborts the process, so it cannot be caught in a loop):
///   for k in 64 48 32 24 16; do STACK_KIB=$k MLDSA_SET=65 \
///     cargo test --release --target <host> -p rsk-mldsa stack_floor_probe \
///     -- --ignored --nocapture; done
/// The smallest size that still prints "completed" is the host floor; the
/// RP2350 (in-order, opt="s") runs ~1.4–1.6× higher.
#[test]
#[ignore = "manual stack measurement; drive via STACK_KIB/MLDSA_SET/MLDSA_PHASE env"]
fn stack_floor_probe() {
    let kib: usize = std::env::var("STACK_KIB")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(64);
    let set: u16 = std::env::var("MLDSA_SET")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(65);
    // "sign" boxes the key first (mirrors the firmware, key off-stack); "keygen"
    // measures from_seed; "both" runs the full per-request path on one stack.
    let phase = std::env::var("MLDSA_PHASE").unwrap_or_else(|_| "sign".into());
    let keygen_only = phase == "keygen";
    let xi = [7u8; 32];
    let rnd = [3u8; 32];

    // Pre-build+box the key OUTSIDE the bounded thread for the "sign" phase, so
    // the measured frame is signing alone (the key lives on the heap on-device).
    let boxed44 = (set == 44 && phase == "sign")
        .then(|| Box::new(ExpandedKey::<4, 4>::from_seed(&ML_DSA_44, &xi)));
    let boxed65 = (set == 65 && phase == "sign")
        .then(|| Box::new(ExpandedKey::<6, 5>::from_seed(&ML_DSA_65, &xi)));

    let out = std::thread::Builder::new()
        .stack_size(kib * 1024)
        .spawn(move || match set {
            44 => {
                let key = boxed44
                    .unwrap_or_else(|| Box::new(ExpandedKey::<4, 4>::from_seed(&ML_DSA_44, &xi)));
                if keygen_only {
                    return key.probe_byte();
                }
                let mut s = vec![0u8; 2420];
                key.sign(&ML_DSA_44, b"stack probe", &[], &rnd, &mut s);
                s[0]
            }
            _ => {
                let key = boxed65
                    .unwrap_or_else(|| Box::new(ExpandedKey::<6, 5>::from_seed(&ML_DSA_65, &xi)));
                if keygen_only {
                    return key.probe_byte();
                }
                let mut s = vec![0u8; 3309];
                key.sign(&ML_DSA_65, b"stack probe", &[], &rnd, &mut s);
                s[0]
            }
        })
        .unwrap()
        .join()
        .unwrap();
    println!("ML-DSA-{set} {phase} completed within {kib} KiB stack (byte={out})");
}

#[test]
fn acvp_sigver_accept_reject() {
    assert_eq!(SIGVER.len(), 45, "ACVP sigVer cases");
    for kat in SIGVER.iter() {
        let pk = unhex(kat.pk);
        let msg = unhex(kat.msg);
        let ctx = unhex(kat.ctx);
        let sig = unhex(kat.sig);
        let got = match kat.set {
            44 => verify::<4, 4>(&ML_DSA_44, &pk, &msg, &ctx, &sig),
            65 => verify::<6, 5>(&ML_DSA_65, &pk, &msg, &ctx, &sig),
            87 => verify::<8, 7>(&ML_DSA_87, &pk, &msg, &ctx, &sig),
            s => panic!("unexpected param set {s}"),
        };
        let want = if kat.expected {
            "should have verified"
        } else {
            "should have been refused"
        };
        let (tc, set, reason) = (kat.tc_id, kat.set, kat.reason);
        assert_eq!(
            got, kat.expected,
            "ACVP sigVer, tcId {tc} (ML-DSA-{set}, {reason}): {want}"
        );
    }
}

#[test]
fn a_bounded_corrupt_t0_precompute_cannot_reuse_the_first_accepted_challenge() {
    let p = &ML_DSA_44;
    let mut key = ExpandedKey::<4, 4>::from_seed(p, &[0x42; SEED_LEN]);
    key.s1_hat_mont = zero_vec();
    key.s2_hat_mont = zero_vec();
    key.t0_hat_mont = zero_vec();
    let mut baseline = vec![0; p.sig_len];
    key.sign(p, b"norm-control", &[], &[0; SEED_LEN], &mut baseline);
    let (challenge, z, _) =
        sig_decode::<4, 4>(p.gamma1, p.omega, p.lambda_div4, &baseline).unwrap();
    let c = sample_in_ball(p.tau, &challenge[..p.lambda_div4]);
    let mut t0 = zero_vec::<4>();
    let bound = (1 << (D - 1)) - 1;
    t0[0].0[0] = c.0[0] * bound;
    for i in 1..crate::params::N {
        t0[0].0[crate::params::N - i] = -c.0[i] * bound;
    }
    let coefficient = c.0[0] * t0[0].0[0]
        - (1..crate::params::N)
            .map(|i| c.0[i] * t0[0].0[crate::params::N - i])
            .sum::<i32>();
    assert_eq!(coefficient, p.tau * bound);
    assert!(coefficient >= p.gamma2);
    key.t0_hat_mont = to_mont_vec(&ntt_vec(&t0));
    let mut c_hat = c.clone();
    ntt_inplace(&mut c_hat);
    let c_t0: [Poly; 4] = core::array::from_fn(|i| {
        let mut product = pointwise_mont(&c_hat, &key.t0_hat_mont[i]);
        inv_ntt_inplace(&mut product);
        product
    });
    assert_eq!(center_mod(c_t0[0].0[0]), coefficient);
    let mut w = matrix_mul_streaming::<4, 4>(&key.rho, &ntt_vec(&z));
    reduce_vec(&mut w);
    for row in &mut w {
        inv_ntt_inplace(row);
    }
    let weight: usize = (0..4)
        .flat_map(|row| (0..crate::params::N).map(move |column| (row, column)))
        .filter(|&(row, column)| {
            make_hint(
                p.gamma2,
                Q - c_t0[row].0[column],
                partial_reduce32(w[row].0[column] + c_t0[row].0[column]),
            )
        })
        .count();
    assert!(
        weight <= p.omega as usize,
        "the hint guard must not own this rejection"
    );
    let mut refused_challenge = vec![0; p.sig_len];
    key.sign(
        p,
        b"norm-control",
        &[],
        &[0; SEED_LEN],
        &mut refused_challenge,
    );
    assert_ne!(
        &refused_challenge[..p.lambda_div4],
        &baseline[..p.lambda_div4],
        "the norm-violating candidate was accepted"
    );
}

#[test]
#[should_panic(expected = "params/dimension mismatch")]
fn expansion_refuses_mismatched_row_dimensions_before_using_the_seed() {
    let mut params = ML_DSA_44;
    params.k += 1;
    ExpandedKey::<4, 4>::zeroed().expand(&params, &[0; SEED_LEN]);
}

#[test]
#[should_panic(expected = "params/dimension mismatch")]
fn expansion_refuses_mismatched_column_dimensions_before_using_the_seed() {
    let mut params = ML_DSA_44;
    params.l += 1;
    ExpandedKey::<4, 4>::zeroed().expand(&params, &[0; SEED_LEN]);
}

#[test]
#[should_panic(expected = "assertion failed: K == p.k && L == p.l")]
fn verification_refuses_mismatched_row_dimensions_before_decoding() {
    let mut params = ML_DSA_44;
    params.k += 1;
    let _ = verify::<4, 4>(&params, &[], &[], &[], &[]);
}

#[test]
#[should_panic(expected = "assertion failed: K == p.k && L == p.l")]
fn verification_refuses_mismatched_column_dimensions_before_decoding() {
    let mut params = ML_DSA_44;
    params.l += 1;
    let _ = verify::<4, 4>(&params, &[], &[], &[], &[]);
}

#[test]
fn the_keygen_probe_byte_matches_the_public_key_hash() {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let key = ExpandedKey::<4, 4>::from_seed(&ML_DSA_44, &[0x42; SEED_LEN]);
    let mut public = vec![0; ML_DSA_44.pk_len];
    key.write_public_key(&ML_DSA_44, &mut public);
    let mut hash = sha3::Shake256::default();
    hash.update(&public);
    let mut expected = [0; 1];
    hash.finalize_xof().read(&mut expected);
    assert_eq!(std::hint::black_box(&key).probe_byte(), expected[0]);
}
