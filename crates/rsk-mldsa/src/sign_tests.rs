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
    for kat in KEYGEN {
        let mut xi = [0u8; 32];
        xi.copy_from_slice(&unhex(kat.seed));
        let expected = unhex(kat.pk);
        match kat.set {
            44 => {
                let key = ExpandedKey::<4, 4>::from_seed(&ML_DSA_44, &xi);
                let mut pk = vec![0u8; 1312];
                key.write_public_key(&ML_DSA_44, &mut pk);
                assert_eq!(pk, expected, "ACVP keyGen pk (ML-DSA-44)");
            }
            65 => {
                let key = ExpandedKey::<6, 5>::from_seed(&ML_DSA_65, &xi);
                let mut pk = vec![0u8; 1952];
                key.write_public_key(&ML_DSA_65, &mut pk);
                assert_eq!(pk, expected, "ACVP keyGen pk (ML-DSA-65)");
            }
            87 => {
                let key = ExpandedKey::<8, 7>::from_seed(&ML_DSA_87, &xi);
                let mut pk = vec![0u8; 2592];
                key.write_public_key(&ML_DSA_87, &mut pk);
                assert_eq!(pk, expected, "ACVP keyGen pk (ML-DSA-87)");
            }
            s => panic!("unexpected param set {s}"),
        }
    }
}

#[test]
fn acvp_siggen_signature_exact() {
    for kat in SIGGEN {
        let sk = unhex(kat.sk);
        let msg = unhex(kat.msg);
        let ctx = unhex(kat.ctx);
        let mut rnd = [0u8; 32];
        rnd.copy_from_slice(&unhex(kat.rnd));
        let expected = unhex(kat.sig);
        match kat.set {
            44 => {
                let key = ExpandedKey::<4, 4>::from_sk_bytes(&ML_DSA_44, &sk);
                let mut sig = vec![0u8; 2420];
                key.sign(&ML_DSA_44, &msg, &ctx, &rnd, &mut sig);
                assert_eq!(sig, expected, "ACVP sigGen (ML-DSA-44)");
            }
            65 => {
                let key = ExpandedKey::<6, 5>::from_sk_bytes(&ML_DSA_65, &sk);
                let mut sig = vec![0u8; 3309];
                key.sign(&ML_DSA_65, &msg, &ctx, &rnd, &mut sig);
                assert_eq!(sig, expected, "ACVP sigGen (ML-DSA-65)");
            }
            87 => {
                let key = ExpandedKey::<8, 7>::from_sk_bytes(&ML_DSA_87, &sk);
                let mut sig = vec![0u8; 4627];
                key.sign(&ML_DSA_87, &msg, &ctx, &rnd, &mut sig);
                assert_eq!(sig, expected, "ACVP sigGen (ML-DSA-87)");
            }
            s => panic!("unexpected param set {s}"),
        }
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
    for kat in SIGVER {
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
        assert_eq!(
            got, kat.expected,
            "ACVP sigVer set {} ({})",
            kat.set, kat.reason
        );
    }
}
