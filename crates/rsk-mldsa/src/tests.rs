// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn a_zeroed_key_refuses_to_sign_until_expanded() {
    let mut key = MlDsa44::zeroed();
    let mut sig = [0u8; MLDSA44_SIG_LEN];
    assert_eq!(key.sign(b"m", &[0; 32], &mut sig), Err(Error::NotExpanded));
    key.expand(&[7; SEED_LEN]);
    assert_eq!(key.sign(b"m", &[0; 32], &mut sig), Ok(MLDSA44_SIG_LEN));
}

#[test]
fn public_seed_constructors_match_every_nist_acvp_public_key() {
    for kat in testvectors::KEYGEN.iter() {
        let xi: [u8; SEED_LEN] = testutil::unhex(kat.seed).try_into().unwrap();
        let actual = match kat.set {
            44 => MlDsa44::from_seed(&xi).public_key().to_vec(),
            65 => MlDsa65::from_seed(&xi).public_key().to_vec(),
            87 => MlDsa87::from_seed(&xi).public_key().to_vec(),
            set => panic!("unexpected parameter set {set}"),
        };
        assert_eq!(
            actual,
            testutil::unhex(kat.pk),
            "ACVP keyGen tcId {}",
            kat.tc_id
        );
    }
}

#[test]
fn every_parameter_set_rejects_short_buffers_and_unexpanded_keys_without_writing() {
    let mut out = [0xA5; MLDSA87_SIG_LEN];
    let k44 = MlDsa44::zeroed();
    let k65 = MlDsa65::zeroed();
    let k87 = MlDsa87::zeroed();
    assert_eq!(
        k44.sign(b"m", &[0; 32], &mut out[..MLDSA44_SIG_LEN - 1]),
        Err(Error::BufferTooSmall)
    );
    assert_eq!(
        k65.sign(b"m", &[0; 32], &mut out[..MLDSA65_SIG_LEN - 1]),
        Err(Error::BufferTooSmall)
    );
    assert_eq!(
        k87.sign(b"m", &[0; 32], &mut out[..MLDSA87_SIG_LEN - 1]),
        Err(Error::BufferTooSmall)
    );
    assert_eq!(k44.sign(b"m", &[0; 32], &mut out), Err(Error::NotExpanded));
    assert_eq!(k65.sign(b"m", &[0; 32], &mut out), Err(Error::NotExpanded));
    assert_eq!(k87.sign(b"m", &[0; 32], &mut out), Err(Error::NotExpanded));
    assert!(out.iter().all(|&b| b == 0xA5));
}

#[test]
fn verifier_refuses_context_public_key_signature_and_norm_boundaries() {
    let key = MlDsa44::from_seed(&[7; SEED_LEN]);
    let pk = key.public_key();
    let mut signature = [0; MLDSA44_SIG_LEN];
    key.sign(b"message", &[0; 32], &mut signature).unwrap();
    let verify = |pk: &[u8], context: &[u8], sig: &[u8]| {
        sign::verify::<4, 4>(&params::ML_DSA_44, pk, b"message", context, sig)
    };
    assert!(verify(&pk, &[], &signature));
    assert!(!verify(&pk, &[0; 256], &signature));
    assert!(!verify(&pk[..pk.len() - 1], &[], &signature));
    assert!(!verify(&pk, &[], &signature[..signature.len() - 1]));
    assert!(!verify(&pk, &[], &[0; MLDSA44_SIG_LEN]));
}

#[test]
fn hedged_ml_dsa65_signatures_remain_verifiable_across_many_rejection_walks() {
    let mut rng = testutil::Rng::new(0x5eed);
    let mut seed = [0; SEED_LEN];
    rng.fill(&mut seed);
    let key = MlDsa65::from_seed(&seed);
    let public = key.public_key();
    for number in 0u32..1024 {
        let mut random = [0; SEED_LEN];
        rng.fill(&mut random);
        let mut sig = [0; MLDSA65_SIG_LEN];
        let message = number.to_be_bytes();
        assert_eq!(key.sign(&message, &random, &mut sig), Ok(MLDSA65_SIG_LEN));
        assert!(mldsa65_verify(&public, &message, &sig), "walk {number}");
    }
}
