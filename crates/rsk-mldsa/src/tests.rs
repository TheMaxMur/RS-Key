// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

std::thread_local! {
    static POLY_WIPED: core::cell::Cell<Option<bool>> = const { core::cell::Cell::new(None) };
}

pub(crate) fn observe_poly_drop(coefficients: &[i32; params::N]) {
    POLY_WIPED.with(|observed| {
        if observed.get().is_some() {
            observed.set(Some(*coefficients == [0; params::N]));
        }
    });
}

#[test]
fn dropping_a_secret_polynomial_wipes_every_live_coefficient() {
    let polynomial = poly::Poly([7; params::N]);
    POLY_WIPED.with(|observed| observed.set(Some(false)));
    drop(polynomial);
    POLY_WIPED.with(|observed| assert_eq!(observed.replace(None), Some(true)));
}

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

#[test]
fn in_place_public_expansion_matches_every_nist_acvp_key() {
    for kat in testvectors::KEYGEN.iter() {
        let seed = testutil::unhex(kat.seed).try_into().unwrap();
        let actual = match kat.set {
            44 => {
                let mut key = MlDsa44::zeroed();
                key.expand(&seed);
                key.public_key().to_vec()
            }
            65 => {
                let mut key = MlDsa65::zeroed();
                key.expand(&seed);
                key.public_key().to_vec()
            }
            87 => {
                let mut key = MlDsa87::zeroed();
                key.expand(&seed);
                key.public_key().to_vec()
            }
            set => panic!("unexpected parameter set {set}"),
        };
        assert_eq!(actual, testutil::unhex(kat.pk), "ACVP tcId {}", kat.tc_id);
    }
}

#[test]
fn a_real_maximum_hint_signature_matches_deterministic_openssl() {
    let key = MlDsa65::from_seed(&[7; SEED_LEN]);
    let message = 130u32.to_le_bytes();
    let mut signature = [0; MLDSA65_SIG_LEN];
    assert_eq!(
        key.sign(&message, &[0; SEED_LEN], &mut signature),
        Ok(MLDSA65_SIG_LEN)
    );
    let encoded = include_str!("hint_boundary_signature.txt")
        .lines()
        .find(|line| !line.starts_with('#') && !line.is_empty())
        .unwrap();
    let expected = testutil::unhex(encoded);
    assert_eq!(
        signature.as_slice(),
        expected.as_slice(),
        "deterministic OpenSSL signature changed"
    );
    assert_eq!(
        signature[MLDSA65_SIG_LEN - 1],
        params::ML_DSA_65.omega as u8
    );
    assert!(mldsa65_verify(&key.public_key(), &message, &signature));
}

#[test]
fn the_public_verifier_refuses_an_openssl_rejected_exact_norm_candidate() {
    let key = MlDsa65::from_seed(&[7; SEED_LEN]);
    let message = 78u32.to_le_bytes();
    let encoded = include_str!("norm_boundary_signature.txt")
        .lines()
        .find(|line| !line.starts_with('#') && !line.is_empty())
        .unwrap();
    let signature: [u8; MLDSA65_SIG_LEN] = testutil::unhex(encoded).try_into().unwrap();
    let (_, z, _) = encode::sig_decode::<6, 5>(
        params::ML_DSA_65.gamma1,
        params::ML_DSA_65.omega,
        params::ML_DSA_65.lambda_div4,
        &signature,
    )
    .unwrap();
    let norm = z
        .iter()
        .flat_map(|polynomial| &polynomial.0)
        .map(|coefficient| coefficient.abs())
        .max()
        .unwrap();
    assert_eq!(norm, params::ML_DSA_65.gamma1 - params::ML_DSA_65.beta);
    let mut relaxed = params::ML_DSA_65;
    relaxed.beta -= 1;
    assert!(
        sign::verify::<6, 5>(&relaxed, &key.public_key(), &message, &[], &signature),
        "another refusal masked the norm boundary"
    );
    assert!(
        !mldsa65_verify(&key.public_key(), &message, &signature),
        "accepted the forbidden exact norm boundary"
    );
}

macro_rules! public_verifier {
    ($name:ident, $key:ident, $verify:ident, $length:ident) => {
        #[test]
        fn $name() {
            let mut key = $key::zeroed();
            key.expand(&[7; SEED_LEN]);
            let pk = key.public_key();
            let mut signature = [0; $length];
            assert_eq!(
                key.sign(b"message", &[0; SEED_LEN], &mut signature),
                Ok($length)
            );
            assert!(
                $verify(&pk, b"message", &signature),
                "valid signature refused"
            );
            assert!(
                !$verify(&pk, b"other message", &signature),
                "wrong message accepted"
            );
            signature[0] ^= 1;
            assert!(
                !$verify(&pk, b"message", &signature),
                "bad challenge accepted"
            );
            assert!(
                !$verify(&pk, b"message", &[0; $length]),
                "zero signature accepted"
            );
            key.expand(&[8; SEED_LEN]);
            assert_ne!(
                key.public_key(),
                pk,
                "in-place expansion retained the old key"
            );
            signature.fill(0xa5);
            assert_eq!(
                key.sign(b"message", &[0; SEED_LEN], &mut signature),
                Ok($length)
            );
            assert!($verify(&key.public_key(), b"message", &signature));
            assert!(
                !$verify(&pk, b"message", &signature),
                "old key accepted replacement"
            );
        }
    };
}

public_verifier!(
    public_ml_dsa44_accepts_and_refuses,
    MlDsa44,
    mldsa44_verify,
    MLDSA44_SIG_LEN
);
public_verifier!(
    public_ml_dsa65_accepts_and_refuses,
    MlDsa65,
    mldsa65_verify,
    MLDSA65_SIG_LEN
);
public_verifier!(
    public_ml_dsa87_accepts_and_refuses,
    MlDsa87,
    mldsa87_verify,
    MLDSA87_SIG_LEN
);
