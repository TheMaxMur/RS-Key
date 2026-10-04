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
