// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn curve_from_attr_matches_oid_only() {
    // ECDSA- and ECDH-tagged P-256 share an OID → same curve.
    assert_eq!(
        curve_from_attr(&[0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]),
        Some(Curve::P256)
    );
    assert_eq!(
        curve_from_attr(&[0x12, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]),
        Some(Curve::P256)
    );
    // RSA / unknown OIDs are not EC curves.
    assert_eq!(curve_from_attr(&[0x01, 0x08, 0x00, 0x00, 0x20, 0x00]), None);
}

#[test]
fn ec_sw_reproduces_every_status_word() {
    // This table **is** wire surface: the status word a PSO / INTERNAL
    // AUTHENTICATE answers with when the key refuses. It must stay identical
    // to `rsk-piv`'s copy — `rsk-ec` names the target in each variant's doc.
    // Assert the arms one by one, so a swapped pair cannot pass by covering for
    // each other.
    assert_eq!(
        ec_sw(EcError::Failed),
        Sw::EXEC_ERROR,
        "a failed computation must stay 6400"
    );
    assert_eq!(
        ec_sw(EcError::BadPoint),
        Sw::WRONG_DATA,
        "an undecodable peer point must answer 6A80, as a YubiKey 5.8.0 does"
    );
    assert_eq!(
        ec_sw(EcError::RejectedPoint),
        Sw::MEMORY_FAILURE,
        "a small-order peer must answer 6581, as a YubiKey 5.8.0's OpenPGP does"
    );
    assert_eq!(
        ec_sw(EcError::Unsupported),
        Sw::FUNC_NOT_SUPPORTED,
        "an operation the curve does not offer must stay 6A81"
    );
}

#[test]
fn legacy_record_widths_accept_only_the_layouts_older_builds_wrote() {
    for len in 0..=1400 {
        assert_eq!(legacy_ec_len(len), [33, 49, 67].contains(&len));
        assert_eq!(legacy_aes_len(len), [16, 24, 32].contains(&len));
        let rsa_lengths = (32..=256).step_by(32).flat_map(|half| [half * 2, half * 5]);
        assert_eq!(
            legacy_rsa_len(len),
            rsa_lengths.into_iter().any(|allowed| len == allowed)
        );
        assert_eq!(
            crate::consts::pin_kdf_size(std::hint::black_box(len)),
            len + 28
        );
    }
}

#[test]
fn the_signature_counter_keeps_every_byte_of_a_nonzero_value() {
    // Small counters only ever exercise the low lane; these literals pin the
    // high and middle ones, and the carries, with expected bytes not recomputed
    // from the expression under test.
    for (before, after) in [
        ([0x12, 0x34, 0x56], [0x12, 0x34, 0x57]),
        ([0x00, 0x00, 0xff], [0x00, 0x01, 0x00]),
        ([0x00, 0xff, 0xff], [0x01, 0x00, 0x00]),
        ([0xff, 0xff, 0xff], [0x00, 0x00, 0x00]),
    ] {
        let mut fs = rsk_fs::Fs::new(rsk_fs::storage::ram::RamStorage::new());
        fs.put(EF_SIG_COUNT, &before).unwrap();
        assert_eq!(inc_sig_count(&mut fs), Ok(()), "{before:02X?}");
        let mut got = [0u8; 3];
        assert_eq!(fs.read(EF_SIG_COUNT, &mut got), Some(3));
        assert_eq!(got, after, "{before:02X?}");
    }
}

#[test]
fn a_missing_signature_counter_is_not_created_by_increment() {
    let mut fs = rsk_fs::Fs::new(rsk_fs::storage::ram::RamStorage::new());
    let generation = fs.write_gen();
    assert_eq!(inc_sig_count(&mut fs), Err(Sw::REFERENCE_NOT_FOUND));
    assert_eq!(fs.write_gen(), generation);
    assert!(!fs.has_data(EF_SIG_COUNT));
}
