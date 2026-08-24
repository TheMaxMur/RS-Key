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
    // Assert the three arms one by one, so a swapped pair cannot pass by
    // covering for each other.
    assert_eq!(
        ec_sw(EcError::Failed),
        Sw::EXEC_ERROR,
        "a failed computation must stay 6400"
    );
    assert_eq!(
        ec_sw(EcError::BadPoint),
        Sw::DATA_INVALID,
        "an unusable point or scalar must stay 6984"
    );
    assert_eq!(
        ec_sw(EcError::Unsupported),
        Sw::FUNC_NOT_SUPPORTED,
        "an operation the curve does not offer must stay 6A81"
    );
}
