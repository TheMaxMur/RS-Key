// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Wycheproof's ECDH and X25519 cases (`third_party/wycheproof/`, Apache-2.0, from
//! `scripts/wycheproof_vectors.py`) through [`PrivKey::ecdh`], the agreement both card
//! applets run on a host's point. The counts make a case lost in a refresh red.

use super::*;

const ECPOINT: &str = include_str!("../../../third_party/wycheproof/ecdh-ecpoint.txt");
const SPKI: &str = include_str!("../../../third_party/wycheproof/ecdh-spki.txt");
const X25519: &str = include_str!("../../../third_party/wycheproof/x25519.txt");

/// One line of a vector file: `curve tcId result private public shared flags comment`.
struct Case {
    at: String,
    curve: Curve,
    invalid: bool,
    private: Vec<u8>,
    public: Vec<u8>,
    shared: Vec<u8>,
    flags: &'static str,
}

impl Case {
    fn has(&self, flag: &str) -> bool {
        self.flags.split(',').any(|f| f == flag)
    }
}

fn cases(text: &'static str) -> Vec<Case> {
    let lines = text.lines().filter(|l| !l.starts_with('#'));
    lines
        .map(|line| {
            let fields: Vec<&'static str> = line.splitn(8, ' ').collect();
            let [
                curve,
                tc_id,
                result,
                private,
                public,
                shared,
                flags,
                _comment,
            ] = fields[..]
            else {
                panic!("{} of 8 fields: {line:.60}", fields.len());
            };
            Case {
                at: format!("{curve} tcId {tc_id} ({flags})"),
                curve: named(curve),
                invalid: match result {
                    "valid" | "acceptable" => false,
                    "invalid" => true,
                    v => panic!("a Wycheproof result of {v:?}"),
                },
                private: hex(private),
                public: hex(public),
                shared: hex(shared),
                flags,
            }
        })
        .collect()
}

fn named(curve: &str) -> Curve {
    match curve {
        "secp256r1" => Curve::P256,
        "secp384r1" => Curve::P384,
        "secp521r1" => Curve::P521,
        "secp256k1" => Curve::K256,
        "brainpoolP256r1" => Curve::Bp256,
        "brainpoolP384r1" => Curve::Bp384,
        "curve25519" => Curve::X25519,
        c => panic!("a curve named {c:?}"),
    }
}

/// `-` is an empty field.
fn hex(s: &str) -> Vec<u8> {
    let s = if s == "-" { "" } else { s };
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// What a YubiKey 5.8.0's OpenPGP answers: 6A80 (`BadPoint`) for all but `04 ‖ x ‖ y`
/// at the field's width, compressed points included, and 6581 (`RejectedPoint`) for
/// such a point off the curve. An InvalidAsn case here is one tampered in place.
fn yubikey_answer(case: &Case) -> Result<Vec<u8>, EcError> {
    let uncompressed = 1 + 2 * coordinate_len(case.curve);
    if case.public.len() != uncompressed || case.public.first() != Some(&0x04) {
        Err(EcError::BadPoint)
    } else if case.invalid || case.has("InvalidAsn") {
        Err(EcError::RejectedPoint)
    } else {
        Ok(case.shared.clone())
    }
}

fn coordinate_len(curve: Curve) -> usize {
    match curve {
        Curve::P256 | Curve::K256 | Curve::Bp256 => 32,
        Curve::P384 | Curve::Bp384 => 48,
        Curve::P521 => 66,
        c => panic!("{c:?} has no SEC1 point"),
    }
}

#[test]
fn wycheproof_ecdh_agrees_or_refuses_like_a_yubikey() {
    let (ecpoint, spki) = (cases(ECPOINT), cases(SPKI));
    assert_eq!(
        (ecpoint.len(), spki.len()),
        (1806, 1734),
        "Wycheproof ECDH cases"
    );
    for case in ecpoint.iter().chain(&spki) {
        let key = PrivKey::from_scalar(case.curve, &case.private).expect(&case.at);
        let mut out = [0u8; MAX_EC_POINT];
        let got = key.ecdh(&case.public, &mut out).map(|n| out[..n].to_vec());
        assert_eq!(got, yubikey_answer(case), "{}", case.at);
    }
}

#[test]
fn wycheproof_x25519_agrees_or_refuses_like_a_yubikey() {
    let cases = cases(X25519);
    assert_eq!(cases.len(), 518, "Wycheproof X25519 cases");
    for case in &cases {
        // The card keeps the RFC 7748 scalar big-endian, as the OpenPGP MPI it imports.
        let mut scalar = case.private.clone();
        scalar.reverse();
        let key = PrivKey::from_scalar(Curve::X25519, &scalar).expect(&case.at);
        let mut out = [0u8; 32];
        let got = key.ecdh(&case.public, &mut out).map(|n| out[..n].to_vec());
        // A low-order peer agrees to zeros whatever the scalar; a YubiKey 5.8.0 refuses it.
        // The rest agree as RFC 7748 §5 computes, twist and non-canonical points included.
        let want = match case.has("ZeroSharedSecret") {
            true => Err(EcError::RejectedPoint),
            false => Ok(case.shared.clone()),
        };
        assert_eq!(got, want, "{}", case.at);
    }
}
