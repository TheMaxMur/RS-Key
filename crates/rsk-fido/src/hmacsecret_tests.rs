// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_crypto::hmac_sha256;
use rsk_crypto::pinproto::{authenticate, encrypt, public_xy};

struct SeqRng(u64);
impl Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

fn scalar(seed: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = seed;
    s[31] = seed;
    s
}

const SEED: [u8; 32] = [0x42; 32];
const CRED_ID: [u8; 80] = [0x55; 80];

// The platform half: encrypt + MAC the salts under the shared secret.
fn platform(
    proto: PinProto,
    plat_scalar: &[u8; 32],
    auth_x: &[u8; 32],
    auth_y: &[u8; 32],
    salt: &[u8],
) -> (std::vec::Vec<u8>, std::vec::Vec<u8>, std::vec::Vec<u8>) {
    let mut shared = [0u8; 64];
    let slen = pinproto::ecdh(proto, plat_scalar, auth_x, auth_y, &mut shared).unwrap();
    let shared = &shared[..slen];
    let iv = [0x33u8; 16];
    let mut enc = [0u8; 16 + 64];
    let ne = encrypt(proto, shared, &iv, salt, &mut enc).unwrap();
    let mut auth = [0u8; 32];
    let na = authenticate(proto, shared, &enc[..ne], &mut auth).unwrap();
    (enc[..ne].to_vec(), auth[..na].to_vec(), shared.to_vec())
}

fn roundtrip(proto: PinProto, two_salts: bool) {
    let auth_scalar = scalar(0x11);
    let plat_scalar = scalar(0x22);
    let (ax, ay) = public_xy(&auth_scalar).unwrap();
    let (px, py) = public_xy(&plat_scalar).unwrap();

    let salt64: [u8; 64] = core::array::from_fn(|i| if i < 32 { 0xA1 } else { 0xB2 });
    let salt: &[u8] = if two_salts { &salt64 } else { &salt64[..32] };
    let (salt_enc, salt_auth, shared) = platform(proto, &plat_scalar, &ax, &ay, salt);

    let req = HmacSecretReq {
        peer_present: true,
        peer_x: px,
        peer_y: py,
        salt_enc: Some(&salt_enc),
        salt_auth: Some(&salt_auth),
        proto: if proto == PinProto::One { 1 } else { 2 },
        present: true,
    };
    let mut rng = SeqRng(1);
    let mut out = [0u8; 80];
    let nout = eval(
        &req,
        &auth_scalar,
        &SEED,
        &CRED_ID,
        false,
        &mut rng,
        &mut out,
    )
    .unwrap();
    assert_eq!(nout, salt_enc.len());

    // The platform decrypts the output and checks it against its own HMAC.
    let mut dec = [0u8; 64];
    let ndec = pinproto::decrypt(proto, &shared, &out[..nout], &mut dec).unwrap();
    let cr = derive_hmac_key(&SEED, &CRED_ID);
    assert_eq!(
        &dec[..32],
        &hmac_sha256(&cr.expose()[..32], &salt[..32])[..]
    );
    if two_salts {
        assert_eq!(ndec, 64);
        assert_eq!(
            &dec[32..64],
            &hmac_sha256(&cr.expose()[..32], &salt[32..64])[..]
        );
    } else {
        assert_eq!(ndec, 32);
    }
}

#[test]
fn hmac_secret_roundtrip() {
    for proto in [PinProto::One, PinProto::Two] {
        roundtrip(proto, false);
        roundtrip(proto, true);
    }
}

#[test]
fn uv_half_differs_from_non_uv() {
    let auth_scalar = scalar(0x11);
    let plat_scalar = scalar(0x22);
    let (ax, ay) = public_xy(&auth_scalar).unwrap();
    let (px, py) = public_xy(&plat_scalar).unwrap();
    let salt = [0xA1u8; 32];
    let (salt_enc, salt_auth, shared) = platform(PinProto::Two, &plat_scalar, &ax, &ay, &salt);
    let req = HmacSecretReq {
        peer_present: true,
        peer_x: px,
        peer_y: py,
        salt_enc: Some(&salt_enc),
        salt_auth: Some(&salt_auth),
        proto: 2,
        present: true,
    };
    let mut rng = SeqRng(1);
    let mut decrypt_out = |uv: bool| {
        let mut out = [0u8; 80];
        let n = eval(&req, &auth_scalar, &SEED, &CRED_ID, uv, &mut rng, &mut out).unwrap();
        let mut dec = [0u8; 64];
        pinproto::decrypt(PinProto::Two, &shared, &out[..n], &mut dec).unwrap();
        dec
    };
    let cr = derive_hmac_key(&SEED, &CRED_ID);
    let without = decrypt_out(false);
    let with = decrypt_out(true);
    assert_eq!(&without[..32], &hmac_sha256(&cr.expose()[..32], &salt)[..]);
    assert_eq!(&with[..32], &hmac_sha256(&cr.expose()[32..], &salt)[..]);
    assert_ne!(&without[..32], &with[..32]);
}

/// §12.5 verbatim: "Authenticator calls verify(shared secret, saltEnc, saltAuth) —
/// if the verification fails, return CTAP2_ERR_PIN_AUTH_INVALID." It used to be
/// CTAP2_ERR_EXTENSION_FIRST, a code about extension ordering that tells a platform
/// to retry the very request that just failed its MAC. No YubiKey reading exists:
/// §12.5 puts the check after "the authenticator waits for user consent", and the
/// oracle refuses hmac-secret on an `up: false` assertion outright.
#[test]
fn bad_salt_auth_is_pin_auth_invalid() {
    let auth_scalar = scalar(0x11);
    let plat_scalar = scalar(0x22);
    let (ax, ay) = public_xy(&auth_scalar).unwrap();
    let (px, py) = public_xy(&plat_scalar).unwrap();
    let salt = [0xA1u8; 32];
    let (salt_enc, mut salt_auth, _shared) = platform(PinProto::Two, &plat_scalar, &ax, &ay, &salt);
    salt_auth[0] ^= 0xFF; // corrupt the MAC
    let req = HmacSecretReq {
        peer_present: true,
        peer_x: px,
        peer_y: py,
        salt_enc: Some(&salt_enc),
        salt_auth: Some(&salt_auth),
        proto: 2,
        present: true,
    };
    let mut rng = SeqRng(1);
    let mut out = [0u8; 80];
    assert_eq!(
        eval(
            &req,
            &auth_scalar,
            &SEED,
            &CRED_ID,
            false,
            &mut rng,
            &mut out
        ),
        Err(CtapError::PinAuthInvalid)
    );
}

#[test]
fn bad_salt_length_rejected() {
    let auth_scalar = scalar(0x11);
    let req = HmacSecretReq {
        peer_present: true,
        salt_enc: Some(&[0u8; 20]), // not one of the four legal wire lengths
        salt_auth: Some(&[0u8; 32]),
        proto: 2,
        present: true,
        ..Default::default()
    };
    let mut rng = SeqRng(1);
    let mut out = [0u8; 80];
    assert_eq!(
        eval(
            &req,
            &auth_scalar,
            &SEED,
            &CRED_ID,
            false,
            &mut rng,
            &mut out
        ),
        Err(CtapError::InvalidLength)
    );
}

/// A value with no sub-fields in it asks for no evaluation, and the oracle reads
/// it as if the extension had not been sent at all: a YubiKey 5.8.0 completes the
/// ceremony for an empty map and for a boolean, on `getAssertion` and
/// `makeCredential` alike, and even on an `up:false` request — where a *present*
/// extension is refused. Ours used to answer MISSING_PARAMETER to the empty map and
/// INVALID_CBOR to the boolean, both of which end the ceremony.
///
/// The refused half is the correction: this was measured on a BOOLEAN and written
/// as "not a map", which is wider than the reference. Sweeping the value shapes
/// against a real 5.8.0 gives a map or a boolean accepted and every other CBOR type
/// refused with CBOR_UNEXPECTED_TYPE — the same for both extensions.
#[test]
fn only_a_map_or_a_boolean_is_a_value_with_no_subfields() {
    for (label, bytes) in [
        ("empty map", &[0xA0u8][..]),
        ("boolean true", &[0xF5u8][..]),
        ("boolean false", &[0xF4u8][..]),
    ] {
        // Matched, not unwrapped: deriving Debug/PartialEq on a struct that holds
        // salt ciphertext just to let a test print it is the wrong trade.
        match parse_bytes(bytes) {
            Ok(req) => assert!(!req.present, "{label} must read as absent"),
            Err(_) => panic!("{label} must parse, not fail"),
        }
    }
    for (label, bytes) in [
        ("uint 1", &[0x01u8][..]),
        ("uint 0", &[0x00u8][..]),
        ("nint -1", &[0x20u8][..]),
        ("text string", &[0x61u8, b'x'][..]),
        ("byte string", &[0x41u8, b'x'][..]),
        ("empty array", &[0x80u8][..]),
        ("array [1]", &[0x81u8, 0x01][..]),
    ] {
        assert!(
            matches!(parse_bytes(bytes), Err(CtapError::CborUnexpectedType)),
            "{label} is the wrong CBOR type for this extension and must be refused \
             as one — reading it as absent is the over-wide rule this replaces"
        );
    }
}

/// The carve-out the rule above must not widen: an INDEFINITE-length map is a map,
/// so it is not "no sub-fields" — it stays the non-canonical encoding `def_map`
/// has always refused.
#[test]
fn an_indefinite_length_map_is_still_invalid_cbor() {
    assert!(matches!(
        parse_bytes(&[0xBFu8, 0xFF]),
        Err(CtapError::InvalidCbor)
    ));
}

/// `keyAgreement` absent from a map that carries other fields. The coordinates
/// default to zero, which is not a point, so this used to surface as the ECDH's
/// INVALID_PARAMETER; a YubiKey 5.8.0 calls it MISSING_PARAMETER, like the salts.
#[test]
fn an_absent_key_agreement_is_missing_parameter() {
    let req = HmacSecretReq {
        peer_present: false,
        salt_enc: Some(&[0u8; 32]),
        salt_auth: Some(&[0u8; 32]),
        proto: 2,
        present: true,
        ..Default::default()
    };
    let mut rng = SeqRng(1);
    let mut out = [0u8; 80];
    assert_eq!(
        eval(
            &req,
            &scalar(0x11),
            &SEED,
            &CRED_ID,
            false,
            &mut rng,
            &mut out
        ),
        Err(CtapError::MissingParameter)
    );
}
