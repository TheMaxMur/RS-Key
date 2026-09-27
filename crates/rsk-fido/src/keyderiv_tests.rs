// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::ec::P256Key;

// Deterministic test RNG (a simple LCG byte stream).
struct SeqRng(u64);
impl Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

const SEED: [u8; 32] = [0x42; 32];
const APP: [u8; 32] = [0xA5; 32];

#[test]
fn ratchet_is_deterministic_and_path_sensitive() {
    let p1 = [0x11u8; 32];
    let mut p2 = p1;
    p2[0] ^= 0x01;
    assert_eq!(
        crate::bare(ratchet(&SEED, &p1)),
        crate::bare(ratchet(&SEED, &p1))
    );
    assert_ne!(
        crate::bare(ratchet(&SEED, &p1)),
        crate::bare(ratchet(&SEED, &p2))
    );
}

#[test]
fn derive_new_then_verify_roundtrips() {
    let mut rng = SeqRng(1);
    let (kh, scalar) = derive_new(&SEED, &APP, &mut rng);
    // The handle's path reproduces the same scalar.
    assert_eq!(
        crate::bare(verify_key(&SEED, &APP, &kh)),
        Some(crate::bare(&scalar))
    );
    // Every entry's high bit is set.
    for i in 0..KEY_PATH_ENTRIES {
        assert_ne!(kh[i * 4 + 3] & 0x80, 0);
    }
    // The derived scalar is a usable P-256 key.
    assert!(P256Key::from_scalar(scalar.expose()).is_some());
}

#[test]
fn verify_rejects_wrong_app_and_tamper() {
    let mut rng = SeqRng(2);
    let (kh, _) = derive_new(&SEED, &APP, &mut rng);
    let mut other_app = APP;
    other_app[0] ^= 0x01;
    assert!((verify_key(&SEED, &other_app, &kh)).is_none());

    let mut bad = kh;
    bad[KEY_PATH_LEN] ^= 0x01; // flip a tag byte
    assert!((verify_key(&SEED, &APP, &bad)).is_none());

    let mut cleared = kh;
    cleared[3] &= 0x7f; // clear a path entry's high bit
    assert!((verify_key(&SEED, &APP, &cleared)).is_none());
}

#[test]
fn fido_load_key_deterministic_and_independent_of_first_bytes() {
    let mut cred = [0u8; 64];
    for (i, b) in cred.iter_mut().enumerate() {
        *b = i as u8;
    }
    let a = fido_load_key(&SEED, &cred).unwrap();
    assert_eq!(
        crate::bare(&a),
        crate::bare(fido_load_key(&SEED, &cred).unwrap())
    );
    // The first 4 bytes are overwritten by the fixed prefix, so changing them
    // must not change the derived key.
    let mut cred2 = cred;
    cred2[0] ^= 0xFF;
    cred2[1] ^= 0xFF;
    assert_eq!(
        crate::bare(&a),
        crate::bare(fido_load_key(&SEED, &cred2).unwrap())
    );
    // But a later path byte does matter.
    cred2[8] ^= 0xFF;
    assert_ne!(
        crate::bare(&a),
        crate::bare(fido_load_key(&SEED, &cred2).unwrap())
    );
    // The leading 32 bytes are a usable P-256 scalar; CredKey reads the curve's
    // length off the front.
    let scalar: [u8; 32] = a.expose()[..32].try_into().unwrap();
    assert!(P256Key::from_scalar(&scalar).is_some());
    assert!(crate::ec::CredKey::from_raw(crate::consts::CURVE_P521 as i64, a.expose()).is_some());
}

#[test]
fn fido_load_key_too_short() {
    assert!((fido_load_key(&SEED, &[0u8; 16])).is_none());
}
