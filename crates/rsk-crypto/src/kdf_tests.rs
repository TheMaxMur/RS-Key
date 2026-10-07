// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn dev() -> Device<'static> {
    Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        otp_key: None,
        latched: false,
    }
}

const OTP: [u8; 32] = [0x5A; 32];

#[test]
fn kbase_otp_vs_nootp_differ() {
    let no = dev().derive_kbase();
    let with = Device {
        otp_key: Some(&OTP),
        ..dev()
    }
    .derive_kbase();
    assert_ne!(no.expose(), with.expose());
    // No-OTP path: HKDF(salt="NO-OTP", ikm=serial_hash, info="DEVICE/ROOT\0").
    let mut expected = [0u8; 32];
    hkdf_sha256(
        SALT_NOOTP,
        dev().serial_hash,
        b"DEVICE/ROOT\0",
        &mut expected,
    )
    .unwrap();
    assert_eq!(no.expose(), &expected);
}

// Each KDF must wire exactly the documented salt / ikm / info.
#[test]
fn compositions_match_primitives() {
    let d = dev();
    let pin = b"123456";

    let kver = d.derive_kver(pin);
    assert_eq!(kver.expose(), &hmac_sha256(d.derive_kbase().expose(), pin));

    let mut want = [0u8; 32];
    hkdf_sha256(d.serial_hash, kver.expose(), b"PIN/VERIFY", &mut want).unwrap();
    assert_eq!(d.pin_derive_verifier(pin).expose(), &want);

    hkdf_sha256(d.serial_hash, kver.expose(), b"PIN/TOKEN", &mut want).unwrap();
    assert_eq!(d.pin_derive_session(pin).expose(), &want);

    let token = [0x77u8; 32];
    hkdf_sha256(d.serial_hash, &token, b"PIN/ENC", &mut want).unwrap();
    assert_eq!(d.pin_derive_kenc(&token).expose(), &want);

    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(d.derive_kbase().expose());
    ikm[32..].copy_from_slice(&token);
    hkdf_sha256(d.serial_hash, &ikm, b"PIN/ENC2", &mut want).unwrap();
    assert_eq!(d.pin_derive_kenc2(&token).expose(), &want);
}

#[test]
fn kbase_otp_arm_reference_vector() {
    // Pinned against an independent Python HKDF implementation
    // (salt=serial_hash, ikm=otp_key, info="DEVICE/ROOT\0") — a
    // cross-implementation vector guards the OTP arm.
    let with = Device {
        otp_key: Some(&OTP),
        ..dev()
    }
    .derive_kbase();
    assert_eq!(
        with.expose(),
        &[
            0xD3, 0x83, 0x07, 0xA2, 0xB9, 0xF0, 0xD4, 0xEF, 0x44, 0xE8, 0x01, 0x3D, 0x95, 0x4A,
            0x89, 0x4A, 0xE0, 0x90, 0x3C, 0xAA, 0xAC, 0xFD, 0x68, 0xFA, 0x61, 0xC1, 0x46, 0x8A,
            0x1F, 0x0B, 0xCD, 0xA7
        ]
    );
}

#[test]
fn without_otp_drops_only_the_key() {
    let d = Device {
        otp_key: Some(&OTP),
        ..dev()
    };
    let old = d.without_otp();
    assert!(old.otp_key.is_none());
    assert_eq!(old.serial_hash, d.serial_hash);
    assert_eq!(old.serial_id, d.serial_id);
    assert_eq!(old.derive_kbase().expose(), dev().derive_kbase().expose());
}

/// The latch closes the arms below the fused root and nothing else: the pre-OTP
/// arm and the clear answer no, while the current arm and PIN verifiers'
/// [`Device::without_otp`] stay as they were.
#[test]
fn the_latch_closes_the_arms_below_the_fused_root() {
    let open = Device {
        otp_key: Some(&OTP),
        ..dev()
    };
    let latched = Device {
        latched: true,
        ..open
    };
    let old = open
        .pre_otp_arm()
        .expect("an unlatched device keeps its pre-OTP arm");
    assert_eq!(
        old.derive_kbase().expose(),
        open.without_otp().derive_kbase().expose()
    );
    assert!(open.clear_arm_open());
    assert!(latched.pre_otp_arm().is_none());
    assert!(!latched.clear_arm_open());
    assert_eq!(
        latched.derive_kbase().expose(),
        open.derive_kbase().expose()
    );
    assert!(latched.without_otp().otp_key.is_none());
}

/// A fused-key source carries the boot's latch into every device built from a read.
#[test]
fn a_fused_read_carries_the_latch_into_its_device() {
    fn read(out: &mut [u8; 32]) -> bool {
        *out = OTP;
        true
    }
    fn blank(_: &mut [u8; 32]) -> bool {
        false
    }
    let (hash, id) = ([0xAB; 32], [1u8, 2, 3, 4, 5, 6, 7, 8]);
    for (src, latched) in [
        (FusedKey::open(read), false),
        (FusedKey::latched(read), true),
    ] {
        let fused = read_fused(Some(src));
        let dev = Device::fused(&hash, &id, &fused).expect("a key that read");
        assert_eq!((dev.otp_key, dev.latched), (Some(&OTP), latched));
    }
    // Before the latch a key that does not read leaves the chip-serial arm, as on
    // an unprovisioned device; past it no arm is left, so there is no device.
    let open = read_fused(Some(FusedKey::open(blank)));
    let dev = Device::fused(&hash, &id, &open).expect("the pre-OTP device");
    assert_eq!((dev.otp_key, dev.latched), (None, false));
    let shut = read_fused(Some(FusedKey::latched(blank)));
    assert!(Device::fused(&hash, &id, &shut).is_none());
    let absent = read_fused(None);
    assert!(Device::fused(&hash, &id, &absent).is_some_and(|d| d.otp_key.is_none()));
}

#[test]
fn info_root_nul_matters() {
    // Dropping the trailing NUL would change the key — guard against a
    // regression that "tidies" INFO_ROOT to 11 bytes.
    let mut with_nul = [0u8; 32];
    let mut without = [0u8; 32];
    hkdf_sha256(
        SALT_NOOTP,
        dev().serial_hash,
        b"DEVICE/ROOT\0",
        &mut with_nul,
    )
    .unwrap();
    hkdf_sha256(SALT_NOOTP, dev().serial_hash, b"DEVICE/ROOT", &mut without).unwrap();
    assert_ne!(with_nul, without);
    assert_eq!(dev().derive_kbase().expose(), &with_nul);
}

#[test]
fn aead_roundtrip_v1_and_v2() {
    let d = dev();
    let token = [0x33u8; 32];
    let nonce = [0x44u8; 12];
    let secret = [0xDEu8; 32];
    for version in [PinKdf::V1, PinKdf::V2] {
        let mut out = [0u8; 12 + 32 + 16];
        let n = d
            .encrypt_with_aad(&token, &secret, version, &nonce, &mut out)
            .unwrap();
        assert_eq!(n, 60);
        let mut back = [0u8; 32];
        let m = d
            .decrypt_with_aad(&token, &out[..n], version, &mut back)
            .unwrap();
        assert_eq!(m, 32);
        assert_eq!(back, secret);
    }
}

#[test]
fn aead_wrong_version_fails() {
    let d = dev();
    let token = [0x33u8; 32];
    let nonce = [0x44u8; 12];
    let secret = [0xDEu8; 32];
    let mut out = [0u8; 60];
    let n = d
        .encrypt_with_aad(&token, &secret, PinKdf::V2, &nonce, &mut out)
        .unwrap();
    let mut back = [0u8; 32];
    // Decrypting V2 ciphertext as V1 derives a different kenc → auth fails.
    assert_eq!(
        d.decrypt_with_aad(&token, &out[..n], PinKdf::V1, &mut back),
        Err(Error::Decrypt)
    );
}

#[test]
fn aead_tamper_fails() {
    let d = dev();
    let token = [0x33u8; 32];
    let nonce = [0x44u8; 12];
    let mut out = [0u8; 60];
    d.encrypt_with_aad(&token, &[0xAAu8; 32], PinKdf::V2, &nonce, &mut out)
        .unwrap();
    out[20] ^= 0x01; // flip a ciphertext byte
    let mut back = [0u8; 32];
    assert_eq!(
        d.decrypt_with_aad(&token, &out, PinKdf::V2, &mut back),
        Err(Error::Decrypt)
    );
}

#[test]
fn hash_funcs_deterministic_and_empty_safe() {
    let d = dev();
    assert_eq!(d.hash_multi(b"pin"), d.hash_multi(b"pin"));
    assert_eq!(
        d.double_hash_pin(b"pin").expose(),
        d.double_hash_pin(b"pin").expose()
    );
    // Must not hang / panic on empty input.
    assert_eq!(d.hash_multi(b""), crate::hash::sha256(d.serial_id));
    let _ = d.double_hash_pin(b"");
}

#[test]
fn short_aead_outputs_are_refused_before_any_write() {
    let d = dev();
    let token = [0x33; 32];
    let nonce = [0x44; NONCE_LEN];
    let plain = [0xDE; 32];
    for version in [PinKdf::V1, PinKdf::V2] {
        let mut encrypted = [0u8; NONCE_LEN + 32 + TAG_LEN];
        let n = d
            .encrypt_with_aad(&token, &plain, version, &nonce, &mut encrypted)
            .unwrap();
        for capacity in 0..=n + 1 {
            let mut out = [0xA5; NONCE_LEN + 33 + TAG_LEN];
            let result = d.encrypt_with_aad(&token, &plain, version, &nonce, &mut out[..capacity]);
            if capacity < n {
                assert_eq!(result, Err(Error::BadLength));
                assert_eq!(out, [0xA5; NONCE_LEN + 33 + TAG_LEN]);
            } else {
                assert_eq!(result, Ok(n));
                assert_eq!(&out[..n], &encrypted);
                assert!(out[n..].iter().all(|&b| b == 0xA5));
            }
        }
        for input_len in 0..NONCE_LEN + TAG_LEN {
            let mut out = [0xA5; 33];
            assert_eq!(
                d.decrypt_with_aad(&token, &encrypted[..input_len], version, &mut out),
                Err(Error::BadLength)
            );
            assert_eq!(out, [0xA5; 33]);
        }
        for capacity in 0..=plain.len() + 1 {
            let mut out = [0xA5; 33];
            let result = d.decrypt_with_aad(&token, &encrypted, version, &mut out[..capacity]);
            if capacity < plain.len() {
                assert_eq!(result, Err(Error::BadLength));
                assert_eq!(out, [0xA5; 33]);
            } else {
                assert_eq!(result, Ok(plain.len()));
                assert_eq!(&out[..plain.len()], &plain);
                assert!(out[plain.len()..].iter().all(|&b| b == 0xA5));
            }
        }
    }
}

#[test]
fn wiping_a_fused_read_clears_its_key_without_changing_its_latch() {
    fn read(out: &mut [u8; 32]) -> bool {
        *out = OTP;
        true
    }
    for source in [FusedKey::open(read), FusedKey::latched(read)] {
        let mut fused = read_fused(Some(source));
        assert_eq!(fused.key(), Some(&OTP));
        let latched = fused.latched;
        fused.wipe();
        assert_eq!(fused.key(), Some(&[0; 32]));
        assert_eq!(fused.latched, latched);
        fused.wipe();
        assert_eq!(fused.key(), Some(&[0; 32]));
    }
    let mut absent = read_fused(None);
    absent.wipe();
    assert_eq!(absent.key(), None);
    assert!(!absent.latched);
}
