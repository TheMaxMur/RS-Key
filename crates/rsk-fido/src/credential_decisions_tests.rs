// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn record_composition_rejects_each_bad_bound_without_changing_output() {
    let hash = sha256(b"example.com");
    let resident = [0x42; CRED_RESIDENT_LEN];
    let point = [0x04; 65];
    let boxed = b"opaque box";
    let needed = RECORD_PREFIX + 1 + point.len() + boxed.len();
    for len in 0..needed {
        let mut out = [0xA5; CRED_REC_MAX];
        assert!(compose_cred_record(&hash, &resident, &point, boxed, &mut out[..len]).is_none());
        assert_eq!(out, [0xA5; CRED_REC_MAX]);
    }
    for rid in [
        &resident[..CRED_RESIDENT_LEN - 1],
        &[0x42; CRED_RESIDENT_LEN + 1],
    ] {
        let mut out = [0xA5; CRED_REC_MAX];
        assert!(compose_cred_record(&hash, rid, &point, boxed, &mut out).is_none());
        assert_eq!(out, [0xA5; CRED_REC_MAX]);
        assert_eq!(resident_key_input(boxed, Some(rid)), boxed);
        assert!(!resident_has_trailer(rid));
    }
    let mut out = [0xA5; CRED_REC_MAX];
    assert!(
        compose_cred_record(&hash, &resident, &[0; CRED_PUBKEY_MAX + 1], boxed, &mut out).is_none()
    );
    assert_eq!(out, [0xA5; CRED_REC_MAX]);
    assert_eq!(
        compose_cred_record(&hash, &resident, &point, boxed, &mut out[..needed]),
        Some(needed)
    );
    assert_eq!(&out[..32], &hash);
    assert_eq!(&out[32..RECORD_PREFIX], &resident);
    assert_eq!(cred_record_pubkey(&out[..needed]), Some(&point[..]));
    assert_eq!(cred_record_box(&out[..needed]), boxed);
    assert!(out[needed..].iter().all(|&b| b == 0xA5));
}

#[test]
fn truncated_record_trailers_never_supply_a_partial_cached_point() {
    let mut rec = [0x42; RECORD_PREFIX + 1 + 65];
    rec[RECORD_PREFIX] = 65;
    for len in 0..rec.len() {
        assert!(
            cred_record_pubkey(&rec[..len]).is_none(),
            "record length {len}"
        );
        assert!(cred_record_box(&rec[..len]).is_empty());
    }
    assert_eq!(cred_record_pubkey(&rec), Some(&rec[RECORD_PREFIX + 1..]));
    rec[RECORD_PREFIX] = 0;
    assert!(cred_record_pubkey(&rec).is_none());
    assert_eq!(cred_record_box(&rec), &rec[RECORD_PREFIX + 1..]);
}

#[test]
fn short_credential_outputs_and_load_scratch_refuse_without_a_write() {
    let hash = sha256(b"example.com");
    for len in 0..WRAP_LEN {
        let mut out = [0xA5; WRAP_LEN];
        assert_eq!(
            credential_create(&SEED, &dev(), &input(), &hash, &IV, &mut out[..len]),
            Err(Error::NoMemory)
        );
        assert_eq!(out, [0xA5; WRAP_LEN]);
    }
    let mut boxed = [0u8; 512];
    let n = credential_create(&SEED, &dev(), &input(), &hash, &IV, &mut boxed).unwrap();
    for len in 0..n {
        let mut scratch = [0xA5; 512];
        assert!(credential_load(&SEED, &boxed[..n], &hash, &mut scratch[..len]).is_none());
        assert_eq!(scratch, [0xA5; 512]);
    }
    let mut scratch = [0u8; 512];
    assert_eq!(
        credential_load(&SEED, &boxed[..n], &hash, &mut scratch[..n])
            .unwrap()
            .user_id,
        input().user_id
    );
}

#[test]
fn serial_source_bounds_do_not_create_an_unfinished_credential() {
    let hash = sha256(b"example.com");
    let mut out = [0u8; 512];
    let mut d = dev();
    d.serial_id = &[0x42; 33];
    assert_eq!(
        credential_create(&SEED, &d, &input(), &hash, &IV, &mut out),
        Err(Error::NoMemory)
    );
    d.serial_id = &[0x42; 32];
    let n = credential_create(&SEED, &d, &input(), &hash, &IV, &mut out).unwrap();
    let mut scratch = [0u8; 512];
    assert!(credential_load(&SEED, &out[..n], &hash, &mut scratch).is_some());
}

#[test]
fn rp_boxes_require_a_complete_buffer_and_authenticated_utf8() {
    let hash = sha256(b"example.com");
    let mut boxed = [0u8; RP_REC_MAX];
    let n = seal_rp_id(&SEED, "example.com", &hash, &mut boxed).unwrap();
    for len in 0..n {
        let mut out = [0xA5; RP_REC_MAX];
        assert!(unseal_rp_id(&SEED, &hash, &boxed[..n], &mut out[..len]).is_none());
    }
    let mut out = [0u8; RP_REC_MAX];
    assert_eq!(
        unseal_rp_id(&SEED, &hash, &boxed[..n], &mut out),
        Some(("example.com", true))
    );
    assert!(unseal_rp_id(&SEED, &hash, &[0xFF], &mut out).is_none());
    let mut invalid = [0u8; IV_LEN + 1 + TAG_LEN];
    invalid[..IV_LEN].copy_from_slice(&IV);
    invalid[IV_LEN] = 0xFF;
    let mut key = derive_chacha_key(&SEED, RP_PROTO);
    let tag = chacha20poly1305_encrypt(key.expose(), &IV, &hash, &mut invalid[IV_LEN..IV_LEN + 1]);
    key.wipe();
    invalid[IV_LEN + 1..].copy_from_slice(&tag);
    assert!(unseal_rp_id(&SEED, &hash, &invalid, &mut out).is_none());
    assert_eq!(
        unseal_rp_id(&SEED, &hash, b"legacy.example", &mut out),
        Some(("legacy.example", false))
    );
}

#[test]
fn authenticated_malformed_credential_bodies_are_still_refused() {
    let hash = sha256(b"example.com");
    for body in [
        &[0xFF][..],
        &[0xA1, 1, 0],
        &[0xA1, 7, 0xBF, 0xFF],
        &[0xA1, 8, 1],
    ] {
        let mut boxed = [0u8; 512];
        boxed[..IV_LEN].copy_from_slice(&IV);
        let end = IV_LEN + body.len();
        boxed[IV_LEN..end].copy_from_slice(body);
        let mut key = derive_chacha_key(&SEED, CRED_PROTO);
        let tag = chacha20poly1305_encrypt(key.expose(), &IV, &hash, &mut boxed[IV_LEN..end]);
        key.wipe();
        boxed[end..end + TAG_LEN].copy_from_slice(&tag);
        let prefix = end + TAG_LEN;
        let silent = silent_tag(&dev(), &boxed[..prefix], &hash).unwrap();
        boxed[prefix..prefix + SILENT_TAG_LEN].copy_from_slice(&silent);
        let mut scratch = [0u8; 512];
        assert!(
            credential_load(
                &SEED,
                &boxed[..prefix + SILENT_TAG_LEN],
                &hash,
                &mut scratch
            )
            .is_none(),
            "body {body:02x?}"
        );
    }
}
