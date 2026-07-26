// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the credential-box extension round-trip: sealing arbitrary credProtect /
//! credBlob / flag inputs into a box (`credential_create`) and loading it back
//! (`credential_load`) must never panic and must reproduce the extensions (a
//! credBlob is sealed only when no longer than `MAX_CREDBLOB_LENGTH`).

use libfuzzer_sys::fuzz_target;
use rsk_crypto::{Device, sha256};
use rsk_fido::consts::MAX_CREDBLOB_LENGTH;
use rsk_fido::credential::{CredExt, CredInput, credential_create, credential_load};

fuzz_target!(|data: &[u8]| {
    let dev = Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    };
    let seed = [0x42u8; 32];
    let rp_hash = sha256(b"example.com");
    let iv = [0x11u8; 12];

    let flags = data.first().copied().unwrap_or(0);
    let cred_protect = (flags & 0x03) as u64; // 0..=3
    let blob = data.get(1..).unwrap_or(&[]);
    let ext = CredExt {
        cred_protect,
        cred_blob: blob,
        hmac_secret: flags & 0x10 != 0,
        large_blob_key: flags & 0x20 != 0,
        third_party_payment: flags & 0x40 != 0,
    };
    let input = CredInput {
        rp_id: "example.com",
        user_id: &[1, 2, 3, 4],
        user_name: "u",
        user_display_name: "d",
        use_sign_count: true,
        rk: false,
        created_ms: 0,
        alg: -7,  // ES256
        curve: 1, // P-256
        ext,
    };

    let mut out = [0u8; 1024];
    if let Ok(len) = credential_create(&seed, &dev, &input, &rp_hash, &iv, &mut out) {
        let mut scratch = [0u8; 1024];
        let c = credential_load(&seed, &out[..len], &rp_hash, &mut scratch)
            .expect("a freshly sealed box must load");
        assert_eq!(c.ext.cred_protect, cred_protect);
        assert_eq!(c.ext.hmac_secret, flags & 0x10 != 0);
        assert_eq!(c.ext.large_blob_key, flags & 0x20 != 0);
        assert_eq!(c.ext.third_party_payment, flags & 0x40 != 0);
        if !blob.is_empty() && blob.len() <= MAX_CREDBLOB_LENGTH {
            assert_eq!(c.ext.cred_blob, blob);
        } else {
            assert!(c.ext.cred_blob.is_empty());
        }
    }
});
