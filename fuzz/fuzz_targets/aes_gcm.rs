// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the AES-256-GCM primitive: any (key, nonce, aad, plaintext) must survive
//! an encrypt → decrypt round-trip, and decrypting attacker-chosen tags must never
//! panic (and must not authenticate).

use libfuzzer_sys::fuzz_target;
use rsk_crypto::aes;

fuzz_target!(|data: &[u8]| {
    // Carve a key (32) + nonce (12) out of the front; the rest is plaintext/aad.
    if data.len() < 44 {
        return;
    }
    let key: [u8; 32] = data[..32].try_into().unwrap();
    let nonce: [u8; 12] = data[32..44].try_into().unwrap();
    let msg = &data[44..];

    let n = msg.len().min(2048);
    let aad_len = msg.len().min(32);

    let mut buf = [0u8; 2048];
    buf[..n].copy_from_slice(&msg[..n]);
    // AAD taken from a copy so it doesn't alias the in-place buffer.
    let mut aad = [0u8; 32];
    aad[..aad_len].copy_from_slice(&msg[..aad_len]);
    let aad = &aad[..aad_len];

    let tag = aes::aes256gcm_encrypt(&key, &nonce, aad, &mut buf[..n]);

    // Round-trip must recover the plaintext.
    let mut dec = [0u8; 2048];
    dec[..n].copy_from_slice(&buf[..n]);
    aes::aes256gcm_decrypt(&key, &nonce, aad, &mut dec[..n], &tag)
        .expect("round-trip authenticates");
    assert_eq!(&dec[..n], &msg[..n]);

    // A flipped tag must be rejected, never panic.
    let mut bad = tag;
    bad[0] ^= 0xff;
    let mut dec2 = [0u8; 2048];
    dec2[..n].copy_from_slice(&buf[..n]);
    assert!(aes::aes256gcm_decrypt(&key, &nonce, aad, &mut dec2[..n], &bad).is_err());

    // The good tag under a *different* AAD must be rejected too: AAD is what binds
    // a sealed secret to its FID and generation, so a decrypt that ignores it
    // cannot be allowed to pass this target. With no byte to flip, the length is
    // the difference — `aad2` must never equal `aad` or the assertion inverts.
    let mut alt = [0u8; 32];
    alt[..aad_len].copy_from_slice(aad);
    let aad2: &[u8] = if aad_len == 0 {
        &[0u8]
    } else {
        alt[0] ^= 0xff;
        &alt[..aad_len]
    };
    let mut dec3 = [0u8; 2048];
    dec3[..n].copy_from_slice(&buf[..n]);
    assert!(aes::aes256gcm_decrypt(&key, &nonce, aad2, &mut dec3[..n], &tag).is_err());
});
