// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz ChaCha20-Poly1305: any (key, nonce, aad, plaintext) must survive an
//! encrypt → decrypt round-trip, and decrypting a flipped tag must never panic
//! (and must not authenticate). Mirrors the AES-GCM target.

use libfuzzer_sys::fuzz_target;
use rsk_crypto::chachapoly;

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
    let mut aad = [0u8; 32];
    aad[..aad_len].copy_from_slice(&msg[..aad_len]);
    let aad = &aad[..aad_len];

    let tag = chachapoly::chacha20poly1305_encrypt(&key, &nonce, aad, &mut buf[..n]);

    let mut dec = [0u8; 2048];
    dec[..n].copy_from_slice(&buf[..n]);
    chachapoly::chacha20poly1305_decrypt(&key, &nonce, aad, &mut dec[..n], &tag)
        .expect("round-trip authenticates");
    assert_eq!(&dec[..n], &msg[..n]);

    let mut bad = tag;
    bad[0] ^= 0xff;
    let mut dec2 = [0u8; 2048];
    dec2[..n].copy_from_slice(&buf[..n]);
    assert!(chachapoly::chacha20poly1305_decrypt(&key, &nonce, aad, &mut dec2[..n], &bad).is_err());

    // And the good tag under a *different* AAD: an implementation that ignores AAD
    // would pass every check above. With no byte to flip, the length is the
    // difference — `aad2` must never equal `aad` or the assertion inverts.
    let mut alt = [0u8; 32];
    alt[..aad_len].copy_from_slice(aad);
    let aad2: &[u8] = if aad_len == 0 {
        &[0u8]
    } else {
        // The index comes off the input rather than being fixed at 0: an AEAD
        // that authenticated only `aad[..1]` passed every byte-0 flip ever
        // generated — measured, 300k executions.
        alt[nonce[0] as usize % aad_len] ^= 0xff;
        &alt[..aad_len]
    };
    let mut dec3 = [0u8; 2048];
    dec3[..n].copy_from_slice(&buf[..n]);
    assert!(
        chachapoly::chacha20poly1305_decrypt(&key, &nonce, aad2, &mut dec3[..n], &tag).is_err()
    );
});
