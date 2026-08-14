// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the PIN KDF / device-key AEAD: arbitrary PINs (including empty and very
//! long) must terminate without panicking — `hash_multi`/`double_hash_pin`
//! contain an iteration loop that must never hang — and the AEAD must round-trip.

use libfuzzer_sys::fuzz_target;
use rsk_crypto::kdf::{Device, PinKdf};

fuzz_target!(|data: &[u8]| {
    let dev = Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    };

    // Arbitrary PIN — must not hang or panic.
    let _ = dev.hash_multi(data);
    let _ = dev.double_hash_pin(data);
    let _ = dev.derive_kver(data);

    // Domain separation: the at-rest verifier and the bearer session token expand
    // the same kver and must never coincide for any PIN — a collapsed `info` would
    // publish the token in the PIN record.
    assert_ne!(dev.pin_derive_verifier(data), dev.pin_derive_session(data));

    // Device-key AEAD round-trip on a bounded plaintext.
    let token = [0x33u8; 32];
    let nonce = [0x44u8; 12];
    let pt = &data[..data.len().min(64)];
    let mut out = [0u8; 12 + 64 + 16];
    if let Ok(n) = dev.encrypt_with_aad(&token, pt, PinKdf::V2, &nonce, &mut out) {
        let mut back = [0u8; 64];
        let m = dev
            .decrypt_with_aad(&token, &out[..n], PinKdf::V2, &mut back)
            .expect("round-trip authenticates");
        assert_eq!(&back[..m], pt);
    }
});
