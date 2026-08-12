// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the CTAP2 PIN/UV-auth protocol: ECDH with an attacker-chosen peer point
//! must reject (not panic) off-curve points; decrypt of arbitrary ciphertext must
//! never panic; and any block-multiple plaintext must survive encrypt → decrypt.

use libfuzzer_sys::fuzz_target;
use rsk_crypto::pinproto::{self, PinProto};

fuzz_target!(|data: &[u8]| {
    let shared = [0x5Au8; 64];
    for proto in [PinProto::One, PinProto::Two] {
        // 1. ECDH against an attacker-chosen peer point: Err, never panic.
        if data.len() >= 64 {
            let mut x = [0u8; 32];
            let mut y = [0u8; 32];
            x.copy_from_slice(&data[..32]);
            y.copy_from_slice(&data[32..64]);
            let scalar = [0x11u8; 32]; // in range [1, n)
            let mut out = [0u8; 64];
            let _ = pinproto::ecdh(proto, &scalar, &x, &y, &mut out);
        }

        // 2. Decrypt of arbitrary ciphertext: Err on bad length, never panic.
        if data.len() <= 1024 {
            let mut pt = [0u8; 1024];
            let _ = pinproto::decrypt(proto, &shared, data, &mut pt);
        }

        // 3. Encrypt → decrypt round-trip on a block-multiple slice.
        let blk = ((data.len() / 16) * 16).min(512);
        let iv = [0x77u8; 16];
        let mut ct = [0u8; 512 + 16];
        if let Ok(n) = pinproto::encrypt(proto, &shared, &iv, &data[..blk], &mut ct) {
            let mut back = [0u8; 512];
            let m = pinproto::decrypt(proto, &shared, &ct[..n], &mut back).expect("round-trip");
            assert_eq!(&back[..m], &data[..blk]);
        }

        // 4. Two-sided MAC oracle. `verify` is the constant-time check behind every
        //    pinUvAuthParam, so a `true`-wired one forges session tokens wholesale;
        //    discarding its verdict here would let that through. The candidate is
        //    the genuine MAC, never the fuzzer's bytes — betting a coverage-guided
        //    mutator against a `ct_eq` is the wrong side of that race.
        let mut mac = [0u8; 32];
        let n = pinproto::authenticate(proto, &shared, data, &mut mac).expect("32-byte MAC buffer");
        assert!(pinproto::verify(proto, &shared, data, &mac[..n]));
        mac[0] ^= 0xff;
        assert!(!pinproto::verify(proto, &shared, data, &mac[..n]));
    }
});
