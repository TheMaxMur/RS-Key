// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::ram::RamStorage;

struct SeqRng(u64);
impl Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

// Run process_cbor with a fresh context (empty flash).
fn dispatch(data: &[u8], out: &mut [u8]) -> usize {
    let mut fs = Fs::new(RamStorage::new());
    let dev = Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    };
    let mut rng = SeqRng(1);
    let mut state = FidoState::new();
    let mut presence = AlwaysConfirm;
    let mut ctx = Ctx {
        dev,
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
        presence: &mut presence,
    };
    process_cbor(&mut ctx, data, out)
}

#[test]
fn dispatch_get_info_ok() {
    // Sized well clear of the response: `advertise-pqc` adds two ML-DSA algorithm
    // entries on top of the vendorPrototype id list, and `process_cbor` answers a
    // short buffer with a status byte alone rather than a panic.
    let mut out = [0u8; 1024];
    let n = dispatch(&[consts::CTAP_GET_INFO], &mut out);
    assert!(n > 1);
    assert_eq!(out[0], CTAP2_OK);
    // The payload is the getInfo map: 0xB6 = map(22), one less on a
    // `largeblob-ext` build (no maxSerializedLargeBlobArray).
    assert_eq!(out[1], 0xB6 - u8::from(consts::LARGE_BLOB_EXT));
}

#[test]
fn dispatch_unknown_command() {
    let mut out = [0u8; 64];
    let n = dispatch(&[0xEE], &mut out);
    assert_eq!(n, 1);
    assert_eq!(out[0], CtapError::InvalidCommand.as_u8());
}

#[test]
fn dispatch_empty_is_invalid_length() {
    let mut out = [0u8; 64];
    let n = dispatch(&[], &mut out);
    assert_eq!(n, 1);
    assert_eq!(out[0], CtapError::InvalidLength.as_u8());
}

#[test]
fn dispatch_get_assertion_routes_to_handler() {
    // getAssertion with empty params is malformed CBOR.
    let mut out = [0u8; 64];
    let n = dispatch(&[consts::CTAP_GET_ASSERTION], &mut out);
    assert_eq!(n, 1);
    assert_eq!(out[0], CtapError::InvalidCbor.as_u8());
}
