// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests_support::*;

/// A slot record as stored: `cfg`, then `tail`.
fn record(cfg: &[u8; CONFIG_SIZE], tail: [u8; 8]) -> SlotRecord {
    let mut stored = [0u8; CONFIG_SIZE + 8];
    stored[..CONFIG_SIZE].copy_from_slice(cfg);
    stored[CONFIG_SIZE..].copy_from_slice(&tail);
    SlotRecord::from_bytes(&stored).unwrap()
}

/// The record's tail, as a press left it.
fn tail(slot: &SlotRecord) -> &[u8] {
    &slot.expose()[CONFIG_SIZE..]
}

/// A tail holding `counter` as its use counter.
fn use_counter(counter: u16) -> [u8; 8] {
    let mut tail = [0u8; 8];
    tail[..2].copy_from_slice(&counter.to_be_bytes());
    tail
}

#[test]
fn hotp_matches_rfc4226_vectors() {
    // RFC 4226 Appendix D: key = "12345678901234567890" (20 bytes ASCII).
    let key = b"12345678901234567890";
    let expect = [
        "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871",
        "520489",
    ];
    let mut out = [0u8; MAX_TICKET];
    for (c, want) in expect.iter().enumerate() {
        let n = hotp(key, c as u64, 6, &mut out);
        assert_eq!(&out[..n], want.as_bytes(), "counter {c}");
    }
}

#[test]
fn hotp_slot_uses_20_byte_key_and_bumps_imf() {
    // Program a HOTP slot the ykman way: key[..16] in the AES field,
    // key[16..20] in the UID head. The typed code must equal RFC 4226 over
    // the full 20-byte key.
    let key20 = b"12345678901234567890";
    let mut cfg = [0u8; CONFIG_SIZE];
    cfg[OFF_AES_KEY..OFF_AES_KEY + 16].copy_from_slice(&key20[..16]);
    cfg[OFF_UID..OFF_UID + 4].copy_from_slice(&key20[16..]);
    cfg[OFF_TKT_FLAGS] = TKT_OATH_HOTP | TKT_APPEND_CR;
    let mut slot = record(&cfg, [0; 8]);

    let mut out = [0u8; MAX_TICKET];
    let t = build(&mut slot, 0, 0, [0, 0], &mut out);
    assert!(t.encode);
    assert_eq!(&out[..t.len], b"755224\r"); // RFC 4226 counter 0 + CR
    // IMF advanced 0 → 1.
    assert!(t.persist);
    assert_eq!(tail(&slot), 1u64.to_be_bytes());

    // The next press, at IMF 1 → the next RFC 4226 code.
    let t = build(&mut slot, 0, 0, [0, 0], &mut out);
    assert_eq!(&out[..6], b"287082");
    assert!(t.persist);
    assert_eq!(tail(&slot), 2u64.to_be_bytes());
}

#[test]
fn hotp8_digits() {
    let key20 = b"12345678901234567890";
    let mut cfg = [0u8; CONFIG_SIZE];
    cfg[OFF_AES_KEY..OFF_AES_KEY + 16].copy_from_slice(&key20[..16]);
    cfg[OFF_UID..OFF_UID + 4].copy_from_slice(&key20[16..]);
    cfg[OFF_TKT_FLAGS] = TKT_OATH_HOTP;
    cfg[OFF_CFG_FLAGS] = CFG_OATH_HOTP8;
    let mut slot = record(&cfg, [0; 8]);
    let mut out = [0u8; MAX_TICKET];
    let t = build(&mut slot, 0, 0, [0, 0], &mut out);
    // RFC 4226 8-digit truncation of counter 0 = 84755224.
    assert_eq!(&out[..t.len], b"84755224");
}

#[test]
fn yubico_otp_is_decryptable_and_bumps_counter() {
    // A plain Yubico-OTP slot. Decrypt the modhex with the AES key and check
    // the embedded fields + the trailing CRC residual.
    let aes = [0x11u8; 16];
    let uid = [1, 2, 3, 4, 5, 6];
    let mut cfg = [0u8; CONFIG_SIZE];
    cfg[..6].copy_from_slice(b"\x01\x02\x03\x04\x05\x06"); // public id
    cfg[OFF_UID..OFF_UID + 6].copy_from_slice(&uid);
    cfg[OFF_AES_KEY..OFF_AES_KEY + 16].copy_from_slice(&aes);
    cfg[OFF_TKT_FLAGS] = TKT_APPEND_CR;
    let mut slot = record(&cfg, [0; 8]);

    let mut out = [0u8; MAX_TICKET];
    let t = build(&mut slot, 0, 100, [0xAA, 0xBB], &mut out);
    assert!(t.encode);
    assert_eq!(t.len, 44 + 1); // 44 modhex + CR
    assert_eq!(out[44], b'\r');
    assert_eq!(t.new_session, 1);
    // Counter was 0 → set to 1 and persisted.
    assert!(t.persist);
    assert_eq!(tail(&slot)[..2], 1u16.to_be_bytes());

    // Decode modhex → 22 bytes; the first 6 are the clear public id.
    let raw = demodhex(&out[..44]);
    assert_eq!(&raw[..6], &cfg[..6]);
    // Decrypt the 16-byte block and verify uid + counter + CRC residual.
    let mut block = [0u8; 16];
    block.copy_from_slice(&raw[6..22]);
    aes128_decrypt_block(&aes, &mut block);
    assert_eq!(&block[..6], &uid); // private uid
    assert_eq!(u16::from_le_bytes([block[6], block[7]]), 1); // counter
    let mut chk = [0u8; 16];
    chk.copy_from_slice(&block);
    // CRC over the first 14 bytes ‖ stored ~CRC ⇒ X.25 residual.
    assert_eq!(crc16(&chk), 0xF0B8);
}

#[test]
fn yubico_session_wrap_bumps_counter() {
    let mut cfg = [0u8; CONFIG_SIZE];
    cfg[OFF_AES_KEY..OFF_AES_KEY + 16].copy_from_slice(&[0x22; 16]);
    let mut slot = record(&cfg, use_counter(5));
    let mut out = [0u8; MAX_TICKET];
    // session 255 → wraps to 0 → counter 5 → 6.
    let t = build(&mut slot, 255, 0, [0, 0], &mut out);
    assert_eq!(t.new_session, 0);
    assert!(t.persist);
    assert_eq!(tail(&slot)[..2], 6u16.to_be_bytes());
}

#[test]
fn yubico_use_counter_stops_at_the_ceiling() {
    let mut cfg = [0u8; CONFIG_SIZE];
    cfg[OFF_AES_KEY..OFF_AES_KEY + 16].copy_from_slice(&[0x22; 16]);
    let mut slot = record(&cfg, use_counter(crate::USE_COUNTER_MAX));
    let mut out = [0u8; MAX_TICKET];
    // The wrapping press at the ceiling must store nothing: 0x8000 sets the
    // reserved high bit, and power_up_bump would then decline forever after.
    let t = build(&mut slot, 255, 0, [0, 0], &mut out);
    assert_eq!(t.new_session, 0);
    assert!(!t.persist);
    assert_eq!(tail(&slot), use_counter(crate::USE_COUNTER_MAX));
}

#[test]
fn static_password_types_scancodes_verbatim() {
    let mut cfg = [0u8; CONFIG_SIZE];
    for (i, b) in cfg[..38].iter_mut().enumerate() {
        *b = i as u8;
    }
    cfg[OFF_TKT_FLAGS] = TKT_APPEND_CR;
    cfg[OFF_CFG_FLAGS] = CFG_STATIC_TICKET;
    let mut slot = record(&cfg, [0; 8]);
    let mut out = [0u8; MAX_TICKET];
    let t = build(&mut slot, 0, 0, [0, 0], &mut out);
    assert!(!t.encode); // raw scancodes
    assert_eq!(t.len, 38 + 1);
    assert_eq!(&out[..38], &cfg[..38]);
    assert_eq!(out[38], 0x28); // Enter scancode
    assert!(!t.persist);
    assert_eq!(tail(&slot), [0; 8]);
}
