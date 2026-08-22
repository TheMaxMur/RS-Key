// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn conf_len_matches_layout() {
    assert_eq!(CONF_LEN, 4);
    assert_eq!(CORE_LEN, 3);
}

#[test]
fn default_mirrors_firmware_runtime_defaults() {
    let d = DisplayConfig::default();
    assert_eq!(d.brightness, crate::BRIGHTNESS_LEVELS);
    assert_eq!(d.sleep_secs, 60);
    assert!(!d.pin_declined);
    assert!(d.random_pin_pad);
}

#[test]
fn encode_decode_roundtrip() {
    let cfg = DisplayConfig {
        brightness: 3,
        sleep_secs: 120,
        pin_declined: true,
        random_pin_pad: false,
    };
    let mut got = DisplayConfig::default();
    got.apply_block(&cfg.encode());
    assert_eq!(got, cfg);
}

#[test]
fn encode_layout_is_brightness_then_be_sleep_then_flags() {
    let b = DisplayConfig {
        brightness: 4,
        sleep_secs: 300,
        pin_declined: true,
        random_pin_pad: false,
    }
    .encode();
    assert_eq!(b.len(), 4);
    assert_eq!(b[0], 4);
    assert_eq!(u16::from_be_bytes([b[1], b[2]]), 300);
    assert_eq!(b[3], FLAG_PIN_DECLINED | FLAG_FIXED_PIN_PAD);
}

#[test]
fn pin_declined_clear_encodes_zero_flags() {
    let b = DisplayConfig {
        brightness: 2,
        sleep_secs: 60,
        pin_declined: false,
        random_pin_pad: true,
    }
    .encode();
    assert_eq!(b[3], 0);
}

#[test]
fn off_sentinel_roundtrips() {
    let cfg = DisplayConfig {
        brightness: 5,
        sleep_secs: 0, // Off
        pin_declined: false,
        random_pin_pad: true,
    };
    let mut got = DisplayConfig::default();
    got.apply_block(&cfg.encode());
    assert_eq!(got, cfg);
}

#[test]
fn legacy_core_block_loads_fields_and_keeps_flag_default() {
    // A record written before the flags byte existed is exactly CORE_LEN: its
    // brightness + sleep still load, and pin_declined stays at its default
    // (false) — so an already-provisioned device survives the upgrade.
    let core = [3u8, 0x00, 0x1E]; // brightness 3, sleep 30 s, no flags
    let mut got = DisplayConfig::default();
    got.apply_block(&core);
    assert_eq!(got.brightness, 3);
    assert_eq!(got.sleep_secs, 30);
    assert!(!got.pin_declined);
    assert!(got.random_pin_pad);
}

#[test]
fn unknown_flag_bits_do_not_set_pin_declined() {
    // A future bit set alone must not change either known option.
    let mut got = DisplayConfig::default();
    got.apply_block(&[5, 0x00, 0x3C, 0x04]);
    assert!(!got.pin_declined);
    assert!(got.random_pin_pad);
}

#[test]
fn fixed_pin_pad_flag_is_an_opt_out() {
    let mut got = DisplayConfig::default();
    got.apply_block(&[5, 0x00, 0x3C, FLAG_FIXED_PIN_PAD]);
    assert!(!got.random_pin_pad);
}

#[test]
fn empty_block_keeps_defaults() {
    let mut got = DisplayConfig::default();
    got.apply_block(&[]);
    assert_eq!(got, DisplayConfig::default());
}

#[test]
fn short_block_below_core_len_keeps_defaults() {
    // No sub-CORE_LEN layout was ever written, so a 1- or 2-byte block is
    // corruption: leave the fields at their defaults rather than half-apply.
    for short in [&[2u8][..], &[2u8, 0u8][..]] {
        let mut got = DisplayConfig::default();
        got.apply_block(short);
        assert_eq!(got, DisplayConfig::default());
    }
}

#[test]
fn longer_future_block_reads_known_prefix() {
    // A future, longer record still loads its first CONF_LEN bytes (the >= branch).
    let cfg = DisplayConfig {
        brightness: 1,
        sleep_secs: 30,
        pin_declined: true,
        random_pin_pad: false,
    };
    let mut b = [0u8; 7];
    b[..CONF_LEN].copy_from_slice(&cfg.encode());
    let mut got = DisplayConfig::default();
    got.apply_block(&b);
    assert_eq!(got, cfg);
}

/// Deterministic property sweep: `apply_block` must never panic and must be
/// idempotent on an *arbitrary* byte slice — the persisted record is attacker-
/// or corruption-influenced flash, and `Storage::read` returns the value's *full*
/// length (which can exceed the firmware's 4-byte read buffer), so the codec is
/// the chokepoint that guarantees an out-of-range, truncated, all-0xFF, empty, or
/// over-long record can only mis-load fields, never index OOB or brick the boot.
#[test]
fn apply_block_no_panic_and_idempotent_over_random_slices() {
    // A tiny xorshift64* PRNG: deterministic, reproducible in CI, no dev-dep.
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };

    // Lengths from 0 up to well past CONF_LEN exercise: empty, sub-CORE_LEN,
    // CORE_LEN-only (legacy), full CONF_LEN, and the longer-than-known cases —
    // the last is what a host buffer trim (`n.min(buf.len())`) protects in
    // `Ui::build`; proving the codec itself is OOB-safe makes that defence
    // belt-and-braces, not the only thing standing between flash and a panic.
    let mut bytes = [0u8; 64];
    for _ in 0..50_000 {
        let len = (next() as usize) % (bytes.len() + 1);
        for b in bytes[..len].iter_mut() {
            *b = next() as u8;
        }
        let block = &bytes[..len];

        // (a) panic-freedom: applying onto a fresh default must not index OOB.
        let mut a = DisplayConfig::default();
        a.apply_block(block); // would panic here on any OOB bug

        // (b) idempotence: a second application of the *same* block is a no-op,
        // because apply_block is a pure field-by-field overlay (no accumulation).
        let mut b2 = a;
        b2.apply_block(block);
        assert_eq!(a, b2, "apply_block not idempotent for {block:02x?}");

        // Cross-check the documented prefix contract: a >= CORE_LEN block sets
        // brightness/sleep from the first 3 bytes; a shorter one leaves them at
        // the default (never half-applied); the flag only loads from a full block.
        if len >= CORE_LEN {
            assert_eq!(a.brightness, block[0]);
            assert_eq!(a.sleep_secs, u16::from_be_bytes([block[1], block[2]]));
        } else {
            assert_eq!(a.brightness, DisplayConfig::default().brightness);
            assert_eq!(a.sleep_secs, DisplayConfig::default().sleep_secs);
        }
        if len >= CONF_LEN {
            assert_eq!(a.pin_declined, block[3] & FLAG_PIN_DECLINED != 0);
            assert_eq!(a.random_pin_pad, block[3] & FLAG_FIXED_PIN_PAD == 0);
        } else {
            assert!(!a.pin_declined); // default
            assert!(a.random_pin_pad);
        }
    }
}

/// The all-0xFF block (erased / never-written flash reads as 0xFF on this medium)
/// must load cleanly, not panic: brightness 0xFF (the firmware clamps it to the
/// valid range before driving the PWM), sleep 0xFFFF, pin_declined set.
#[test]
fn all_ones_block_loads_without_panic() {
    let mut got = DisplayConfig::default();
    got.apply_block(&[0xFF; CONF_LEN]);
    assert_eq!(got.brightness, 0xFF); // raw; firmware clamps to 1..=BRIGHTNESS_LEVELS
    assert_eq!(got.sleep_secs, 0xFFFF);
    assert!(got.pin_declined);
    assert!(!got.random_pin_pad);
}
