// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn row_is_page58_lock1() {
    // PAGE_N_LOCK1 = 0xF80 + 2*N + 1.
    assert_eq!(PAGE58_LOCK1_ROW, 0xF80 + 58 * 2 + 1);
}

#[test]
fn value_keeps_secure_rw_blocks_bl_and_ns() {
    let byte = PAGE58_LOCK_VALUE & 0xFF;
    assert_eq!(byte & 0b11, 0, "LOCK_S must be 0 = secure read-write");
    assert_eq!((byte >> 2) & 0b11, 3, "LOCK_NS must be 3 = inaccessible");
    assert_eq!((byte >> 4) & 0b11, 3, "LOCK_BL must be 3 = inaccessible");
    // Majority-vote: the same byte in all three copies (R2 | R1 | base).
    assert_eq!(PAGE58_LOCK_VALUE, byte | (byte << 8) | (byte << 16));
}

#[test]
fn blank_row_writes() {
    assert_eq!(lock_decision(0), LockDecision::Write);
}

#[test]
fn our_value_is_idempotent() {
    assert_eq!(
        lock_decision(PAGE58_LATCH_VALUE),
        LockDecision::AlreadyLocked
    );
}

#[test]
fn an_older_builds_lock_takes_the_latch() {
    assert_eq!(lock_decision(PAGE58_LOCK_VALUE), LockDecision::Latch);
    // A burn only sets bits, so the latch is the old lock plus bits, never minus.
    assert_eq!(PAGE58_LATCH_VALUE & PAGE58_LOCK_VALUE, PAGE58_LOCK_VALUE);
}

#[test]
fn the_latch_keeps_the_keys_readable_to_secure_code() {
    let byte = PAGE58_LATCH_VALUE & 0xFF;
    assert_eq!(byte & 0b11, 1, "LOCK_S must be 1 = secure read-only");
    assert_eq!(
        byte & !0b11,
        PAGE58_LOCK_VALUE & 0xFF,
        "NS and BL as the lock"
    );
    assert_eq!(PAGE58_LATCH_VALUE, byte | (byte << 8) | (byte << 16));
}

#[test]
fn the_arms_close_on_the_latch_alone_by_majority() {
    assert!(arms_closed(PAGE58_LATCH_VALUE));
    // One copy short of its bit still reads latched; two do not.
    assert!(arms_closed(0x3D_3D_3C));
    assert!(!arms_closed(0x3D_3C_3C));
    for raw in [0, PAGE58_LOCK_VALUE, 0x14_14_14, 0x3F_3F_3F] {
        assert!(!arms_closed(raw), "{raw:#08x} closed the arms");
    }
}

/// Every row the patterns below can make, judged copy by copy: all blank writes, all
/// latch is the latch, a bit outside the latch in any copy is foreign, and the rest is
/// a subset (an older build's lock, a burn a power cut tore), which a burn completes.
#[test]
fn the_lock_decision_over_every_byte_pattern() {
    let latch = PAGE58_LATCH_VALUE & 0xFF;
    // The latch's own bits, subsets of it, the latch, and each bit outside it.
    let bytes: [u32; 16] = [
        0x00, 0x01, 0x04, 0x08, 0x10, 0x20, 0x14, 0x39, 0x3C, 0x3D, 0x02, 0x40, 0x80, 0x3F, 0x7D,
        0xFF,
    ];
    for a in bytes {
        for b in bytes {
            for c in bytes {
                let raw = a | (b << 8) | (c << 16);
                let copies = [a, b, c];
                let want = if copies.iter().any(|&x| x & !latch != 0) {
                    LockDecision::Unexpected
                } else if copies == [latch; 3] {
                    LockDecision::AlreadyLocked
                } else if copies == [0; 3] {
                    LockDecision::Write
                } else {
                    LockDecision::Latch
                };
                let got = lock_decision(raw);
                assert_eq!(got, want, "{raw:#08x}");
                if got == LockDecision::Latch {
                    assert_eq!(raw | PAGE58_LATCH_VALUE, PAGE58_LATCH_VALUE, "{raw:#08x}");
                }
            }
        }
    }
    // Bits above the row's 24 belong to no copy, and no burn of ours explains them.
    for raw in [
        1 << 24,
        PAGE58_LATCH_VALUE | 1 << 31,
        PAGE58_LOCK_VALUE | 1 << 24,
    ] {
        assert_eq!(lock_decision(raw), LockDecision::Unexpected, "{raw:#010x}");
    }
}

#[test]
fn a_key_is_fused_blank_or_unreadable_by_its_rows() {
    assert_eq!(key_rows([Some(0); 16]), KeyRows::Blank);
    // Only the 24 data bits count; the top byte of a raw word is not a row's.
    assert_eq!(key_rows([Some(0xFF00_0000); 16]), KeyRows::Blank);
    let mut one = [Some(0); 16];
    one[15] = Some(0x01);
    assert_eq!(key_rows(one), KeyRows::Fused);
    // A refused row is not a blank one, whatever the others read: a page closed to
    // secure code must not pass for a board never provisioned.
    for bad in 0..16 {
        let mut rows = [Some(0x00AB_CDEF); 16];
        rows[bad] = None;
        assert_eq!(key_rows(rows), KeyRows::Unreadable, "row {bad}");
        let mut rows = [Some(0); 16];
        rows[bad] = None;
        assert_eq!(key_rows(rows), KeyRows::Unreadable, "row {bad}");
    }
}

#[test]
fn an_unreadable_key_reads_as_neither_verdict() {
    // `lock_page58` burns only over `0`, and the host tool names this value apart
    // from the unchecked one.
    assert_ne!(PRE_OTP_KEY_UNREADABLE, 0);
    assert_ne!(PRE_OTP_KEY_UNREADABLE, PRE_OTP_UNCHECKED);
    let passes = PRE_OTP_FIDO | PRE_OTP_DEVICE_KEY | PRE_OTP_PIV | PRE_OTP_OATH | PRE_OTP_OTP;
    assert_ne!(
        PRE_OTP_KEY_UNREADABLE & !passes,
        0,
        "reads as a set of passes"
    );
}
