// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn status(copies: [u32; 8], flags: [u32; 3]) -> SecureBootStatus {
    read_status(|row| {
        if PAGE_LOCK_ROWS.contains(&row) {
            Some(PAGE_LOCK_BL_NS_RO)
        } else if row < BOOT_FLAGS1_ROW {
            row.checked_sub(CRIT1_ROW)
                .and_then(|index| copies.get(index).copied())
        } else {
            row.checked_sub(BOOT_FLAGS1_ROW)
                .and_then(|index| flags.get(index).copied())
        }
    })
}

#[test]
fn enable_uses_three_of_eight_without_trusting_first_copy() {
    for count in 0..8 {
        let mut copies = [0; 8];
        for raw in copies.iter_mut().skip(1).take(count) {
            *raw = 1;
        }
        assert_eq!(status(copies, [1; 3]).enabled, count >= 3);
    }
}

#[test]
fn locked_requires_every_hardening_bit_in_every_copy() {
    assert!(status([0x77; 8], [0xe01; 3]).locked);
    for i in 0..8 {
        for bit in [1, 2, 4, 5, 6] {
            let mut copies = [0x77; 8];
            *copies.get_mut(i).unwrap() &= !(1 << bit);
            let st = status(copies, [0xe01; 3]);
            assert!(st.enabled);
            assert!(!st.locked);
        }
    }
}

#[test]
fn revoked_or_ambiguous_keys_cannot_establish_lock() {
    let revoked = status([0x77; 8], [0xf01; 3]);
    assert!(!revoked.enabled && !revoked.locked);
    assert_eq!(revoked.bootkey, 0xff);
    assert!(!status([0x77; 8], [0xc03; 3]).locked);
    assert!(!status([0x77; 8], [1; 3]).locked);
    assert!(!status([0x76; 8], [0xe01; 3]).locked);
    let rotated = status([0x77; 8], [0xd02; 3]);
    assert!(rotated.enabled && rotated.locked);
    assert_eq!(rotated.bootkey, 1);
}

#[test]
fn flags_use_physical_majority_and_read_failures_refuse_claims() {
    assert!(status([0x77; 8], [0, 0xe01, 0xe01]).locked);
    assert!(!status([0x77; 8], [0xe01, 0, 0]).enabled);
    for missing in (CRIT1_ROW..CRIT1_ROW + 8).chain(BOOT_FLAGS1_ROW..BOOT_FLAGS1_ROW + 3) {
        let st = read_status(|row| {
            (row != missing).then_some(if row < BOOT_FLAGS1_ROW { 0x77 } else { 0xe01 })
        });
        assert!(!st.enabled && !st.locked);
        assert_eq!(st.bootkey, 0xff);
    }
}

#[test]
fn locked_requires_complete_page_locks_but_read_error_does_not_change_enable() {
    for missing in PAGE_LOCK_ROWS {
        for lock in [
            None,
            Some(0),
            Some(0x14),
            Some(0x1414),
            Some(0x101010),
            Some(0x040404),
        ] {
            let st = read_status(|row| {
                if row == missing {
                    lock
                } else if PAGE_LOCK_ROWS.contains(&row) {
                    Some(PAGE_LOCK_BL_NS_RO)
                } else if row < BOOT_FLAGS1_ROW {
                    Some(0x77)
                } else {
                    Some(0xe01)
                }
            });
            assert!(st.enabled);
            assert!(!st.locked);
            assert_eq!(st.bootkey, 0);
        }
    }
}
