// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn the_es256_public_wrapper_writes_a_canonical_cose_key() {
    use minicbor::Encoder;
    use minicbor::encode::write::Cursor;

    let x = [0x12; 32];
    let y = [0x34; 32];
    let mut expected = std::vec![0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 32];
    expected.extend(x);
    expected.extend([0x22, 0x58, 32]);
    expected.extend(y);
    for capacity in 0..=expected.len() {
        let mut out = std::vec![0; capacity];
        let mut enc = Encoder::new(Cursor::new(out.as_mut_slice()));
        let result = crate::cose::cose_key_es256(&mut enc, &x, &y);
        assert_eq!(result.is_ok(), capacity == expected.len());
        if result.is_ok() {
            assert_eq!(out, expected);
        }
    }
}

#[test]
fn the_clientpin_trace_reads_the_subcommand_from_the_request() {
    for subcommand in 1u8..=9 {
        assert_eq!(
            crate::clientpin::assurance::trace_subcommand(&[0xa2, 1, 2, 2, subcommand]),
            Some(u64::from(subcommand))
        );
    }
    for body in [&[][..], &[0xa1, 2][..], &[0x80][..]] {
        assert_eq!(crate::clientpin::assurance::trace_subcommand(body), None);
    }
}

#[test]
fn a_default_fido_state_has_no_carried_pin_lock() {
    let lock = FidoState::default().pin_lock();
    assert!(!lock.engaged);
    assert_eq!(lock.mismatches, 0);
}
