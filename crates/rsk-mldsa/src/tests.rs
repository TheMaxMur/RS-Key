// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn a_zeroed_key_refuses_to_sign_until_expanded() {
    let mut key = MlDsa44::zeroed();
    let mut sig = [0u8; MLDSA44_SIG_LEN];
    assert_eq!(key.sign(b"m", &[0; 32], &mut sig), Err(Error::NotExpanded));
    key.expand(&[7; SEED_LEN]);
    assert_eq!(key.sign(b"m", &[0; 32], &mut sig), Ok(MLDSA44_SIG_LEN));
}
