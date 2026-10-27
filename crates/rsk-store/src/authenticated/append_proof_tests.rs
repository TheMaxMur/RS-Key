// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

const KEY: [u8; 32] = [0x25; 32];

fn prefix() -> AppendProof {
    let mut state = Sha256State::new();
    state.update(b"prefix");
    AppendProof::new(state, 6, &KEY)
}

#[test]
#[expect(
    clippy::unwrap_used,
    reason = "A valid public prefix must extend before its exact digest is checked."
)]
fn append_proofs_bind_the_key_offset_and_all_appended_bytes() {
    assert!(
        prefix()
            .extend(&[0x26; 32], 6, b"prefix", &[b"new"])
            .is_err()
    );
    assert!(prefix().extend(&KEY, 7, b"prefix", &[b"new"]).is_err());
    assert!(prefix().extend(&KEY, 6, b"short", &[b"new"]).is_err());
    assert!(prefix().extend(&KEY, 6, b"damage", &[b"new"]).is_err());
    let extended = prefix().extend(&KEY, 6, b"prefix", &[b"ne", b"w"]).unwrap();
    let mut state = Sha256State::new();
    state.update(b"prefixnew");
    state.update(&9u32.to_le_bytes());
    assert_eq!(extended.end(), 9);
    assert_eq!(extended.tag(), hmac_sha256(&KEY, &state.finish()));
}

#[test]
fn append_proofs_refuse_offset_overflow() {
    let proof = AppendProof::new(Sha256State::new(), u32::MAX, &KEY);
    assert!(proof.extend(&KEY, u32::MAX, b"", &[b"x"]).is_err());
}
