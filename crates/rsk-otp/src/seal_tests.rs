// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::{CONFIG_SIZE, SLOT_SIZE};

/// The runtime twin of the compile-time assertion in `seal.rs`: it walks the
/// whole plaintext domain (`CONFIG_SIZE..=SLOT_SIZE`) rather than only its
/// cheapest end, and names the length that collided. The const block is what
/// holds the shipping build; this is what says why it matters when it fires.
#[test]
fn sealed_length_never_looks_like_plaintext_exhaustive() {
    for plain in CONFIG_SIZE..=SLOT_SIZE {
        let sealed = NONCE_LEN + plain + TAG_LEN;
        assert!(
            !(CONFIG_SIZE..=SLOT_SIZE).contains(&sealed),
            "sealed len {sealed} for plaintext {plain} collides with the plaintext range \
             — migrate_seal would double-seal an already-sealed slot"
        );
    }
}
