// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// Every index [`entropy_to_indices`] returns is `< 2048`, so [`word`]/[`WORDS`]
/// indexing can never go out of bounds for any seed — and the first and last words
/// carry exactly the BIP-39 bits, which pins the big-endian order and the splice.
#[kani::proof]
fn indices_in_range() {
    let entropy: [u8; 32] = kani::any();
    // The checksum is symbolic, not SHA-256's: quantifying over every byte covers
    // whatever the hash produces, and keeps SHA-256 out of the solver cone.
    let checksum: u8 = kani::any();
    let idx = pack_indices(&entropy, checksum);
    let mut i = 0;
    while i < WORD_COUNT {
        assert!((idx[i] as usize) < WORDS.len());
        i += 1;
    }
    // Word 0 is entropy bits 0..10 and word 23 is entropy bits 253..255 followed by
    // all 8 checksum bits — the two ends of the 264-bit string, in closed form.
    assert!(idx[0] == ((entropy[0] as u16) << 3) | ((entropy[1] >> 5) as u16));
    assert!(idx[WORD_COUNT - 1] == (((entropy[31] & 0x07) as u16) << 8) | checksum as u16);
}
