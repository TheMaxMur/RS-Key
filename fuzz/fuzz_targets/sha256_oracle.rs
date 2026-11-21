// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use rsk_crypto::hash::Sha256State;
use sha2::{Digest, Sha256};

pub fn check(data: &[u8], digest: [u8; 32]) {
    let expected: [u8; 32] = Sha256::digest(data).into();
    assert_eq!(digest, expected);
    let stride = 1 + usize::from(data.first().copied().unwrap_or(0));
    let mut streaming = Sha256State::new();
    for part in data.chunks(stride) {
        streaming.update(part);
    }
    assert_eq!(streaming.finish(), expected);
}
