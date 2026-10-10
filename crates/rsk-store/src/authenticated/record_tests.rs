// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
#[expect(
    clippy::unwrap_used,
    reason = "Valid fixtures precede the deliberately signed contradictions."
)]
fn a_valid_tag_cannot_authorize_a_payload_length_or_deletion_contradiction() {
    let identity = Identity {
        partition: Partition::Main,
        epoch: [0x4B; EPOCH_BYTES],
    };
    let key = [0x35; 32];
    let data = b"owner";
    let mut live = Entry::live(identity, &key, 0xB000, 1, data).unwrap();
    live.length += 1;
    live.tag = live.authenticate(identity, &key, data).unwrap();
    assert_eq!(live.verify(identity, &key, data), Err(Error::MemoryFatal));
    let mut deleted = Entry::deleted(identity, &key, 0xB000, 1).unwrap();
    deleted.tag = deleted.authenticate(identity, &key, data).unwrap();
    assert_eq!(
        deleted.verify(identity, &key, data),
        Err(Error::MemoryFatal)
    );
}
