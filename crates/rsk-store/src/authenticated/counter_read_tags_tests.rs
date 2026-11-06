// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
#[expect(
    clippy::unwrap_used,
    reason = "The fixture constructs an authenticated binding before varying only its payload width."
)]
fn an_authenticated_cache_tag_cannot_make_a_different_payload_width_valid() {
    use crate::authenticated::authority::{Authority, Snapshot};
    let source = crate::authenticated::KeySource::new(
        [0x43; 32],
        |_| crate::authenticated::RootRead::Blank,
        false,
    );
    let proof = source
        .prepare_read(crate::authenticated::RootArm::PreOtp, false)
        .unwrap();
    let identity = crate::authenticated::Identity {
        partition: crate::authenticated::Partition::Counter,
        epoch: [0x4b; 16],
    };
    let key = [0x35; 32];
    let fid = rsk_fs::counter::EF_COUNTER.get();
    let entry = Entry::live(identity, &key, fid, 1, b"old").unwrap();
    let mut authority = Authority::New;
    authority
        .admit(
            &key,
            Snapshot {
                identity,
                arm: crate::authenticated::RootArm::PreOtp,
                sequence: 1,
                digest: [0x51; 32],
            },
            None,
        )
        .unwrap();
    let bound = authority
        .read_bound(identity, crate::authenticated::RootArm::PreOtp)
        .unwrap();
    let mut cache = ReadCache::new();
    cache.remember(&proof, bound, entry, b"xx").unwrap();
    assert_eq!(
        cache.verify(&proof, bound, entry, b"xx"),
        Err(Error::MemoryFatal)
    );
    cache.remember(&proof, bound, entry, b"old").unwrap();
    assert_eq!(cache.verify(&proof, bound, entry, b"old"), Ok(()));
}
