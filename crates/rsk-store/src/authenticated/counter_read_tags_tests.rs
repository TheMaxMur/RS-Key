// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[expect(
    clippy::unwrap_used,
    reason = "The fixture constructs counter proofs for chosen authority versions."
)]
fn fixture(authority_sequence: u64) -> (ReadProof, Bound, Entry) {
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
    let mut key = source.key(crate::authenticated::RootArm::PreOtp).unwrap();
    let fid = rsk_fs::counter::EF_COUNTER.get();
    let entry = Entry::live(identity, key.expose(), fid, 1, b"old").unwrap();
    let mut authority = Authority::New;
    authority
        .admit(
            key.expose(),
            Snapshot {
                identity,
                arm: crate::authenticated::RootArm::PreOtp,
                sequence: authority_sequence,
                digest: [0x51; 32],
            },
            None,
        )
        .unwrap();
    key.wipe();
    let bound = authority
        .read_bound(identity, crate::authenticated::RootArm::PreOtp)
        .unwrap();
    (proof, bound, entry)
}

#[test]
#[expect(
    clippy::unwrap_used,
    reason = "The fixture constructs an authenticated binding before varying only its payload width."
)]
fn an_authenticated_cache_tag_cannot_make_a_different_payload_width_valid() {
    let (proof, bound, entry) = fixture(1);
    let mut cache = ReadCache::new();
    cache.remember(&proof, bound, entry, b"xx").unwrap();
    assert_eq!(
        cache.verify(&proof, bound, entry, b"xx"),
        Err(Error::MemoryFatal)
    );
    cache.remember(&proof, bound, entry, b"old").unwrap();
    assert_eq!(cache.verify(&proof, bound, entry, b"old"), Ok(()));
}

#[test]
fn clearing_counter_read_tags_forgets_mount_and_payload_proofs() {
    let (proof, bound, entry) = fixture(1);
    let mut cache = ReadCache::new();
    assert_eq!(cache.bind(&proof, bound), Ok(()));
    assert_eq!(cache.remember(&proof, bound, entry, b"old"), Ok(()));
    assert!(cache.mount(bound).is_some());
    assert!(cache.find(entry).is_some());
    cache.clear();
    assert!(cache.mount(bound).is_none());
    assert!(cache.find(entry).is_none());
}

#[test]
fn a_verified_counter_value_rebinds_after_an_authority_advance() {
    let (proof, bound, entry) = fixture(1);
    let (_, next, _) = fixture(2);
    for (value, expected) in [
        (b"bad".as_slice(), Err(Error::MemoryFatal)),
        (b"old".as_slice(), Ok(())),
    ] {
        let mut cache = ReadCache::new();
        assert_eq!(cache.bind(&proof, bound), Ok(()));
        assert_eq!(cache.remember(&proof, bound, entry, b"old"), Ok(()));
        assert_eq!(cache.bind(&proof, next), Ok(()));
        assert_eq!(cache.verify(&proof, next, entry, value), expected);
        if expected.is_ok() {
            assert!(cache.find(entry).is_some_and(|tag| tag.binds(next)));
            assert!(cache.find(entry).is_some_and(|tag| !tag.binds(bound)));
        } else {
            assert!(!cache.find(entry).is_some_and(|tag| tag.binds(next)));
        }
    }
}
