// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_sdk::error::Error;

const KEY: [u8; 32] = [0x35; 32];
const IDENTITY: Identity = Identity {
    partition: Partition::Main,
    epoch: [0xA6; EPOCH_BYTES],
};

#[test]
fn a_valid_mac_does_not_authorize_an_unknown_transaction_layout() {
    let entry = Entry::live(IDENTITY, &KEY, 0xCE10, 7, b"owner").unwrap();
    let delta = Delta {
        kind: DeltaKind::Prepare,
        partition: Partition::Main,
        sequence: 7,
        address: 4096,
        entry,
        previous: [0xA7; 32],
    };
    let encoded = delta.encode(&KEY).unwrap();
    for offset in [0, 10, 11, 88, 95, 112, 127] {
        let mut changed = encoded;
        changed[offset] ^= 1;
        let tag = rsk_crypto::hmac_sha256(&KEY, &changed[..96]);
        changed[96..112].copy_from_slice(&tag[..TAG_BYTES]);
        assert_eq!(
            Delta::verify(&changed, &KEY),
            Err(Error::MemoryFatal),
            "offset {offset}"
        );
    }
}

#[test]
fn every_descriptor_byte_and_every_payload_byte_is_bound() {
    let payload = b"configured owner PIN and policy";
    let entry = Entry::live(IDENTITY, &KEY, 0xCE10, 7, payload).unwrap();
    assert_eq!(entry.verify(IDENTITY, &KEY, payload), Ok(()));
    assert_eq!(Entry::decode(&entry.encode().unwrap()), Ok(entry));
    for byte in 0..ENTRY_BYTES {
        let mut encoded = entry.encode().unwrap();
        encoded[byte] ^= 1;
        if let Ok(damaged) = Entry::decode(&encoded) {
            assert_eq!(
                damaged.verify(IDENTITY, &KEY, payload),
                Err(Error::MemoryFatal)
            );
        }
    }
    for byte in 0..payload.len() {
        let mut damaged = *payload;
        damaged[byte] ^= 1;
        assert_eq!(
            entry.verify(IDENTITY, &KEY, &damaged),
            Err(Error::MemoryFatal)
        );
    }
    for prefix in 0..payload.len() {
        assert_eq!(
            entry.verify(IDENTITY, &KEY, &payload[..prefix]),
            Err(Error::MemoryFatal)
        );
    }
}

#[test]
fn identity_partition_epoch_key_and_complete_width_are_bound() {
    let entry = Entry::live(IDENTITY, &KEY, 0xCE10, 7, b"policy").unwrap();
    let other_partition = Identity {
        partition: Partition::Counter,
        ..IDENTITY
    };
    let other_epoch = Identity {
        epoch: [0xA7; EPOCH_BYTES],
        ..IDENTITY
    };
    for identity in [other_partition, other_epoch] {
        assert_eq!(
            entry.verify(identity, &KEY, b"policy"),
            Err(Error::MemoryFatal)
        );
    }
    assert_eq!(
        entry.verify(IDENTITY, &[0x36; 32], b"policy"),
        Err(Error::MemoryFatal)
    );
    assert_eq!(
        entry.verify(IDENTITY, &KEY, b"policy appended"),
        Err(Error::MemoryFatal)
    );
}

#[test]
fn empty_present_and_deleted_are_distinct_authenticated_states() {
    let present = Entry::live(IDENTITY, &KEY, 0xCE10, 7, &[]).unwrap();
    let absent = Entry::deleted(IDENTITY, &KEY, 0xCE10, 7).unwrap();
    assert_eq!(present.length(), Some(0));
    assert_eq!(absent.length(), None);
    assert_ne!(present.encode().unwrap(), absent.encode().unwrap());
    assert_eq!(present.verify(IDENTITY, &KEY, &[]), Ok(()));
    assert_eq!(absent.verify(IDENTITY, &KEY, &[]), Ok(()));
    assert_eq!(
        absent.verify(IDENTITY, &KEY, b"not absent"),
        Err(Error::MemoryFatal)
    );
}

#[test]
fn all_truncated_descriptor_widths_and_unknown_partition_codes_are_refused() {
    let encoded = Entry::live(IDENTITY, &KEY, 5, 3, b"owner")
        .unwrap()
        .encode()
        .unwrap();
    for width in 0..ENTRY_BYTES {
        assert_eq!(Entry::decode(&encoded[..width]), Err(Error::MemoryFatal));
    }
    for code in 2..=u8::MAX {
        assert_eq!(Partition::decode(code), Err(Error::MemoryFatal));
        assert_eq!(RootArm::decode(code), Err(Error::MemoryFatal));
    }
}

#[test]
fn the_published_value_ceiling_is_unchanged() {
    let payload = [0x73; rsk_fs::MAX_VALUE_BYTES];
    let entry = Entry::live(IDENTITY, &KEY, 0xCE10, 7, &payload).unwrap();
    assert_eq!(entry.length(), Some(rsk_fs::MAX_VALUE_BYTES));
    assert_eq!(entry.verify(IDENTITY, &KEY, &payload), Ok(()));
    assert_eq!(Entry::decode(&entry.encode().unwrap()), Ok(entry));
    assert_eq!(
        Entry::live(IDENTITY, &KEY, 0xCE10, 7, &[0; rsk_fs::MAX_VALUE_BYTES + 1]),
        Err(Error::MemoryFatal)
    );
}

#[test]
fn a_complete_directory_binds_presence_revision_order_and_closed_world_absence() {
    let low = Entry::live(IDENTITY, &KEY, 1, 1, &[]).unwrap();
    let high = Entry::live(IDENTITY, &KEY, 9, 2, b"owner").unwrap();
    let mut directory = Directory::<2>::new();
    directory.apply(high).unwrap();
    directory.apply(low).unwrap();
    let digest = directory.digest(IDENTITY, &KEY, 2).unwrap();
    let mut snapshot = Directory::<2>::new();
    snapshot.push_snapshot(low, 2).unwrap();
    snapshot.push_snapshot(high, 2).unwrap();
    assert_eq!(snapshot.digest(IDENTITY, &KEY, 2).unwrap(), digest);
    assert_ne!(directory.digest(IDENTITY, &KEY, 3).unwrap(), digest);
    directory
        .apply(Entry::deleted(IDENTITY, &KEY, 1, 3).unwrap())
        .unwrap();
    assert_eq!(directory.find(1), None);
    assert_eq!(directory.find(9), Some(high));
    assert_ne!(directory.digest(IDENTITY, &KEY, 2).unwrap(), digest);
    assert_eq!(snapshot.push_snapshot(high, 2), Err(Error::MemoryFatal));
}

#[test]
fn obsolete_deletions_do_not_exhaust_the_live_file_budget() {
    let mut directory = Directory::<1>::new();
    for fid in 0..=u16::MAX {
        directory
            .apply(Entry::live(IDENTITY, &KEY, fid, 1, b"owner").unwrap())
            .unwrap();
        assert_eq!(directory.entries().len(), 1);
        directory
            .apply(Entry::deleted(IDENTITY, &KEY, fid, 2).unwrap())
            .unwrap();
        assert!(directory.entries().is_empty());
    }
    directory
        .apply(Entry::live(IDENTITY, &KEY, 1, 3, b"first").unwrap())
        .unwrap();
    assert_eq!(
        directory.apply(Entry::live(IDENTITY, &KEY, 2, 3, b"second").unwrap()),
        Err(Error::NoMemory)
    );
    assert!(directory.find(1).is_some());
    assert!(directory.find(2).is_none());
}

fn blank(_: &mut [u8; 32]) -> RootRead {
    RootRead::Blank
}
fn fused(out: &mut [u8; 32]) -> RootRead {
    out.fill(0x56);
    RootRead::Fused
}
fn unreadable(_: &mut [u8; 32]) -> RootRead {
    RootRead::Unreadable
}

#[test]
fn root_reads_cannot_downgrade_an_unread_fuse_to_the_public_arm() {
    let pre = KeySource::new([0x43; 32], blank, false);
    assert_eq!(pre.current_arm(), Ok(RootArm::PreOtp));
    assert!(pre.key(RootArm::PreOtp).is_ok());
    assert!(pre.key(RootArm::Otp).is_err());
    let otp = KeySource::new([0x43; 32], fused, false);
    assert_eq!(otp.current_arm(), Ok(RootArm::Otp));
    let mut old = pre.key(RootArm::PreOtp).unwrap();
    let mut current = otp.key(RootArm::Otp).unwrap();
    assert_ne!(old.expose(), current.expose());
    old.wipe();
    current.wipe();
    for latched in [false, true] {
        let source = KeySource::new([0x43; 32], unreadable, latched);
        assert_eq!(source.current_arm(), Err(Error::MemoryFatal));
        assert!(source.key(RootArm::PreOtp).is_err());
        assert!(source.key(RootArm::Otp).is_err());
    }
    let latched_blank = KeySource::new([0x43; 32], blank, true);
    assert_eq!(latched_blank.current_arm(), Err(Error::MemoryFatal));
    let latched_fused = KeySource::new([0x43; 32], fused, true);
    assert!(latched_fused.key(RootArm::PreOtp).is_err());
    assert!(latched_fused.key(RootArm::Otp).is_ok());
}

#[test]
fn checkpoint_header_has_no_unauthenticated_version_count_or_publication_fields() {
    let checkpoint = Checkpoint {
        identity: IDENTITY,
        arm: RootArm::PreOtp,
        sequence: 37,
        entries: 12,
        digest: [0xC3; 32],
    };
    let encoded = checkpoint.encode(&KEY).unwrap();
    assert_eq!(Checkpoint::verify(&encoded, &KEY), Ok(checkpoint));
    for byte in 0..CHECKPOINT_BYTES {
        let mut damaged = encoded;
        damaged[byte] ^= 1;
        assert_eq!(Checkpoint::verify(&damaged, &KEY), Err(Error::MemoryFatal));
    }
    for width in 0..CHECKPOINT_BYTES {
        assert_eq!(
            Checkpoint::verify(&encoded[..width], &KEY),
            Err(Error::MemoryFatal)
        );
    }
    let oversized = Checkpoint {
        entries: u32::try_from(MAX_MAIN_ENTRIES + 1).unwrap(),
        ..checkpoint
    };
    assert_eq!(oversized.encode(&KEY), Err(Error::MemoryFatal));
    let counter = Checkpoint {
        identity: Identity {
            partition: Partition::Counter,
            ..IDENTITY
        },
        entries: u32::try_from(MAX_COUNTER_ENTRIES + 1).unwrap(),
        ..checkpoint
    };
    assert_eq!(counter.encode(&KEY), Err(Error::MemoryFatal));
}

fn prepare(sequence: u64, previous: [u8; 32]) -> Delta {
    Delta {
        kind: DeltaKind::Prepare,
        partition: Partition::Main,
        sequence,
        address: 4096 + 4,
        entry: Entry::live(IDENTITY, &KEY, 0xCF00, sequence, b"owner value").unwrap(),
        previous,
    }
}

#[test]
fn transaction_intent_cannot_publish_or_advance_a_value_by_itself() {
    let mut state = TransactionState::new(Partition::Main, 0, [0x41; 32]);
    let delta = prepare(1, state.chain());
    let bytes = delta.encode(&KEY).unwrap();
    for byte in 0..DELTA_BYTES {
        let mut damaged = bytes;
        damaged[byte] ^= 1;
        let before = state;
        assert_eq!(state.apply(&damaged, &KEY), Err(Error::MemoryFatal));
        assert_eq!(state, before);
    }
    assert_eq!(state.apply(&bytes, &KEY), Ok(None));
    assert_eq!(state.sequence(), 0);
    assert_eq!(
        state.pending(),
        Some(Prepared {
            entry: delta.entry,
            address: delta.address
        })
    );
    let committed = Delta {
        kind: DeltaKind::Commit,
        previous: state.chain(),
        ..delta
    };
    assert_eq!(
        state.apply(&committed.encode(&KEY).unwrap(), &KEY),
        Ok(Some(delta.entry))
    );
    assert_eq!(state.sequence(), 1);
    assert_eq!(state.pending(), None);
    let before = state;
    assert_eq!(state.apply(&bytes, &KEY), Err(Error::MemoryFatal));
    assert_eq!(state, before);
}

#[test]
fn only_a_matching_intent_can_be_committed_or_aborted() {
    for kind in [DeltaKind::Commit, DeltaKind::Abort] {
        let mut state = TransactionState::new(Partition::Main, 0, [0x41; 32]);
        let prepared = prepare(1, state.chain());
        let finish = Delta { kind, ..prepared };
        assert_eq!(
            state.apply(&finish.encode(&KEY).unwrap(), &KEY),
            Err(Error::MemoryFatal)
        );
        state.apply(&prepared.encode(&KEY).unwrap(), &KEY).unwrap();
        let wrong_address = Delta {
            kind,
            previous: state.chain(),
            address: 8192 + 4,
            ..prepared
        };
        let before = state;
        assert_eq!(
            state.apply(&wrong_address.encode(&KEY).unwrap(), &KEY),
            Err(Error::MemoryFatal)
        );
        assert_eq!(state, before);
        let finish = Delta {
            kind,
            previous: state.chain(),
            ..prepared
        };
        let expected = if kind == DeltaKind::Commit {
            Some(prepared.entry)
        } else {
            None
        };
        assert_eq!(
            state.apply(&finish.encode(&KEY).unwrap(), &KEY),
            Ok(expected)
        );
        assert_eq!(state.sequence(), 1);
        assert_eq!(state.pending(), None);
    }
}

#[test]
fn transaction_chain_rejects_future_generation_foreign_partition_and_a_second_intent() {
    let mut state = TransactionState::new(Partition::Main, 0, [0x41; 32]);
    let before = state;
    assert_eq!(
        state.apply(&prepare(2, state.chain()).encode(&KEY).unwrap(), &KEY),
        Err(Error::MemoryFatal)
    );
    assert_eq!(state, before);
    let foreign = Delta {
        partition: Partition::Counter,
        entry: Entry::live(
            Identity {
                partition: Partition::Counter,
                ..IDENTITY
            },
            &KEY,
            0xC000,
            1,
            b"counter",
        )
        .unwrap(),
        ..prepare(1, state.chain())
    };
    assert_eq!(
        state.apply(&foreign.encode(&KEY).unwrap(), &KEY),
        Err(Error::MemoryFatal)
    );
    assert_eq!(state, before);
    let wrong_link = prepare(1, [0x42; 32]);
    assert_eq!(
        state.apply(&wrong_link.encode(&KEY).unwrap(), &KEY),
        Err(Error::MemoryFatal)
    );
    let first = prepare(1, state.chain());
    state.apply(&first.encode(&KEY).unwrap(), &KEY).unwrap();
    let before = state;
    let second = prepare(1, state.chain());
    assert_eq!(
        state.apply(&second.encode(&KEY).unwrap(), &KEY),
        Err(Error::MemoryFatal)
    );
    assert_eq!(state, before);
    assert_eq!(
        TransactionState::new(Partition::Main, u64::MAX, [0; 32]).next_sequence(),
        Err(Error::MemoryFatal)
    );
}
