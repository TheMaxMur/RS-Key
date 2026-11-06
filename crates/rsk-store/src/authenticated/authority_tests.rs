// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::super::Partition;
use super::*;

const KEY: [u8; 32] = [0x35; 32];
const NEW_KEY: [u8; 32] = [0x47; 32];

#[test]
fn payload_tag_association_covers_the_whole_stable_binding() {
    use super::super::read_tags::ReadTags;
    let bound = stable().read_bound(BASE.identity, BASE.arm).unwrap();
    let entry = Entry::live(BASE.identity, &KEY, 0xB000, 10, b"owner").unwrap();
    let mut cache = ReadTags::new();
    cache.insert(bound, entry, [0x75; 32]);
    assert_eq!(cache.find(bound, entry), Some([0x75; 32]));
    for index in 0..32 {
        let mut changed = bound;
        *changed.tag.get_mut(index).unwrap() ^= 1;
        assert!(cache.find(changed, entry).is_none());
        let mut changed = bound;
        *changed.snapshot.digest.get_mut(index).unwrap() ^= 1;
        assert!(cache.find(changed, entry).is_none());
    }
    for snapshot in [
        Snapshot {
            sequence: BASE.sequence + 1,
            ..BASE
        },
        Snapshot {
            arm: RootArm::Otp,
            ..BASE
        },
        Snapshot {
            identity: Identity {
                epoch: [0x4C; 16],
                ..BASE.identity
            },
            ..BASE
        },
        Snapshot {
            identity: Identity {
                partition: Partition::Counter,
                ..BASE.identity
            },
            ..BASE
        },
    ] {
        assert!(
            cache
                .find(Bound::new(&KEY, snapshot).unwrap(), entry)
                .is_none()
        );
    }
    for changed in [
        Entry::live(BASE.identity, &KEY, 0xB001, 10, b"owner").unwrap(),
        Entry::live(BASE.identity, &KEY, 0xB000, 11, b"owner").unwrap(),
        Entry::live(BASE.identity, &KEY, 0xB000, 10, b"owne").unwrap(),
        Entry::live(BASE.identity, &KEY, 0xB000, 10, b"forge").unwrap(),
    ] {
        assert!(cache.find(bound, changed).is_none());
    }
}
const BASE: Snapshot = Snapshot {
    identity: Identity {
        partition: Partition::Main,
        epoch: [0x4b; 16],
    },
    arm: RootArm::PreOtp,
    sequence: 10,
    digest: [0x51; 32],
};
const TARGET: Snapshot = Snapshot {
    sequence: 11,
    digest: [0x62; 32],
    ..BASE
};

fn stable() -> Authority {
    let mut authority = Authority::New;
    assert!(!authority.established());
    authority.admit(&KEY, BASE, None).unwrap();
    assert!(authority.established());
    authority
}

fn prepared() -> Prepared {
    Prepared {
        entry: Entry::live(BASE.identity, &KEY, 0xb000, 11, b"new").unwrap(),
        address: 1024,
    }
}

fn pending() -> Pending {
    Pending {
        prepared: prepared(),
        digest: TARGET.digest,
    }
}

#[test]
fn stable_authority_binds_root_context_and_exact_version_even_for_absence() {
    let a = stable();
    assert!(a.verify_read(&KEY, BASE.identity, BASE.arm).is_ok());
    for key in [NEW_KEY, [0; 32]] {
        assert!(a.verify_read(&key, BASE.identity, BASE.arm).is_err());
    }
    let changed_epoch = Identity {
        epoch: [0x4c; 16],
        ..BASE.identity
    };
    assert!(a.verify_read(&KEY, changed_epoch, BASE.arm).is_err());
    assert!(a.verify_read(&KEY, BASE.identity, RootArm::Otp).is_err());
    for sequence in 8..=12 {
        for digest in [BASE.digest, TARGET.digest, [0; 32]] {
            let mut trial = a;
            let result = trial.admit(
                &KEY,
                Snapshot {
                    sequence,
                    digest,
                    ..BASE
                },
                None,
            );
            assert_eq!(
                result.is_ok(),
                sequence == BASE.sequence && digest == BASE.digest
            );
        }
    }
    assert!(stable().admit(&KEY, BASE, Some(pending())).is_err());
}

#[test]
fn preparation_requires_the_exact_reserved_entry_and_address() {
    let mut a = stable();
    a.stage_write(&KEY, prepared().entry, TARGET.digest)
        .unwrap();
    assert!(a.verify_read(&KEY, BASE.identity, BASE.arm).is_err());
    assert!(a.admit(&KEY, BASE, None).is_ok());
    assert!(a.admit(&KEY, BASE, Some(pending())).is_err());
    assert!(a.observe_prepare().is_err());
    let other = Prepared {
        entry: Entry::deleted(BASE.identity, &KEY, 0xb000, 11).unwrap(),
        ..prepared()
    };
    assert!(a.locate(other).is_err());
    a.locate(prepared()).unwrap();
    let changed = Pending {
        prepared: Prepared {
            address: 2048,
            ..prepared()
        },
        ..pending()
    };
    assert!(a.admit(&KEY, BASE, Some(changed)).is_err());
    assert!(
        a.admit(
            &KEY,
            BASE,
            Some(Pending {
                digest: [0; 32],
                ..pending()
            })
        )
        .is_err()
    );
    a.admit(&KEY, BASE, Some(pending())).unwrap();
    assert!(a.admit(&KEY, BASE, None).is_err());
    assert!(a.finish(&KEY, BASE).is_err());
    assert!(a.verify_read(&KEY, BASE.identity, BASE.arm).is_err());
}

#[test]
fn commit_and_abort_close_the_old_floor_before_later_io_can_fail() {
    for outcome in [
        TARGET,
        Snapshot {
            digest: BASE.digest,
            ..TARGET
        },
    ] {
        let mut a = stable();
        a.stage_write(&KEY, prepared().entry, TARGET.digest)
            .unwrap();
        a.locate(prepared()).unwrap();
        a.observe_prepare().unwrap();
        assert!(a.check_snapshot(&KEY, outcome).is_ok());
        assert!(a.verify_read(&KEY, BASE.identity, BASE.arm).is_err());
        a.admit(&KEY, outcome, None).unwrap();
        assert!(a.admit(&KEY, BASE, None).is_err());
        assert!(a.admit(&KEY, BASE, Some(pending())).is_err());
        a.finish(&KEY, outcome).unwrap();
        assert!(a.verify_read(&KEY, BASE.identity, BASE.arm).is_ok());
        assert!(
            a.admit(
                &KEY,
                Snapshot {
                    sequence: 12,
                    ..outcome
                },
                None
            )
            .is_err()
        );
    }
}

#[test]
fn a_space_checkpoint_preserves_the_staged_write_intent() {
    let mut a = stable();
    a.stage_write(&KEY, prepared().entry, TARGET.digest)
        .unwrap();
    a.check_snapshot(&KEY, BASE).unwrap();
    a.admit(&KEY, BASE, None).unwrap();
    assert!(a.verify_read(&KEY, BASE.identity, BASE.arm).is_err());
    a.locate(prepared()).unwrap();
    a.observe_prepare().unwrap();
    assert!(a.check_snapshot(&KEY, BASE).is_err());
    a.admit(&KEY, TARGET, None).unwrap();
}

#[test]
fn snapshots_and_rekey_have_only_the_exact_old_and_new_states() {
    for (key, target) in [
        (&KEY, TARGET),
        (
            &NEW_KEY,
            Snapshot {
                arm: RootArm::Otp,
                ..TARGET
            },
        ),
    ] {
        let mut a = stable();
        a.stage_replace(&KEY, key, target).unwrap();
        a.admit(&KEY, BASE, None).unwrap();
        assert!(a.verify_read(&KEY, BASE.identity, BASE.arm).is_err());
        assert!(
            a.admit(
                &KEY,
                Snapshot {
                    digest: [0; 32],
                    ..BASE
                },
                None
            )
            .is_err()
        );
        assert!(a.admit(key, target, Some(pending())).is_err());
        a.check_snapshot(key, target).unwrap();
        a.admit(key, target, None).unwrap();
        assert!(a.admit(&KEY, BASE, None).is_err());
        a.finish(key, target).unwrap();
        assert!(a.verify_read(key, target.identity, target.arm).is_ok());
        if *key != KEY {
            assert!(a.verify_read(&KEY, target.identity, target.arm).is_err());
        }
    }
}

#[test]
fn root_replacement_cannot_downgrade_or_change_a_key_without_migration() {
    for (old_arm, new_arm, key, allowed) in [
        (RootArm::PreOtp, RootArm::PreOtp, KEY, true),
        (RootArm::PreOtp, RootArm::PreOtp, NEW_KEY, false),
        (RootArm::PreOtp, RootArm::Otp, KEY, true),
        (RootArm::PreOtp, RootArm::Otp, NEW_KEY, true),
        (RootArm::Otp, RootArm::Otp, KEY, true),
        (RootArm::Otp, RootArm::Otp, NEW_KEY, false),
        (RootArm::Otp, RootArm::PreOtp, KEY, false),
        (RootArm::Otp, RootArm::PreOtp, NEW_KEY, false),
    ] {
        let base = Snapshot {
            arm: old_arm,
            ..BASE
        };
        let target = Snapshot {
            arm: new_arm,
            ..TARGET
        };
        let mut authority = Authority::New;
        authority.admit(&KEY, base, None).unwrap();
        assert_eq!(
            authority.stage_replace(&KEY, &key, target),
            if allowed {
                Ok(())
            } else {
                Err(Error::MemoryFatal)
            }
        );
        if allowed {
            assert!(authority.verify_read(&KEY, base.identity, old_arm).is_err());
            authority.admit(&key, target, None).unwrap();
            authority.finish(&key, target).unwrap();
            authority
                .verify_read(&key, target.identity, new_arm)
                .unwrap();
            if key != KEY {
                assert!(
                    authority
                        .verify_read(&KEY, target.identity, new_arm)
                        .is_err()
                );
            }
        } else {
            authority.verify_read(&KEY, base.identity, old_arm).unwrap();
            authority.finish(&KEY, base).unwrap();
            assert!(authority.admit(&key, target, None).is_err());
        }
    }
}

#[test]
fn bootstrap_refuses_a_pending_entry_outside_the_next_generation() {
    for generation in [BASE.sequence - 1, BASE.sequence, TARGET.sequence + 1] {
        let pending = Pending {
            prepared: Prepared {
                entry: Entry::live(BASE.identity, &KEY, 0xB000, generation, b"new").unwrap(),
                ..prepared()
            },
            ..pending()
        };
        let mut authority = Authority::New;
        assert_eq!(
            authority.admit(&KEY, BASE, Some(pending)),
            Err(Error::MemoryFatal)
        );
        assert!(!authority.established());
        authority.admit(&KEY, BASE, None).unwrap();
        authority
            .verify_read(&KEY, BASE.identity, BASE.arm)
            .unwrap();
    }
}

#[test]
fn bootstrap_pending_records_establish_a_floor_before_recovery_writes() {
    let mut a = Authority::New;
    a.admit(&KEY, BASE, Some(pending())).unwrap();
    assert!(a.established());
    assert!(a.admit(&KEY, BASE, None).is_err());
    assert!(
        a.admit(
            &KEY,
            Snapshot {
                sequence: 9,
                ..BASE
            },
            None
        )
        .is_err()
    );
    a.admit(&KEY, TARGET, None).unwrap();
    assert!(a.admit(&KEY, BASE, None).is_err());
}

#[test]
fn invalid_intents_leave_the_existing_floor_intact() {
    let mut a = stable();
    assert!(
        a.stage_write(&NEW_KEY, prepared().entry, TARGET.digest)
            .is_err()
    );
    let wrong_generation = Entry::live(BASE.identity, &KEY, 0xb000, 12, b"new").unwrap();
    assert!(
        a.stage_write(&KEY, wrong_generation, TARGET.digest)
            .is_err()
    );
    for target in [
        Snapshot {
            sequence: 12,
            ..TARGET
        },
        Snapshot {
            identity: Identity {
                epoch: [0; 16],
                ..BASE.identity
            },
            ..TARGET
        },
    ] {
        assert!(a.stage_replace(&KEY, &KEY, target).is_err());
    }
    assert!(a.verify_read(&KEY, BASE.identity, BASE.arm).is_ok());
    let mut maximum = Authority::New;
    maximum
        .admit(
            &KEY,
            Snapshot {
                sequence: u64::MAX,
                ..BASE
            },
            None,
        )
        .unwrap();
    assert!(
        maximum
            .stage_write(&KEY, prepared().entry, TARGET.digest)
            .is_err()
    );
}

#[test]
fn intermediate_base_does_not_finish_a_staged_transition() {
    for located in [false, true] {
        let mut a = stable();
        a.stage_write(&KEY, prepared().entry, TARGET.digest)
            .unwrap();
        if located {
            a.locate(prepared()).unwrap();
        }
        assert!(a.finish(&KEY, BASE).is_err());
        assert!(a.verify_read(&KEY, BASE.identity, BASE.arm).is_err());
    }
    let mut a = stable();
    a.stage_replace(
        &KEY,
        &NEW_KEY,
        Snapshot {
            arm: RootArm::Otp,
            ..TARGET
        },
    )
    .unwrap();
    assert!(a.finish(&KEY, BASE).is_err());
    assert!(a.verify_read(&KEY, BASE.identity, BASE.arm).is_err());
}

#[test]
fn same_arm_replacement_cannot_change_the_root_key() {
    let mut a = stable();
    assert!(a.stage_replace(&KEY, &NEW_KEY, TARGET).is_err());
    assert!(a.verify_read(&KEY, BASE.identity, BASE.arm).is_ok());
}

#[test]
fn only_an_exact_unpublished_base_can_cancel_an_intent() {
    for phase in 0..4 {
        let mut a = stable();
        if phase < 3 {
            a.stage_write(&KEY, prepared().entry, TARGET.digest)
                .unwrap();
            if phase > 0 {
                a.locate(prepared()).unwrap();
            }
            if phase > 1 {
                a.observe_prepare().unwrap();
            }
        } else {
            a.stage_replace(&KEY, &KEY, TARGET).unwrap();
        }
        assert!(a.cancel_unpublished(&NEW_KEY, BASE).is_err());
        assert!(a.cancel_unpublished(&KEY, TARGET).is_err());
        assert_eq!(a.cancel_unpublished(&KEY, BASE).is_ok(), phase != 2);
        assert_eq!(
            a.verify_read(&KEY, BASE.identity, BASE.arm).is_ok(),
            phase != 2
        );
    }
    assert!(Authority::New.cancel_unpublished(&KEY, BASE).is_err());
}

#[test]
fn staged_write_admits_only_its_exact_phase_and_outcome() {
    let abort = Snapshot {
        digest: BASE.digest,
        ..TARGET
    };
    let snapshots = [
        BASE,
        TARGET,
        abort,
        Snapshot {
            sequence: 9,
            ..BASE
        },
        Snapshot {
            sequence: 12,
            ..TARGET
        },
        Snapshot {
            digest: [0; 32],
            ..TARGET
        },
        Snapshot {
            arm: RootArm::Otp,
            ..TARGET
        },
        Snapshot {
            identity: Identity {
                epoch: [0; 16],
                ..BASE.identity
            },
            ..TARGET
        },
        Snapshot {
            identity: Identity {
                partition: Partition::Counter,
                ..BASE.identity
            },
            ..TARGET
        },
    ];
    let pending_states = [
        None,
        Some(pending()),
        Some(Pending {
            prepared: Prepared {
                address: 2048,
                ..prepared()
            },
            ..pending()
        }),
        Some(Pending {
            digest: [0; 32],
            ..pending()
        }),
    ];
    for phase in 0..3 {
        let mut authority = stable();
        authority
            .stage_write(&KEY, prepared().entry, TARGET.digest)
            .unwrap();
        if phase > 0 {
            authority.locate(prepared()).unwrap();
        }
        if phase > 1 {
            authority.observe_prepare().unwrap();
        }
        for snapshot in snapshots {
            for (pending_index, pending_state) in pending_states.into_iter().enumerate() {
                let expected = if snapshot == BASE {
                    (phase < 2 && pending_state.is_none()) || (phase > 0 && pending_index == 1)
                } else {
                    phase == 2 && pending_state.is_none() && [TARGET, abort].contains(&snapshot)
                };
                let mut trial = authority;
                assert_eq!(
                    trial.admit(&KEY, snapshot, pending_state).is_ok(),
                    expected,
                    "phase={phase}, snapshot={snapshot:?}, pending={pending_index}"
                );
            }
        }
    }
}
