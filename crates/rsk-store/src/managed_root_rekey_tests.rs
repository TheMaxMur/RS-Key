// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

// Partition only initial cut positions; every nested recovery cut stays intact.
const REKEY_PARTS: usize = 8;

fn exercise_rekey_partition(part: usize) {
    assert!(part < REKEY_PARTS);
    let baseline = provision_legacy();
    managed(&baseline, source())
        .administer(StorageAction::ImportLegacy, [0x4B; 16])
        .unwrap();
    let saved = baseline.inner.bytes.borrow().clone();
    let otp = KeySource::new([0x43; 32], fused, false);
    baseline.arm(&[]);
    let mut ready = managed(&baseline, otp);
    assert_imported(&mut ready);
    assert!(ready.root_closed());
    let trace = baseline.events();
    for io in [Io::Program, Io::Erase] {
        let count = trace.iter().filter(|event| event.0 == io).count();
        assert!(count > 0);
        for skip in 0..count {
            if skip % REKEY_PARTS != part {
                continue;
            }
            for effect in [Effect::Refuse, Effect::Drop, Effect::KeepTail] {
                let flash = FaultFlash::new();
                *flash.inner.bytes.borrow_mut() = saved.clone();
                flash.arm(&[Rule {
                    io,
                    skip,
                    effect,
                    latched: true,
                }]);
                let _interrupted = managed(&flash, otp);
                assert!(flash.hits()[0] > 0, "rekey {io:?} {skip} {effect:?}");
                flash.clear();
                let interrupted = flash.inner.bytes.borrow().clone();
                flash.arm(&[]);
                let mut healthy = managed(&flash, otp);
                assert_imported(&mut healthy);
                let recovery = flash.events();
                for second_io in [Io::Program, Io::Erase] {
                    let second_count = recovery.iter().filter(|event| event.0 == second_io).count();
                    for second in 0..second_count {
                        *flash.inner.bytes.borrow_mut() = interrupted.clone();
                        flash.arm(&[Rule {
                            io: second_io,
                            skip: second,
                            effect: Effect::KeepTail,
                            latched: true,
                        }]);
                        let _second_cut = managed(&flash, otp);
                        assert!(
                            flash.hits()[0] > 0,
                            "rekey {io:?} {skip} {effect:?}, recovery {second_io:?} {second}"
                        );
                        flash.clear();
                        let mut reboot = managed(&flash, otp);
                        assert_imported(&mut reboot);
                        assert!(reboot.root_closed());
                        assert_imported(&mut managed(
                            &flash,
                            KeySource::new([0x43; 32], fused, true),
                        ));
                    }
                }
            }
        }
    }
    assert_eq!(
        managed(&baseline, KeySource::new([0x43; 32], unreadable, false)).state(),
        StorageState::Recovery
    );
    assert_eq!(managed(&baseline, source()).state(), StorageState::Recovery);
}

#[test]
fn root_rekey_and_repeated_recovery_keep_values_and_close_the_old_arm_part_0() {
    exercise_rekey_partition(0);
}

#[test]
fn root_rekey_and_repeated_recovery_keep_values_and_close_the_old_arm_part_1() {
    exercise_rekey_partition(1);
}

#[test]
fn root_rekey_and_repeated_recovery_keep_values_and_close_the_old_arm_part_2() {
    exercise_rekey_partition(2);
}

#[test]
fn root_rekey_and_repeated_recovery_keep_values_and_close_the_old_arm_part_3() {
    exercise_rekey_partition(3);
}

#[test]
fn root_rekey_and_repeated_recovery_keep_values_and_close_the_old_arm_part_4() {
    exercise_rekey_partition(4);
}

#[test]
fn root_rekey_and_repeated_recovery_keep_values_and_close_the_old_arm_part_5() {
    exercise_rekey_partition(5);
}

#[test]
fn root_rekey_and_repeated_recovery_keep_values_and_close_the_old_arm_part_6() {
    exercise_rekey_partition(6);
}

#[test]
fn root_rekey_and_repeated_recovery_keep_values_and_close_the_old_arm_part_7() {
    exercise_rekey_partition(7);
}
