// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use sequential_storage::cache::{Cache, Uncached};

std::thread_local! {
    static READ_MODE: core::cell::Cell<super::super::RootRead> = const {
        core::cell::Cell::new(super::super::RootRead::Fused)
    };
    static ROOT_READS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

fn root_read(out: &mut [u8; 32]) -> super::super::RootRead {
    ROOT_READS.with(|count| count.set(count.get() + 1));
    out.fill(0x56);
    READ_MODE.with(core::cell::Cell::get)
}

#[expect(
    clippy::unwrap_used,
    reason = "The fixture admits blank media before injecting OTP read failures."
)]
#[test]
fn a_root_read_error_clears_payload_tags_and_every_hit_reads_otp_again() {
    use super::super::authority::READ_MAC_PROOFS;
    for failure in [
        super::super::RootRead::Unreadable,
        super::super::RootRead::Blank,
    ] {
        READ_MODE.with(|mode| mode.set(super::super::RootRead::Fused));
        let flash = crate::tests::flash_for_authenticated_tests();
        let mut store = Authenticated::new_arms(
            flash,
            0..32768,
            32768..32768 + AUTHORITY_BYTES,
            Cache::<Uncached, Uncached, Uncached, u16>::new_uncached(),
            KeySource::new([0x43; 32], root_read, false),
            [0x4B; 16],
            RootArm::Otp,
            RootArm::Otp,
            None,
        )
        .unwrap();
        store.initialize_blank().unwrap();
        store.write(0xB000, b"owner").unwrap();
        for _ in 0..2 {
            assert_eq!(store.read(0xB000, &mut []), Some(5));
        }
        ROOT_READS.with(|count| count.set(0));
        READ_MAC_PROOFS.with(|count| count.set(0));
        assert_eq!(store.read(0xB000, &mut []), Some(5));
        assert_eq!(ROOT_READS.with(core::cell::Cell::get), 1);
        assert_eq!(READ_MAC_PROOFS.with(core::cell::Cell::get), 0);
        READ_MODE.with(|mode| mode.set(failure));
        assert_eq!(store.read(0xB000, &mut []), None);
        assert!(store.last_error());
        assert!(store.main.has_authority());
        READ_MODE.with(|mode| mode.set(super::super::RootRead::Fused));
        assert_eq!(store.read(0xB000, &mut []), Some(5));
        assert_eq!(store.read(0xB000, &mut []), Some(5));
        assert_eq!(READ_MAC_PROOFS.with(core::cell::Cell::get), 1);
        assert_eq!(store.read(0xB000, &mut []), Some(5));
        assert_eq!(READ_MAC_PROOFS.with(core::cell::Cell::get), 1);
        assert_eq!(ROOT_READS.with(core::cell::Cell::get), 5);
    }
}

#[expect(
    clippy::unwrap_used,
    reason = "The fixture changes only the independent partition arm after seeding a valid read."
)]
#[test]
fn a_changed_partition_arm_cannot_reuse_a_warm_main_read() {
    use super::super::authority::READ_MAC_PROOFS;
    READ_MODE.with(|mode| mode.set(super::super::RootRead::Fused));
    let mut store = Authenticated::new_arms(
        crate::tests::flash_for_authenticated_tests(),
        0..32768,
        32768..32768 + AUTHORITY_BYTES,
        Cache::<Uncached, Uncached, Uncached, u16>::new_uncached(),
        KeySource::new([0x43; 32], root_read, false),
        [0x4B; 16],
        RootArm::Otp,
        RootArm::Otp,
        None,
    )
    .unwrap();
    store.initialize_blank().unwrap();
    store.write(0xB000, b"owner").unwrap();
    for _ in 0..3 {
        assert_eq!(store.read(0xB000, &mut []), Some(5));
    }
    store.main_arm = RootArm::PreOtp;
    let mut out = [0xA5; 5];
    assert_eq!(store.read(0xB000, &mut out), None);
    assert_eq!(out, [0xA5; 5]);
    assert!(store.last_error());
    assert!(store.main.has_authority());
    store.main_arm = RootArm::Otp;
    READ_MAC_PROOFS.with(|count| count.set(0));
    for _ in 0..3 {
        assert_eq!(store.read(0xB000, &mut out), Some(5));
        assert_eq!(&out, b"owner");
    }
    assert_eq!(READ_MAC_PROOFS.with(core::cell::Cell::get), 1);
}

#[expect(
    clippy::unwrap_used,
    reason = "All four independent persisted root-arm combinations use an admitted layout."
)]
#[test]
fn root_closure_requires_both_partition_arms() {
    let flash = crate::tests::flash_for_authenticated_tests();
    let main = 0..32768;
    let counter = main.end..main.end + AUTHORITY_BYTES;
    for (main_arm, counter_arm, closed) in [
        (RootArm::PreOtp, RootArm::PreOtp, false),
        (RootArm::PreOtp, RootArm::Otp, false),
        (RootArm::Otp, RootArm::PreOtp, false),
        (RootArm::Otp, RootArm::Otp, true),
    ] {
        let store = Authenticated::new_arms(
            flash.clone(),
            main.clone(),
            counter.clone(),
            Cache::<Uncached, Uncached, Uncached, u16>::new_uncached(),
            KeySource::new([0x43; 32], |_| super::super::RootRead::Blank, false),
            [0x4B; 16],
            main_arm,
            counter_arm,
            None,
        )
        .unwrap();
        assert_eq!(store.root_closed(), closed);
    }
}
