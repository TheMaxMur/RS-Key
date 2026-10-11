// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use sequential_storage::cache::{Cache, Uncached};

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
        )
        .unwrap();
        assert_eq!(store.root_closed(), closed);
    }
}
