// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn spending_freshness_at_a_key_reference_does_not_spend_it_at_9b() {
    struct Fill;
    impl Rng for Fill {
        fn fill(&mut self, out: &mut [u8]) {
            out.fill(1);
        }
    }
    let dev = Device {
        serial_hash: &[0x22; 32],
        serial_id: &[1; 8],
        otp_key: None,
        latched: false,
    };
    for key_ref in [SLOT_CARDMGM, SLOT_SIGNATURE] {
        let mut sess = Session {
            pin_fresh: true,
            ..Session::default()
        };
        let mut fs = Fs::new(rsk_fs::storage::ram::RamStorage::new());
        let mut presence = crate::AlwaysConfirm;
        let mut context = GenAuth {
            sess: &mut sess,
            dev: &dev,
            fs: &mut fs,
            rng: &mut Fill,
            presence: &mut presence,
            algo: ALGO_ECCP256,
            slot_algo: ALGO_ECCP256,
            key_ref,
            pin_policy: PINPOLICY_ALWAYS,
            touch_policy: TOUCHPOLICY_NEVER,
            chal_len: 16,
        };
        context.spend_pin();
        assert_eq!(sess.pin_fresh, key_ref == SLOT_CARDMGM);
    }
}
