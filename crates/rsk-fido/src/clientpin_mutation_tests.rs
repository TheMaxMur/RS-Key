// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn a_new_local_pin_clears_force_change_without_dropping_multiple_rp_hashes() {
    let (mut fs, _) = setup();
    let mut policy = vec![
        MIN_PIN_LENGTH,
        crate::pinpolicy::FORCE_CHANGE | crate::pinpolicy::COMPLEXITY,
    ];
    policy.extend_from_slice(&[0x22; 32]);
    policy.extend_from_slice(&[0x33; 32]);
    fs.put(EF_MINPINLEN, &policy).unwrap();
    store_local_pin(&dev(), &mut fs, PIN).unwrap();
    policy[1] = crate::pinpolicy::COMPLEXITY;
    let mut back = [0; 66];
    assert_eq!(fs.read(EF_MINPINLEN, &mut back), Some(policy.len()));
    assert_eq!(back.as_slice(), policy);
}

#[test]
fn a_matching_current_verifier_keeps_the_completed_scrub_when_roots_alias() {
    let mut root = [0; 32];
    root[..6].copy_from_slice(b"NO-OTP");
    let device = Device {
        serial_hash: &root,
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: Some(&root),
        latched: false,
    };
    assert_eq!(
        device.derive_kbase().expose(),
        device.without_otp().derive_kbase().expose()
    );
    for device_pin in [false, true] {
        let mut fs = Fs::new(RamStorage::new());
        let mut rng = SeqRng(1);
        ensure_seed(&device, &mut fs, &mut rng).unwrap();
        if device_pin {
            store_device_pin(&device, &mut fs, PIN).unwrap();
        } else {
            store_local_pin(&device, &mut fs, PIN).unwrap();
        }
        fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
        if device_pin {
            assert!(matches!(
                spend_and_verify_device_pin(&device, &mut fs, PIN),
                LocalPin::Ok
            ));
        } else {
            let mut state = FidoState::new();
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: device,
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 0,
            };
            let hash = Secret::new(sha256(PIN));
            assert_eq!(
                spend_and_verify_pin_hash(&mut ctx, &hash.expose()[..16]),
                Ok(())
            );
        }
        let mut marker = [0; 1];
        assert_eq!(fs.read(rsk_fs::EF_HARDENED, &mut marker), Some(1));
        assert_eq!(marker, [1]);
    }
}
