// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::cut::sweep_restarts;
use std::cell::RefCell;

#[test]
fn reset_and_its_owner_retry_keep_gates_over_either_surviving_seed_form() {
    for locked in [false, true] {
        let old = RefCell::new(Vec::new());
        let org = RefCell::new(None);
        let seed_fid = if locked { EF_KEY_DEV_ENC } else { EF_KEY_DEV };
        let inspect = |fs: &mut Fs<Cut>| {
            if owner_seed_survived(fs, seed_fid.get(), &old.borrow()) {
                assert!(fs.has_data(EF_PIN));
                assert!(fs.has_data(crate::consts::EF_ALWAYS_UV));
                assert!(fs.has_data(EF_BACKUP_SEALED));
            }
        };
        assert!(sweep_restarts(
            || {
                let (storage, medium) = Cut::new();
                let mut fs = Fs::new(storage);
                fs.scan();
                ensure_seed(&dev(), &mut fs, &mut SeqRng(1)).unwrap();
                let seed = load_keydev(&dev(), &mut fs).unwrap();
                provision_passkey(&mut fs, seed.expose());
                crate::clientpin::store_local_pin(&dev(), &mut fs, crate::test_pins::PIN).unwrap();
                fs.put(crate::consts::EF_ALWAYS_UV, &[1]).unwrap();
                fs.put(EF_BACKUP_SEALED, &[1]).unwrap();
                crate::seed::store_att_key(&dev(), &mut fs, &[0x11; 32]).unwrap();
                fs.put(crate::consts::EF_ATT_CHAIN, b"organization chain")
                    .unwrap();
                *org.borrow_mut() = medium.value(crate::consts::EF_ATT_KEY.get());
                if locked {
                    let wrapped =
                        crate::seed::seal_seed_locked(&mut SeqRng(71), &[0x99; 32], seed.expose());
                    fs.put_key(EF_KEY_DEV_ENC, rsk_fs::Sealed::wrap(&wrapped))
                        .unwrap();
                    fs.delete_key(EF_KEY_DEV).unwrap();
                }
                *old.borrow_mut() = medium.value(seed_fid.get()).unwrap();
                fs.put(0xB000, b"another applet").unwrap();
                fs.meta_add(0xB000, b"metadata").unwrap();
                (fs, medium)
            },
            |fs| run_reset(fs).is_ok(),
            |fs| {
                let _ = ensure_seed(&dev(), fs, &mut SeqRng(91));
                inspect(fs);
                let _ = run_reset(fs);
            },
            |fs, _, _, _, medium| {
                assert!(!owner_seed_survived(fs, seed_fid.get(), &old.borrow()));
                assert!(load_keydev(&dev(), fs).is_some());
                for fid in [EF_CRED, EF_RP, EF_PIN, EF_DEVICE_PIN, EF_BACKUP_SEALED] {
                    assert!(!fs.has_data(fid));
                }
                assert_eq!(medium.value(crate::consts::EF_ATT_KEY.get()), *org.borrow());
                assert_eq!(
                    medium.value(crate::consts::EF_ATT_CHAIN).as_deref(),
                    Some(&b"organization chain"[..])
                );
                assert_eq!(
                    medium.value(0xB000).as_deref(),
                    Some(&b"another applet"[..])
                );
                let mut meta = [0; 8];
                assert_eq!(fs.meta_find(0xB000, &mut meta), Some(8));
                assert_eq!(&meta, b"metadata");
            }
        ));
    }
}
