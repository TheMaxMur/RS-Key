// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::cut::sweep_restarts;
use rsk_fs::storage::faults::Cut;

#[test]
fn configuration_write_and_its_owner_retry_preserve_lock_authorization_across_two_boots() {
    for transport in [false, true] {
        for clear in [false, true] {
            let old_code = [0x11; 16];
            let new_code = [0x33; 16];
            let mut blob = vec![TAG_CONFIG_UNLOCK, 16];
            blob.extend(old_code);
            blob.extend([TAG_CONFIG_LOCK, 16]);
            blob.extend(if clear { [0; 16] } else { new_code });
            blob.extend([TAG_DEVICE_FLAGS, 1, 0x40]);
            let apply = |fs: &mut Fs<Cut>, blob: &[u8]| {
                let presence = RefCell::new(AlwaysConfirm);
                let mut app = ManagementApplet::new([0; 8], &presence);
                if transport {
                    app.persist_config(fs, blob).is_ok()
                } else {
                    let mut raw = vec![
                        0,
                        INS_WRITE_CONFIG,
                        0,
                        0,
                        (blob.len() + 1) as u8,
                        blob.len() as u8,
                    ];
                    raw.extend(blob);
                    let mut out = [0; 32];
                    Applet::process(
                        &mut app,
                        &Apdu::parse(&raw).unwrap(),
                        fs,
                        &mut ResBuf::new(&mut out),
                    ) == Sw::OK
                }
            };
            let provision = || {
                let (storage, medium) = Cut::new();
                let mut fs = Fs::new(storage);
                fs.scan();
                let mut initial = vec![TAG_CONFIG_LOCK, 16];
                initial.extend(old_code);
                initial.extend([TAG_DEVICE_FLAGS, 1, 0x20]);
                assert!(apply(&mut fs, &initial));
                fs.put(0xB000, b"another applet").unwrap();
                (fs, medium)
            };
            let recover = |fs: &mut Fs<Cut>| {
                let locked = fs.has_data(EF_DEV_LOCK);
                assert!(clear || locked, "replacement transiently removed the lock");
                if locked {
                    let generation = fs.write_gen();
                    assert!(!apply(fs, &[TAG_DEVICE_FLAGS, 1, 0x80]));
                    assert!(!apply(
                        fs,
                        &[
                            &[TAG_CONFIG_UNLOCK, 16][..],
                            &[0x77; 16],
                            &[TAG_DEVICE_FLAGS, 1, 0x80]
                        ]
                        .concat()
                    ));
                    assert_eq!(generation, fs.write_gen());
                }
                if apply(fs, &blob) {
                    return;
                }
                let mut retry = vec![TAG_CONFIG_UNLOCK, 16];
                retry.extend(new_code);
                retry.extend([TAG_CONFIG_LOCK, 16]);
                retry.extend(if clear { [0; 16] } else { new_code });
                retry.extend([TAG_DEVICE_FLAGS, 1, 0x40]);
                let _ = apply(fs, &retry);
            };
            assert!(sweep_restarts(
                provision,
                |fs| apply(fs, &blob),
                recover,
                |fs, _, _, _, medium| {
                    assert_eq!(
                        medium.value(EF_DEV_CONF).as_deref(),
                        Some(&[TAG_DEVICE_FLAGS, 1, 0x40][..])
                    );
                    if !clear {
                        let generation = fs.write_gen();
                        assert!(!apply(fs, &[TAG_DEVICE_FLAGS, 1, 0x80]));
                        assert_eq!(generation, fs.write_gen());
                        assert!(apply(
                            fs,
                            &[
                                &[TAG_CONFIG_UNLOCK, 16][..],
                                &new_code,
                                &[TAG_DEVICE_FLAGS, 1, 0x40]
                            ]
                            .concat()
                        ));
                    } else {
                        assert!(apply(fs, &[TAG_DEVICE_FLAGS, 1, 0x40]));
                    }
                    assert_eq!(
                        medium.value(0xB000).as_deref(),
                        Some(&b"another applet"[..])
                    );
                }
            ));
        }
    }
}
