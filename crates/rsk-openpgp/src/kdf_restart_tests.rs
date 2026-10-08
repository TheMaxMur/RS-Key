// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::cut::sweep_restarts;
use rsk_fs::storage::faults::Cut;

#[test]
fn kdf_on_single_three_salts_and_off_survive_a_second_interrupted_owner_retry() {
    for body in [
        single_salt().to_vec(),
        three_salts().to_vec(),
        KDF_OFF.to_vec(),
    ] {
        let off = body == KDF_OFF;
        let replay = |fs: &mut Fs<Cut>| {
            if scan_files(&dev(), fs, &mut CountRng(9)).is_err() {
                return false;
            }
            let mut sess = Session::new();
            let mut record = [0; 34];
            let Some(n) = fs.read(EF_PW3, &mut record) else {
                return false;
            };
            assert_eq!(n, record.len());
            let password = [PW3_DEFAULT, &HASH_PW3[..]]
                .into_iter()
                .find(|password| dev().pin_derive_verifier(password).expose() == &record[2..])
                .unwrap();
            let authorized = verify(
                &dev(),
                fs,
                &mut sess,
                &mut CountRng(0),
                0,
                PW3_MODE83,
                password,
            ) == Sw::OK;
            authorized && write(fs, &mut sess, &body) == Sw::OK
        };
        assert!(sweep_restarts(
            || {
                let (storage, medium) = Cut::new();
                let mut fs = Fs::new(storage);
                fs.scan();
                scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
                if off {
                    let mut sess = Session::new();
                    admin(&mut fs, &mut sess);
                    assert_eq!(write(&mut fs, &mut sess, &three_salts()), Sw::OK);
                }
                fs.put(0xB000, b"another applet").unwrap();
                (fs, medium)
            },
            replay,
            |fs| {
                let _ = replay(fs);
            },
            |fs, _, _, _, medium| {
                assert!(verifies(
                    fs,
                    PW3_MODE83,
                    if off { PW3_DEFAULT } else { &HASH_PW3 }
                ));
                assert!(verifies(
                    fs,
                    PW1_MODE81,
                    if off { PW1_DEFAULT } else { &HASH_PW1 }
                ));
                assert_eq!(medium.value(EF_KDF).as_deref(), Some(&body[..]));
                assert_eq!(
                    medium.value(0xB000).as_deref(),
                    Some(&b"another applet"[..])
                );
            }
        ));
    }
}
