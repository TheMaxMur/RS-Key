// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::cut::sweep_restarts;
use rsk_fs::storage::faults::Cut;

#[test]
fn a_replacement_cut_cannot_reset_the_counter_of_the_previous_resident_credential() {
    let old = std::cell::RefCell::new(Vec::new());
    let neighbor = std::cell::RefCell::new(Vec::new());
    for legacy_counter in [false, true] {
        let provision = || {
            let (storage, medium) = Cut::new();
            let mut fs = Fs::new(storage);
            fs.scan();
            crate::tests::uv_optional(&mut fs);
            let mut rng = SeqRng(1);
            ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
            register(&mut fs, &mut rng, "example.com", &[1, 1], "alice");
            register(&mut fs, &mut rng, "other.example", &[9, 9], "neighbor");
            crate::seed::set_cred_sign_counter(&mut fs, 0, if legacy_counter { 0 } else { 73 })
                .unwrap();
            crate::seed::set_cred_sign_counter(&mut fs, 1, 59).unwrap();
            fs.put_counter(crate::consts::EF_COUNTER, &73u32.to_le_bytes())
                .unwrap();
            let mut record = [0; CRED_REC_MAX];
            let n = fs.read(EF_CRED, &mut record).unwrap();
            *old.borrow_mut() = record[..n].to_vec();
            let n = fs.read(EF_CRED + 1, &mut record).unwrap();
            *neighbor.borrow_mut() = record[..n].to_vec();
            (fs, medium)
        };
        let replace = |fs: &mut Fs<Cut>| {
            let mut state = FidoState::new();
            let mut presence = crate::AlwaysConfirm;
            let mut rng = SeqRng(91);
            let mut ctx = Ctx {
                dev: dev(),
                fs,
                state: &mut state,
                presence: &mut presence,
                rng: &mut rng,
                now_ms: 10,
            };
            make_credential(
                &mut ctx,
                &mc_request("example.com", &[1, 1], "alice2"),
                &mut [0; 1024],
            )
            .is_ok()
        };
        let (mut reference, _) = provision();
        assert!(replace(&mut reference));
        let mut expected = [0; CRED_REC_MAX];
        let n = reference.read(EF_CRED, &mut expected).unwrap();
        let expected = expected[..n].to_vec();
        assert_ne!(expected, *old.borrow());
        assert!(!sweep_restarts(
            provision,
            replace,
            |fs| {
                let _ = settle_rp_records(fs);
            },
            |fs, first, second, completed, _| {
                assert_eq!(second, 0);
                let mut record = [0; CRED_REC_MAX];
                let n = fs.read(EF_CRED, &mut record).unwrap();
                let current = &record[..n];
                let counter = crate::seed::report_sign_counter(fs, 0).unwrap();
                assert_eq!(crate::seed::cred_sign_counter(fs, 1), Ok(Some(59)));
                if current == old.borrow().as_slice() {
                    assert_eq!(
                        counter, 73,
                        "cut {first}: the old credential retained its key but lost its counter"
                    );
                    assert!(!completed);
                } else {
                    assert_eq!(current, expected);
                    assert!(
                        counter == 73 || counter == 1,
                        "cut {first}: replacement counter {counter}"
                    );
                    if completed {
                        assert_eq!(counter, 1);
                    }
                }
                let n = fs.read(EF_CRED + 1, &mut record).unwrap();
                assert_eq!(&record[..n], neighbor.borrow().as_slice());
                assert_eq!(
                    crate::credential::rp_count(fs, &sha256(b"example.com")).unwrap(),
                    1
                );
            }
        ));
    }
}

#[test]
fn new_credentials_keep_their_counter_and_rp_after_command_and_settle_cuts() {
    let neighbor = std::cell::RefCell::new(Vec::new());
    let provision = || {
        let (storage, medium) = Cut::new();
        let mut fs = Fs::new(storage);
        fs.scan();
        crate::tests::uv_optional(&mut fs);
        let mut rng = SeqRng(1);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        register(&mut fs, &mut rng, "other.example", &[9, 9], "neighbor");
        crate::seed::set_cred_sign_counter(&mut fs, 0, 59).unwrap();
        let mut record = [0; CRED_REC_MAX];
        let n = fs.read(EF_CRED, &mut record).unwrap();
        *neighbor.borrow_mut() = record[..n].to_vec();
        (fs, medium)
    };
    let create = |fs: &mut Fs<Cut>| {
        let mut state = FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut rng = SeqRng(91);
        let mut ctx = Ctx {
            dev: dev(),
            fs,
            state: &mut state,
            presence: &mut presence,
            rng: &mut rng,
            now_ms: 10,
        };
        make_credential(
            &mut ctx,
            &mc_request("created.example", &[1, 1], "alice"),
            &mut [0; 1024],
        )
        .is_ok()
    };
    let (mut reference, _) = provision();
    assert!(create(&mut reference));
    let mut record = [0; CRED_REC_MAX];
    let n = reference.read(EF_CRED + 1, &mut record).unwrap();
    let expected = record[..n].to_vec();
    assert!(sweep_restarts(
        provision,
        create,
        |fs| {
            let _ = settle_rp_records(fs);
        },
        |fs, first, second, completed, _| {
            let mut record = [0; CRED_REC_MAX];
            let current = fs
                .read(EF_CRED + 1, &mut record)
                .map(|n| record[..n].to_vec());
            assert!(
                current.is_none() || current.as_ref() == Some(&expected),
                "cuts {first}/{second}"
            );
            if completed {
                assert_eq!(current.as_ref(), Some(&expected));
            }
            if current.is_some() {
                assert_eq!(crate::seed::cred_sign_counter(fs, 1), Ok(Some(1)));
            }
            assert_eq!(
                crate::credential::rp_count(fs, &sha256(b"created.example")).unwrap(),
                usize::from(current.is_some())
            );
            assert_eq!(crate::seed::cred_sign_counter(fs, 0), Ok(Some(59)));
            let n = fs.read(EF_CRED, &mut record).unwrap();
            assert_eq!(&record[..n], neighbor.borrow().as_slice());
        }
    ));
}
