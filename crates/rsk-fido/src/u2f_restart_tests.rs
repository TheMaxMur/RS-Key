// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::cut::sweep_restarts;
use rsk_fs::storage::faults::Cut;
use std::cell::RefCell;

#[test]
fn u2f_counter_cuts_issue_only_a_signature_with_a_durable_advance() {
    for mode in [U2F_AUTH_ENFORCE, U2F_AUTH_NO_ENFORCE] {
        let handle = RefCell::new(Vec::new());
        let point = RefCell::new(Vec::new());
        let signed = RefCell::new(Vec::new());
        let send = |fs: &mut Fs<Cut>, raw: &[u8]| {
            let mut rng = SeqRng(91);
            let mut state = crate::FidoState::new();
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                dev: dev(),
                fs,
                rng: &mut rng,
                state: &mut state,
                presence: &mut presence,
                now_ms: 0,
            };
            let mut out = [0; 1024];
            let (sw, n) = process_u2f(&mut ctx, &Apdu::parse(raw).unwrap(), &mut out);
            (sw, out[..n].to_vec())
        };
        assert!(!sweep_restarts(
            || {
                let (storage, medium) = Cut::new();
                let mut fs = Fs::new(storage);
                fs.scan();
                crate::tests::uv_optional(&mut fs);
                ensure_seed(&dev(), &mut fs, &mut SeqRng(1)).unwrap();
                let (sw, reg) = send(
                    &mut fs,
                    &ext_apdu(CTAP_REGISTER, 0, &[&CHAL[..], &APP].concat()),
                );
                assert_eq!(sw, Sw::OK);
                *point.borrow_mut() = reg[1..66].to_vec();
                *handle.borrow_mut() = reg[67..67 + KEY_HANDLE_LEN].to_vec();
                fs.put_counter(crate::consts::EF_COUNTER, &73u32.to_le_bytes())
                    .unwrap();
                fs.put(0xB000, b"another applet").unwrap();
                (fs, medium)
            },
            |fs| {
                let body = [
                    &CHAL[..],
                    &APP,
                    &[KEY_HANDLE_LEN as u8],
                    handle.borrow().as_slice(),
                ]
                .concat();
                let (sw, out) = send(fs, &ext_apdu(CTAP_AUTHENTICATE, mode, &body));
                *signed.borrow_mut() = out;
                sw == Sw::OK
            },
            |fs| {
                let _ = ensure_seed(&dev(), fs, &mut SeqRng(7));
            },
            |fs, _, _, completed, medium| {
                let counter = crate::seed::global_sign_counter(fs).unwrap();
                assert!(counter == 73 || counter == 74);
                if completed {
                    let out = signed.borrow();
                    assert_eq!(counter, 74);
                    assert_eq!(&out[1..5], &73u32.to_be_bytes());
                    let signature = Signature::from_der(&out[5..]).unwrap();
                    let data = [&APP[..], &out[..5], &CHAL].concat();
                    let public = point.borrow();
                    vkey(&public[1..33], &public[33..65])
                        .verify(&data, &signature)
                        .unwrap();
                } else {
                    assert!(
                        signed.borrow().is_empty(),
                        "refused counter advancement returned a signature"
                    );
                }
                assert_eq!(
                    medium.value(0xB000).as_deref(),
                    Some(&b"another applet"[..])
                );
            }
        ));
    }
}
