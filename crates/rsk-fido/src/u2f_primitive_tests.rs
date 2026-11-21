// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use std::vec::Vec;

std::thread_local! {
    static REJECT_KEY: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

pub(in crate::u2f) fn key_result_with_injected_failure(key: Option<P256Key>) -> Option<P256Key> {
    if REJECT_KEY.with(|reject| reject.replace(false)) {
        None
    } else {
        key
    }
}

fn pin_ready() -> (Fs<RamStorage>, SeqRng, UvPad) {
    let mut fs = Fs::new(RamStorage::new());
    crate::clientpin::store_local_pin(&dev(), &mut fs, PIN).unwrap();
    fs.put(EF_ALWAYS_UV, &[1]).unwrap();
    (
        fs,
        SeqRng(1),
        UvPad {
            digits: PIN,
            touches: 0,
        },
    )
}

fn register_body() -> Vec<u8> {
    [CHAL.as_slice(), APP.as_slice()].concat()
}

#[test]
fn absent_seed_and_a_sealed_zero_device_scalar_produce_no_u2f_registration() {
    for zero in [false, true] {
        let (mut fs, mut rng, mut presence) = pin_ready();
        if zero {
            crate::seed::encrypt_keydev_f1(&dev(), &mut fs, &[0; 32]).unwrap();
        }
        let raw = ext_apdu(CTAP_REGISTER, 0, &register_body());
        let apdu = Apdu::parse(&raw).unwrap();
        let mut state = crate::FidoState::new();
        let mut output = [0xA5; 1024];
        assert_eq!(
            process_u2f(
                &mut Ctx {
                    dev: dev(),
                    fs: &mut fs,
                    rng: &mut rng,
                    state: &mut state,
                    presence: &mut presence,
                    now_ms: 0
                },
                &apdu,
                &mut output
            ),
            (Sw::EXEC_ERROR, 0)
        );
        assert_eq!(output, [0xA5; 1024]);
    }
}

#[test]
fn an_absent_seed_cannot_resolve_a_u2f_authentication_handle() {
    let (mut fs, mut rng, mut presence) = pin_ready();
    let mut body = register_body();
    body.push(u8::try_from(KEY_HANDLE_LEN).unwrap());
    body.extend([0; KEY_HANDLE_LEN]);
    let raw = ext_apdu(CTAP_AUTHENTICATE, U2F_AUTH_ENFORCE, &body);
    let apdu = Apdu::parse(&raw).unwrap();
    let mut state = crate::FidoState::new();
    let mut output = [0xA5; 256];
    assert_eq!(
        process_u2f(
            &mut Ctx {
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                presence: &mut presence,
                now_ms: 0
            },
            &apdu,
            &mut output
        ),
        (Sw::EXEC_ERROR, 0)
    );
    assert_eq!(output, [0xA5; 256]);
}

#[test]
fn a_refused_derived_key_spends_no_signature_counter_and_the_next_attempt_recovers() {
    let (mut fs, mut rng, mut presence) = pin_ready();
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let mut state = crate::FidoState::new();
    let raw = ext_apdu(CTAP_REGISTER, 0, &register_body());
    let mut registration = [0; 1024];
    let mut ctx = Ctx {
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        presence: &mut presence,
        now_ms: 0,
    };
    assert_eq!(
        process_u2f(&mut ctx, &Apdu::parse(&raw).unwrap(), &mut registration).0,
        Sw::OK
    );
    let mut body = register_body();
    body.push(u8::try_from(KEY_HANDLE_LEN).unwrap());
    body.extend_from_slice(&registration[67..67 + KEY_HANDLE_LEN]);
    let raw = ext_apdu(CTAP_AUTHENTICATE, U2F_AUTH_ENFORCE, &body);
    let apdu = Apdu::parse(&raw).unwrap();
    let before = crate::seed::global_sign_counter(ctx.fs).unwrap();
    let mut output = [0xA5; 256];
    REJECT_KEY.with(|reject| reject.set(true));
    assert_eq!(
        process_u2f(&mut ctx, &apdu, &mut output),
        (Sw::EXEC_ERROR, 0)
    );
    assert!(!REJECT_KEY.with(core::cell::Cell::get));
    assert_eq!(output, [0xA5; 256]);
    assert_eq!(crate::seed::global_sign_counter(ctx.fs), Ok(before));
    assert_eq!(process_u2f(&mut ctx, &apdu, &mut output).0, Sw::OK);
    assert_eq!(crate::seed::global_sign_counter(ctx.fs), Ok(before + 1));
}
