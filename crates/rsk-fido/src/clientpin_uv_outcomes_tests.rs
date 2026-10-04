// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn interrupted_builtin_uv_never_spends_a_retry_or_issues_a_token() {
    for (outcome, want) in [
        (PinEntry::Timeout, CtapError::UserActionTimeout),
        (PinEntry::Cancelled, CtapError::KeepAliveCancel),
        (PinEntry::Unsupported, CtapError::UnsupportedOption),
    ] {
        let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
        let mut pad = UvPad::ending(outcome);
        let mut out = [0x55; 256];
        assert_eq!(
            run_with(
                &mut pad,
                &mut fs,
                &mut rng,
                &mut state,
                &plat.get_uv_token_req(PERM_GA as u64),
                &mut out
            ),
            Err(want)
        );
        assert_eq!(ef_pin_retries(&mut fs), MAX_PIN_RETRIES);
        assert!(!state.paut.in_use);
        assert_eq!(out, [0x55; 256]);
    }
}

#[test]
fn builtin_uv_lockout_is_reported_in_the_uv_retry_response() {
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
    let mut pad = UvPad::typing(WRONG_PIN);
    let mut out = [0; 256];
    for want in [
        CtapError::UvInvalid,
        CtapError::UvInvalid,
        CtapError::UvBlocked,
    ] {
        assert_eq!(
            run_with(
                &mut pad,
                &mut fs,
                &mut rng,
                &mut state,
                &plat.get_uv_token_req(PERM_GA as u64),
                &mut out
            ),
            Err(want)
        );
    }
    assert!(state.needs_power_cycle);
    assert!(!state.paut.in_use);
    assert_eq!(ef_pin_retries(&mut fs), MAX_PIN_RETRIES - 3);
    let req = build(&[(1, V::U(plat.wire)), (2, V::U(7))]);
    let n = run_with(&mut pad, &mut fs, &mut rng, &mut state, &req, &mut out).unwrap();
    let mut d = Decoder::new(&out[..n]);
    assert_eq!(d.map().unwrap(), Some(2));
    assert_eq!(d.u8().unwrap(), 5);
    assert_eq!(d.u8().unwrap(), MAX_PIN_RETRIES - 3);
    assert_eq!(d.u8().unwrap(), 4);
    assert!(d.bool().unwrap());
    assert_eq!(d.position(), n);
}
