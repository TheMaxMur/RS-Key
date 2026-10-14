// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn a_transport_reset_clears_authorization_without_trusting_selection() {
    let env = Env::new();
    rsk_openpgp::scan_files(
        &crate::tests::dev(),
        &mut env.fs.borrow_mut(),
        &mut *env.rng.borrow_mut(),
    )
    .unwrap();
    let mut ccid = env.ccid();
    assert_eq!(sw(ccid.handle_apdu(&select(rsk_piv::PIV_AID), 0)), Sw::OK);
    assert_eq!(
        sw(ccid.handle_apdu(&apdu(0, 0x20, 0, 0x80, &rsk_piv::files::DEFAULT_PIN), 0)),
        Sw::OK
    );
    let request = apdu(0, 0x20, 0, 0x82, rsk_openpgp::consts::PW1_DEFAULT);
    let parsed = Apdu::parse(&request).unwrap();
    let mut out = [0; 16];
    assert_eq!(
        ccid.openpgp.process(
            &parsed,
            &mut env.fs.borrow_mut(),
            &mut ResBuf::new(&mut out)
        ),
        Sw::OK
    );
    assert!(verified_in(&mut ccid.openpgp, &env.fs, 0x82));
    assert!(verified_in(&mut ccid.piv, &env.fs, 0x80));
    ccid.reset_transport_session();
    assert!(
        !verified_in(&mut ccid.openpgp, &env.fs, 0x82),
        "an unselected OpenPGP session survived USB reset"
    );
    assert!(!verified_in(&mut ccid.piv, &env.fs, 0x80));
    assert_eq!(ccid.disp.current(), None);
}

#[test]
fn a_transport_reset_scrubs_dispatcher_buffers_and_preserves_the_pin_budget() {
    let env = Env::new();
    let mut ccid = env.ccid();
    assert_eq!(
        sw(ccid.handle_apdu(&select(rsk_openpgp::consts::OPENPGP_AID), 0)),
        Sw::OK
    );
    let response = ccid.handle_apdu(&[0, 0xca, 0, 0x6e, 0x10], 0).to_vec();
    assert_eq!(response[response.len() - 2], 0x61);
    assert!(ccid.disp.response_owed());
    env.fido_state
        .borrow_mut()
        .restore_pin_lock(rsk_fido::state::PinLock {
            engaged: true,
            mismatches: rsk_fido::consts::PIN_MISMATCH_LIMIT,
        });
    let before = env.fido_state.borrow().pin_lock();
    ccid.reset_transport_session();
    assert!(!ccid.disp.response_owed());
    assert!(!ccid.disp.chain_open());
    assert!(
        ccid.resp.iter().all(|byte| *byte == 0),
        "USB reset left the CCID reply in RAM"
    );
    assert_eq!(env.fido_state.borrow().pin_lock(), before);
}
