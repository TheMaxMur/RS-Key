// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP 2.1 §6.6 `authenticatorReset` conformance, driven through the wire
//! envelope (`process_cbor`): a present-gated wipe that clears credentials and
//! enterprise attestation, and a no-presence rejection.

use super::{Authr, assert_ok, assert_ok_empty, field_at, pin_auth};
use crate::consts::{
    ALG_ES256, CONFIG_ENABLE_EA, CTAP_CONFIG, CTAP_GET_ASSERTION, CTAP_MAKE_CREDENTIAL, CTAP_RESET,
};
use crate::error::CtapError;
use crate::state::{PERM_ACFG, puat_subcommand_msg};
use minicbor::Encoder;
use minicbor::encode::write::Cursor;

const RP_ID: &str = "reset.example";

fn mc_rk() -> Vec<u8> {
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(5).unwrap();
        e.u8(1).unwrap().bytes(&[0xCD; 32]).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str(RP_ID)
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&[5, 5, 5, 5]).unwrap();
        e.str("name").unwrap().str("erin").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(7)
            .unwrap()
            .map(1)
            .unwrap()
            .str("rk")
            .unwrap()
            .bool(true)
            .unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

fn ga() -> Vec<u8> {
    let mut buf = [0u8; 64];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(2).unwrap();
        e.u8(1).unwrap().str(RP_ID).unwrap();
        e.u8(2).unwrap().bytes(&[0xCD; 32]).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

#[test]
fn reset_wipes_credentials() {
    let mut a = Authr::fresh();
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_rk()));
    // authenticatorReset erases all FIDO state on user presence.
    assert_ok_empty(&a.send(CTAP_RESET, &[]));
    // The discoverable credential is gone.
    let r = a.send(CTAP_GET_ASSERTION, &ga());
    assert_eq!(r.status, CtapError::NoCredentials.as_u8());
}

#[test]
fn reset_denied_without_presence() {
    // Reset is destructive → it must not proceed without a touch (§5.6).
    let r = Authr::declining().send(CTAP_RESET, &[]);
    assert_eq!(r.status, CtapError::UserActionTimeout.as_u8());
}

/// `options.ep` from a fresh getInfo, `None` when the key is absent — which a
/// platform reads as enterprise attestation unsupported, not disabled (§6.4).
fn ep_option(a: &mut Authr) -> Option<bool> {
    let r = a.get_info();
    let mut d = field_at(&r.body, 4).expect("options (0x04) present");
    let n = d.map().unwrap().unwrap();
    for _ in 0..n {
        let hit = d.str().unwrap() == "ep";
        let value = d.bool().unwrap();
        if hit {
            return Some(value);
        }
    }
    None
}

/// enableEnterpriseAttestation `{1: 0x01, 3: 2, 4: pinUvAuthParam}`, the MAC over
/// `0xff*32 ‖ 0x0d ‖ 0x01` (§6.11).
fn enable_ea(token: &[u8; 32]) -> Vec<u8> {
    let mut msg = [0u8; 34];
    let n = puat_subcommand_msg(&mut msg, CTAP_CONFIG, CONFIG_ENABLE_EA as u8, &[]);
    let param = pin_auth(token, &msg[..n]);
    let mut buf = [0u8; 64];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(3).unwrap();
        e.u8(1).unwrap().u64(CONFIG_ENABLE_EA).unwrap();
        e.u8(3).unwrap().u64(2).unwrap();
        e.u8(4).unwrap().bytes(&param).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// FIDO EnterpriseAttestation P-1, across a reset. Enterprise attestation is subject
/// to disablement by authenticatorReset (§6.6), so afterwards `options.ep` is still
/// present — the feature is supported — and false.
#[test]
fn a_reset_disables_enterprise_attestation_and_still_advertises_it() {
    let mut a = Authr::fresh();
    let token = a.arm_token(PERM_ACFG);
    assert_ok_empty(&a.send(CTAP_CONFIG, &enable_ea(&token)));
    assert_eq!(ep_option(&mut a), Some(true), "precondition: enabled");
    assert_ok_empty(&a.send(CTAP_RESET, &[]));
    assert_eq!(
        ep_option(&mut a),
        Some(false),
        "after a reset ep is present and false"
    );
}
