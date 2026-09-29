// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP 2.1 §6.11 `authenticatorConfig` conformance, driven through the wire
//! envelope (`process_cbor`): enableEnterpriseAttestation and setMinPINLength as
//! getInfo then reports them, and the pinUvAuthParam over `0xff*32 ‖ 0x0d ‖
//! subCommand ‖ params` is permission-checked (PERM_ACFG).

use super::{Authr, assert_ok_empty, field_at, pin_auth};
use crate::consts::{
    CONFIG_ENABLE_EA, CONFIG_SET_MIN_PIN, CONFIG_TOGGLE_ALWAYS_UV, CTAP_CONFIG, MIN_PIN_LENGTH,
};
use crate::error::CtapError;
use crate::state::{PERM_ACFG, PERM_GA, puat_subcommand_msg};
use minicbor::Encoder;
use minicbor::encode::write::Cursor;

/// authenticatorConfig request `{1: subCommand, 3: proto, 4: pinUvAuthParam}`.
fn config_request(subcommand: u64, param: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(3).unwrap();
        e.u8(1).unwrap().u64(subcommand).unwrap();
        e.u8(3).unwrap().u64(2).unwrap();
        e.u8(4).unwrap().bytes(param).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// The pinUvAuthParam for a parameter-less authenticatorConfig subcommand.
fn acfg_param(token: &[u8; 32], subcommand: u64) -> Vec<u8> {
    let mut msg = [0u8; 64];
    let n = puat_subcommand_msg(&mut msg, CTAP_CONFIG, subcommand as u8, &[]);
    pin_auth(token, &msg[..n])
}

/// Read a boolean `options.<name>` from a fresh getInfo (false if absent).
fn getinfo_option(a: &mut Authr, name: &str) -> bool {
    let r = a.get_info();
    let mut d = field_at(&r.body, 4).expect("options (0x04) present");
    let n = d.map().unwrap().unwrap();
    for _ in 0..n {
        let hit = d.str().unwrap() == name;
        let val = d.bool().unwrap();
        if hit {
            return val;
        }
    }
    false
}

#[test]
fn config_enable_enterprise_attestation_round_trips() {
    let mut a = Authr::fresh();
    assert!(!getinfo_option(&mut a, "ep"), "options.ep starts disabled");
    let token = a.arm_token(PERM_ACFG);
    let param = acfg_param(&token, CONFIG_ENABLE_EA);
    assert_ok_empty(&a.send(CTAP_CONFIG, &config_request(CONFIG_ENABLE_EA, &param)));
    assert!(
        getinfo_option(&mut a, "ep"),
        "options.ep must flip to true after enableEnterpriseAttestation"
    );
}

#[test]
fn config_toggle_always_uv_round_trips() {
    let mut a = Authr::fresh();
    // alwaysUv starts at the compiled default — disabled on the shipped and
    // conformance images, enabled only under `--features always-uv` — and
    // toggleAlwaysUv must flip whatever that default is. A real conformance run is a
    // default build, so it still observes the "starts disabled → true" path.
    let start = getinfo_option(&mut a, "alwaysUv");
    assert_eq!(
        start,
        cfg!(feature = "always-uv"),
        "options.alwaysUv starts at the compiled default"
    );
    let token = a.arm_token(PERM_ACFG);
    let param = acfg_param(&token, CONFIG_TOGGLE_ALWAYS_UV);
    assert_ok_empty(&a.send(
        CTAP_CONFIG,
        &config_request(CONFIG_TOGGLE_ALWAYS_UV, &param),
    ));
    assert_eq!(
        getinfo_option(&mut a, "alwaysUv"),
        !start,
        "toggleAlwaysUv must flip options.alwaysUv"
    );
}

#[test]
fn config_wrong_permission_rejected() {
    // A token without the authenticatorConfiguration permission → PIN_AUTH_INVALID.
    let mut a = Authr::fresh();
    let token = a.arm_token(PERM_GA);
    let param = acfg_param(&token, CONFIG_ENABLE_EA);
    let r = a.send(CTAP_CONFIG, &config_request(CONFIG_ENABLE_EA, &param));
    assert_eq!(r.status, CtapError::PinAuthInvalid.as_u8());
}

/// Read `minPINLength` (getInfo 0x0D).
fn getinfo_min_pin(a: &mut Authr) -> u8 {
    let r = a.get_info();
    let mut d = field_at(&r.body, 0x0D).expect("minPINLength (0x0D) present");
    d.u8().unwrap()
}

/// setMinPINLength request with subCommandParams `{1: newMin}`; the pinUvAuthParam
/// covers `0xff*32 ‖ 0x0d ‖ 0x03 ‖ <raw subCommandParams>`.
fn set_min_pin_req(token: &[u8; 32], new_min: u64) -> Vec<u8> {
    let mut sub = [0u8; 8];
    let sn = {
        let mut e = Encoder::new(Cursor::new(&mut sub[..]));
        e.map(1).unwrap();
        e.u8(1).unwrap().u64(new_min).unwrap();
        e.writer().position()
    };
    let mut msg = [0u8; 64];
    let mn = puat_subcommand_msg(&mut msg, CTAP_CONFIG, CONFIG_SET_MIN_PIN as u8, &sub[..sn]);
    let puap = pin_auth(token, &msg[..mn]);
    let mut buf = [0u8; 64];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(4).unwrap();
        e.u8(1).unwrap().u64(CONFIG_SET_MIN_PIN).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .u8(1)
            .unwrap()
            .u64(new_min)
            .unwrap();
        e.u8(3).unwrap().u64(2).unwrap();
        e.u8(4).unwrap().bytes(&puap).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

#[test]
fn config_set_min_pin_length_round_trips() {
    let mut a = Authr::fresh();
    assert_eq!(
        getinfo_min_pin(&mut a),
        MIN_PIN_LENGTH,
        "minPINLength starts at the build default"
    );
    let token = a.arm_token(PERM_ACFG);
    assert_ok_empty(&a.send(CTAP_CONFIG, &set_min_pin_req(&token, 6)));
    assert_eq!(
        getinfo_min_pin(&mut a),
        6,
        "getInfo minPINLength reflects setMinPINLength"
    );
}

// Imported here, not in the block above: assurance/ cites this file's lines by number.
use super::assert_ok;
use crate::consts::{ALG_ES256, CTAP_MAKE_CREDENTIAL, FLAG_ED, MAX_MIN_PIN_RPIDS, PUBLIC_KEY_TYPE};
use minicbor::Decoder;

/// CBOR-encode a request body with `f`.
fn enc(f: impl Fn(&mut Encoder<Cursor<&mut [u8]>>)) -> Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        f(&mut e);
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// setMinPINLength with the subCommandParams `params` writes, MACed over
/// `0xff*32 ‖ 0x0d ‖ 0x03 ‖ params` (§6.11); the params go on the wire as MACed.
fn min_pin_req(token: &[u8; 32], params: impl Fn(&mut Encoder<Cursor<&mut [u8]>>)) -> Vec<u8> {
    let raw = enc(params);
    let mut msg = vec![0u8; 34 + raw.len()];
    let n = puat_subcommand_msg(&mut msg, CTAP_CONFIG, CONFIG_SET_MIN_PIN as u8, &raw);
    let head = enc(|e| {
        e.map(4).unwrap();
        e.u8(1).unwrap().u64(CONFIG_SET_MIN_PIN).unwrap();
        e.u8(2).unwrap();
    });
    let tail = enc(|e| {
        e.u8(3).unwrap().u64(2).unwrap();
        e.u8(4).unwrap().bytes(&pin_auth(token, &msg[..n])).unwrap();
    });
    [head, raw, tail].concat()
}

/// Read getInfo member `key`, which must be present, as a boolean.
fn getinfo_bool(a: &mut Authr, key: u32) -> bool {
    let r = a.get_info();
    let mut d = field_at(&r.body, key).unwrap_or_else(|| panic!("getInfo {key:#04x} present"));
    d.bool().unwrap()
}

/// FIDO AuthenticatorConfig P-5. setMinPINLength with forceChangePin makes getInfo
/// forcePINChange (0x0C) true (§6.11.4) — on the wire, where a platform reads it
/// to demand a new PIN before the next use.
#[test]
fn force_change_pin_reads_true_in_get_info() {
    let mut a = Authr::fresh();
    assert!(!getinfo_bool(&mut a, 0x0C), "forcePINChange starts false");
    let token = a.arm_token(PERM_ACFG);
    let req = min_pin_req(&token, |e| {
        e.map(1).unwrap();
        e.u8(3).unwrap().bool(true).unwrap();
    });
    assert_ok_empty(&a.send(CTAP_CONFIG, &req));
    assert!(
        getinfo_bool(&mut a, 0x0C),
        "forceChangePin must surface as forcePINChange"
    );
    assert_eq!(
        getinfo_min_pin(&mut a),
        MIN_PIN_LENGTH,
        "no newMinPINLength: the floor stays where it was"
    );
}

/// FIDO AuthenticatorConfig P-3. A floor raised past the configured PIN's length
/// reads back in 0x0D and forces a change, 0x0C true (§6.11.4). `arm_token`'s PIN
/// is four code points, never above a build's floor, so floor + 1 is past it.
#[test]
fn raising_min_pin_length_past_the_pin_forces_a_change() {
    let mut a = Authr::fresh();
    let token = a.arm_token(PERM_ACFG);
    let new_min = MIN_PIN_LENGTH + 1;
    let req = min_pin_req(&token, |e| {
        e.map(1).unwrap();
        e.u8(1).unwrap().u8(new_min).unwrap();
    });
    assert_ok_empty(&a.send(CTAP_CONFIG, &req));
    assert_eq!(
        getinfo_min_pin(&mut a),
        new_min,
        "minPINLength is the new floor"
    );
    assert!(
        getinfo_bool(&mut a, 0x0C),
        "a PIN shorter than the new floor must be changed"
    );
}

/// A non-discoverable makeCredential over `rp` asking for the minPinLength
/// extension; with a PIN set, makeCredUvNotRqd lets presence alone create it.
fn mc_min_pin_ext(rp: &str) -> Vec<u8> {
    enc(|e| {
        e.map(5).unwrap();
        e.u8(1).unwrap().bytes(&[0xCD; 32]).unwrap();
        e.u8(2).unwrap().map(1).unwrap();
        e.str("id").unwrap().str(rp).unwrap();
        e.u8(3).unwrap().map(1).unwrap();
        e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str(PUBLIC_KEY_TYPE).unwrap();
        e.u8(6).unwrap().map(1).unwrap();
        e.str("minPinLength").unwrap().bool(true).unwrap();
    })
}

/// The minPinLength extension output of a makeCredential response; `None` when
/// the authenticator returned none, as §12.5 has it for an RP not on the list.
fn min_pin_output(resp: &[u8]) -> Option<u8> {
    let mut d = field_at(resp, 2).expect("authData (0x02) present");
    let ad = d.bytes().unwrap();
    if ad[32] & FLAG_ED == 0 {
        return None;
    }
    let len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    let mut d = Decoder::new(&ad[55 + len..]);
    d.skip().unwrap(); // the credential public key
    let n = d.map().unwrap().unwrap();
    for _ in 0..n {
        if d.str().unwrap() == "minPinLength" {
            return Some(d.u8().unwrap());
        }
        d.skip().unwrap();
    }
    None
}

/// FIDO AuthenticatorConfig P-4. setMinPINLength takes a list exactly
/// maxRPIDsForSetMinPINLength (0x10) long, and every RP on it is then authorized for
/// the minPinLength extension (§6.11.4, §12.5) — and an RP off it is not.
#[test]
fn set_min_pin_length_authorizes_a_full_length_rp_id_list() {
    let mut a = Authr::fresh();
    let max = {
        let r = a.get_info();
        let mut d = field_at(&r.body, 0x10).expect("maxRPIDsForSetMinPINLength (0x10) present");
        d.u64().unwrap()
    };
    assert_eq!(
        max, MAX_MIN_PIN_RPIDS as u64,
        "0x10 advertises what the list holds"
    );
    let rps: Vec<String> = (0..max).map(|i| format!("rp{i}.pin.example")).collect();
    let token = a.arm_token(PERM_ACFG);
    let req = min_pin_req(&token, |e| {
        e.map(1).unwrap();
        e.u8(2).unwrap().array(rps.len() as u64).unwrap();
        for rp in &rps {
            e.str(rp).unwrap();
        }
    });
    assert_ok_empty(&a.send(CTAP_CONFIG, &req));

    for rp in &rps {
        let r = a.send(CTAP_MAKE_CREDENTIAL, &mc_min_pin_ext(rp));
        assert_ok(&r);
        assert_eq!(
            min_pin_output(&r.body),
            Some(MIN_PIN_LENGTH),
            "{rp} is on the list, so it learns the floor"
        );
    }
    let r = a.send(CTAP_MAKE_CREDENTIAL, &mc_min_pin_ext("off.pin.example"));
    assert_ok(&r);
    assert_eq!(
        min_pin_output(&r.body),
        None,
        "an RP off the list learns nothing"
    );
}
