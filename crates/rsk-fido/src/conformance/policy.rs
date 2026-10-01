// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::consts::*;
use crate::state::{PERM_ACFG, PERM_GA, PERM_MC};
use minicbor::Encoder;
use minicbor::encode::{Write, write::Cursor};

fn finish(e: Encoder<Cursor<[u8; 1024]>>) -> Vec<u8> {
    let n = e.writer().position();
    e.into_writer().into_inner()[..n].to_vec()
}

const RP: &str = "policy.example";
const CDH: [u8; 32] = [0x42; 32];

fn config(a: &mut Authr, params: &[u8]) -> Resp {
    let token = a.arm_token(PERM_ACFG);
    let mut msg = vec![0xff; 32];
    msg.extend_from_slice(&[CTAP_CONFIG, CONFIG_SET_MIN_PIN as u8]);
    msg.extend_from_slice(params);
    let mut e = Encoder::new(Cursor::new([0u8; 1024]));
    e.map(4)
        .unwrap()
        .u8(1)
        .unwrap()
        .u64(CONFIG_SET_MIN_PIN)
        .unwrap();
    e.u8(2).unwrap().writer_mut().write_all(params).unwrap();
    e.u8(3).unwrap().u8(2).unwrap();
    e.u8(4).unwrap().bytes(&pin_auth(&token, &msg)).unwrap();
    a.send(CTAP_CONFIG, &finish(e))
}

fn mc(a: &mut Authr, user: u8, name: &str, input: bool, uv: bool) -> Resp {
    let token = uv.then(|| a.arm_token(PERM_MC));
    a.send(
        CTAP_MAKE_CREDENTIAL,
        &mc_request(user, name, input, token.as_ref(), true),
    )
}

fn mc_request(
    user: u8,
    name: &str,
    input: bool,
    token: Option<&[u8; 32]>,
    resident: bool,
) -> Vec<u8> {
    let mut e = Encoder::new(Cursor::new([0u8; 1024]));
    e.map(5 + u64::from(resident) + 2 * u64::from(token.is_some()))
        .unwrap();
    e.u8(1).unwrap().bytes(&CDH).unwrap();
    e.u8(2)
        .unwrap()
        .map(1)
        .unwrap()
        .str("id")
        .unwrap()
        .str(RP)
        .unwrap();
    e.u8(3)
        .unwrap()
        .map(1)
        .unwrap()
        .str("id")
        .unwrap()
        .bytes(&[user])
        .unwrap();
    e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
    e.str("alg").unwrap().i64(ALG_ES256).unwrap();
    e.str("type").unwrap().str("public-key").unwrap();
    e.u8(6)
        .unwrap()
        .map(1)
        .unwrap()
        .str(name)
        .unwrap()
        .bool(input)
        .unwrap();
    if resident {
        e.u8(7)
            .unwrap()
            .map(1)
            .unwrap()
            .str("rk")
            .unwrap()
            .bool(true)
            .unwrap();
    }
    if let Some(token) = token {
        e.u8(8).unwrap().bytes(&pin_auth(token, &CDH)).unwrap();
        e.u8(9).unwrap().u8(2).unwrap();
    }
    finish(e)
}

/// Go catalog: uvm P-1, pin-complexity-policy P-1/P-2, authenticator-config P-6.
#[test]
fn catalog_extensions_work_without_makecredential_options_and_false_is_a_policy_value() {
    let mut a = Authr::fresh();
    let mut params = Encoder::new(Cursor::new([0u8; 1024]));
    params
        .map(1)
        .unwrap()
        .u8(2)
        .unwrap()
        .array(1)
        .unwrap()
        .str(RP)
        .unwrap();
    assert_ok_empty(&config(&mut a, &finish(params)));
    let expected = field_at(&a.get_info().body, 0x1b).unwrap().bool().unwrap();
    let token = a.arm_token(PERM_MC);
    let r = a.send(
        CTAP_MAKE_CREDENTIAL,
        &mc_request(1, "pinComplexityPolicy", true, Some(&token), false),
    );
    assert_eq!(
        extension(&r, true, "pinComplexityPolicy"),
        Some(vec![if expected { 0xf5 } else { 0xf4 }])
    );
    let token = a.arm_token(PERM_MC);
    let r = a.send(
        CTAP_MAKE_CREDENTIAL,
        &mc_request(2, "pinComplexityPolicy", false, Some(&token), false),
    );
    assert_eq!(extension(&r, true, "pinComplexityPolicy"), None);
    let token = a.arm_token(PERM_MC);
    let r = a.send(
        CTAP_MAKE_CREDENTIAL,
        &mc_request(3, "uvm", true, Some(&token), false),
    );
    assert_eq!(
        extension(&r, true, "uvm"),
        Some(vec![0x82, 0x83, 1, 2, 4, 0x83, 0x19, 8, 0, 2, 4])
    );
    let (alg, sig, leaf) = packed_att_stmt(&r.body);
    assert_eq!(alg, ALG_ES256);
    let (x, y) = att_leaf_pubkey(&leaf);
    let mut message = field_at(&r.body, 2).unwrap().bytes().unwrap().to_vec();
    message.extend_from_slice(&CDH);
    verify_p256(&x, &y, &message, &sig);
    assert_ok_empty(&a.send(CTAP_RESET, &[]));
    assert_eq!(
        field_at(&a.get_info().body, 0x1b).unwrap().bool().unwrap(),
        PIN_COMPLEXITY_POLICY
    );
    let r = mc(&mut a, 4, "pinComplexityPolicy", true, true);
    assert_eq!(extension(&r, true, "pinComplexityPolicy"), None);
}

fn extension(r: &Resp, mc: bool, name: &str) -> Option<Vec<u8>> {
    assert_ok(r);
    let ad = field_at(&r.body, 2).unwrap().bytes().unwrap();
    if ad[32] & FLAG_ED == 0 {
        return None;
    }
    let mut d = if mc {
        let n = u16::from_be_bytes([ad[53], ad[54]]) as usize;
        let mut d = Decoder::new(&ad[55 + n..]);
        d.skip().unwrap();
        d
    } else {
        Decoder::new(&ad[37..])
    };
    let mut previous = Vec::new();
    let mut result = None;
    for _ in 0..d.map().unwrap().unwrap() {
        let start = d.position();
        let key = d.str().unwrap();
        let encoded = d.input()[start..d.position()].to_vec();
        assert!(
            previous.is_empty() || previous < encoded,
            "canonical extension order"
        );
        previous = encoded;
        let start = d.position();
        d.skip().unwrap();
        if key == name {
            result = Some(d.input()[start..d.position()].to_vec());
        }
    }
    assert_eq!(d.position(), d.input().len());
    result
}

#[test]
fn silent_assertion_reports_no_interaction_and_false_is_omitted() {
    let mut a = Authr::fresh();
    assert_ok(&mc(&mut a, 1, "uvm", false, false));
    for requested in [true, false] {
        let mut e = Encoder::new(Cursor::new([0u8; 1024]));
        e.map(4).unwrap().u8(1).unwrap().str(RP).unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(4)
            .unwrap()
            .map(1)
            .unwrap()
            .str("uvm")
            .unwrap()
            .bool(requested)
            .unwrap();
        e.u8(5)
            .unwrap()
            .map(1)
            .unwrap()
            .str("up")
            .unwrap()
            .bool(false)
            .unwrap();
        let r = a.send(CTAP_GET_ASSERTION, &finish(e));
        let expected = if requested {
            Some(if cfg!(feature = "strict-up") {
                vec![0x81, 0x83, 1, 2, 4]
            } else {
                vec![0x81, 0x83, 0x19, 2, 0, 2, 4]
            })
        } else {
            None
        };
        assert_eq!(extension(&r, false, "uvm"), expected);
    }
}

#[test]
fn known_policy_extensions_and_config_validate_boolean_inputs() {
    for name in ["uvm", "pinComplexityPolicy"] {
        let mut a = Authr::fresh();
        let mut e = Encoder::new(Cursor::new([0u8; 1024]));
        e.map(3).unwrap().u8(1).unwrap().str(RP).unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(4)
            .unwrap()
            .map(1)
            .unwrap()
            .str(name)
            .unwrap()
            .u8(1)
            .unwrap();
        assert_eq!(
            a.send(CTAP_GET_ASSERTION, &finish(e)).status,
            CtapError::CborUnexpectedType.as_u8()
        );
        let mut request = mc_request(1, name, false, None, true);
        let mut d = Decoder::new(&request);
        let n = d.map().unwrap().unwrap();
        let mut value = None;
        for _ in 0..n {
            if d.u8().unwrap() == 6 {
                assert_eq!(d.map().unwrap(), Some(1));
                assert_eq!(d.str().unwrap(), name);
                value = Some(d.position());
                break;
            }
            d.skip().unwrap();
        }
        request[value.unwrap()] = 1;
        assert_eq!(
            a.send(CTAP_MAKE_CREDENTIAL, &request).status,
            CtapError::CborUnexpectedType.as_u8()
        );
        assert_ok(&mc(&mut a, 1, name, false, false));
    }
    assert_eq!(
        Authr::fresh()
            .send(CTAP_CONFIG, &[0xa2, 1, 3, 2, 0xa1, 4, 1])
            .status,
        CtapError::CborUnexpectedType.as_u8()
    );
}

#[test]
fn an_unlisted_rp_cannot_read_min_pin_length_alongside_uvm() {
    let mut a = Authr::fresh();
    let mut request = mc_request(1, "minPinLength", true, None, true);
    let mut d = Decoder::new(&request);
    let n = d.map().unwrap().unwrap();
    let mut extensions = None;
    for _ in 0..n {
        if d.u8().unwrap() == 6 {
            extensions = Some(d.position());
            break;
        }
        d.skip().unwrap();
    }
    let at = extensions.unwrap();
    request[at] = 0xa2;
    request.splice(at + 1..at + 1, [0x63, b'u', b'v', b'm', 0xf5]);
    let r = a.send(CTAP_MAKE_CREDENTIAL, &request);
    assert!(extension(&r, true, "uvm").is_some());
    assert_eq!(extension(&r, true, "minPinLength"), None);
}

#[test]
fn uvm_reports_presence_and_external_pin() {
    let mut a = Authr::fresh();
    let r = mc(&mut a, 1, "uvm", true, false);
    assert_eq!(extension(&r, true, "uvm"), Some(vec![0x81, 0x83, 1, 2, 4]));
    let r = mc(&mut a, 2, "uvm", true, true);
    assert_eq!(
        extension(&r, true, "uvm"),
        Some(vec![0x82, 0x83, 1, 2, 4, 0x83, 0x19, 8, 0, 2, 4])
    );
}

#[test]
fn uvm_false_is_omitted_and_next_assertion_keeps_methods() {
    let mut a = Authr::fresh();
    let r = mc(&mut a, 1, "uvm", false, false);
    assert_eq!(extension(&r, true, "uvm"), None);
    assert_ok(&mc(&mut a, 2, "uvm", false, false));
    let token = a.arm_token(PERM_GA);
    let mut e = Encoder::new(Cursor::new([0u8; 1024]));
    e.map(5).unwrap().u8(1).unwrap().str(RP).unwrap();
    e.u8(2).unwrap().bytes(&CDH).unwrap();
    e.u8(4)
        .unwrap()
        .map(1)
        .unwrap()
        .str("uvm")
        .unwrap()
        .bool(true)
        .unwrap();
    e.u8(6).unwrap().bytes(&pin_auth(&token, &CDH)).unwrap();
    e.u8(7).unwrap().u8(2).unwrap();
    let first = a.send(CTAP_GET_ASSERTION, &finish(e));
    let next = a.send(CTAP_GET_NEXT_ASSERTION, &[]);
    let methods = extension(&first, false, "uvm").expect("uvm returned");
    assert_eq!(extension(&next, false, "uvm"), Some(methods));
}

#[test]
fn complexity_config_is_monotonic_and_rp_scoped() {
    let mut a = Authr::fresh();
    let mut e = Encoder::new(Cursor::new([0u8; 1024]));
    e.map(2)
        .unwrap()
        .u8(2)
        .unwrap()
        .array(1)
        .unwrap()
        .str(RP)
        .unwrap();
    e.u8(4).unwrap().bool(true).unwrap();
    assert_ok_empty(&config(&mut a, &finish(e)));
    assert!(field_at(&a.get_info().body, 0x1b).unwrap().bool().unwrap());
    assert_ok_empty(&config(&mut a, &[0xa1, 4, 0xf4]));
    assert!(field_at(&a.get_info().body, 0x1b).unwrap().bool().unwrap());
    let r = mc(&mut a, 1, "pinComplexityPolicy", true, true);
    assert_eq!(extension(&r, true, "pinComplexityPolicy"), Some(vec![0xf5]));
    assert_ok_empty(&config(
        &mut a,
        &[0xa1, 2, 0x81, 0x65, b'o', b't', b'h', b'e', b'r'],
    ));
    let r = mc(&mut a, 2, "pinComplexityPolicy", true, true);
    assert_eq!(extension(&r, true, "pinComplexityPolicy"), None);
}
