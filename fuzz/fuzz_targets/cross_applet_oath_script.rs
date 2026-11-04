// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The scripted OATH SET CODE / VALIDATE route behind opcode `0xF7`.

use rsk_sdk::Sw;

use super::cross_applet_oath::hmac;
use super::{APPLETS, CcidApplets, OathOracle, status};

// OATH instructions the scripted route drives.
const OATH_SET_CODE: u8 = 0x03;
const OATH_CALCULATE: u8 = 0xA2;
const OATH_VALIDATE: u8 = 0xA3;
// Script variant bits. Each seed sets one, so a compact literal reaches the
// transition it names; the route always installs a code and validates it.
const OATH_HEALTHY: u8 = 0x01;
const OATH_WRONG_SET: u8 = 0x02;
const OATH_WRONG_VALIDATE: u8 = 0x04;
const OATH_STALE: u8 = 0x08;
const OATH_MALFORMED: u8 = 0x10;
const OATH_REPLACE: u8 = 0x20;
const OATH_REMOVE: u8 = 0x40;
const OATH_RESET: u8 = 0x80;
const OATH_TAG_KEY: u8 = 0x73;
const OATH_TAG_CHALLENGE: u8 = 0x74;
const OATH_TAG_RESPONSE: u8 = 0x75;

// -------------------------------------------------------------------------
// The scripted OATH route (0xF7)
// -------------------------------------------------------------------------

fn oath_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut data = vec![
        tag,
        u8::try_from(value.len()).expect("scripted TLV under 256"),
    ];
    data.extend_from_slice(value);
    data
}

fn oath_apdu(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut raw = vec![0x00, ins, p1, p2];
    if !data.is_empty() {
        raw.push(u8::try_from(data.len()).expect("scripted APDU under 256"));
        raw.extend_from_slice(data);
    }
    raw
}

/// Submit one real APDU through the shipped dispatcher and hand the same
/// request/response to the oracle, so every scripted transition is judged by
/// the same rules as one the fuzzer wrote itself.
fn script_send<S: rsk_fs::Storage, R: rsk_sdk::Rng + 'static, VP: rsk_vendor::Platform>(
    ccid: &mut CcidApplets<'_, S, R, VP>,
    oath: &mut OathOracle,
    raw: &[u8],
) -> Vec<u8> {
    let enabled = APPLETS.map(|(_, cap)| ccid.caps_enabled(cap));
    let res = ccid.handle_apdu(raw, 0).to_vec();
    oath.observe(raw, &res, enabled);
    res
}

/// SELECT OATH and return the challenge the response carried, if any.
fn oath_select<S: rsk_fs::Storage, R: rsk_sdk::Rng + 'static, VP: rsk_vendor::Platform>(
    ccid: &mut CcidApplets<'_, S, R, VP>,
    oath: &mut OathOracle,
) -> Option<[u8; 8]> {
    let mut raw = vec![0x00, 0xA4, 0x04, 0x00];
    raw.push(u8::try_from(rsk_oath::OATH_AID.len()).expect("OATH AID fits one byte"));
    raw.extend_from_slice(rsk_oath::OATH_AID);
    let res = script_send(ccid, oath, &raw);
    assert_eq!(status(&res), Sw::OK, "scripted SELECT OATH");
    let body = &res[..res.len() - 2];
    rsk_sdk::tlv::find_tag(body, u16::from(OATH_TAG_CHALLENGE))
        .map(|challenge| challenge.try_into().expect("SELECT challenge is 8 bytes"))
}

fn oath_put(name: &[u8], alg: u8, secret: &[u8]) -> Vec<u8> {
    let mut key = vec![0x20 | (alg & 0x0F), 6];
    key.extend_from_slice(secret);
    let mut data = oath_tlv(0x71, name);
    data.extend(oath_tlv(OATH_TAG_KEY, &key));
    oath_apdu(0x01, 0, 0, &data)
}

fn oath_set_code(alg: u8, secret: &[u8], challenge: &[u8], proof: &[u8]) -> Vec<u8> {
    let mut key = vec![alg];
    key.extend_from_slice(secret);
    let mut data = oath_tlv(OATH_TAG_KEY, &key);
    data.extend(oath_tlv(OATH_TAG_CHALLENGE, challenge));
    data.extend(oath_tlv(OATH_TAG_RESPONSE, proof));
    oath_apdu(OATH_SET_CODE, 0, 0, &data)
}

fn oath_validate(proof: &[u8], host_challenge: &[u8]) -> Vec<u8> {
    let mut data = oath_tlv(OATH_TAG_RESPONSE, proof);
    data.extend(oath_tlv(OATH_TAG_CHALLENGE, host_challenge));
    oath_apdu(OATH_VALIDATE, 0, 0, &data)
}

fn oath_calculate(name: &[u8], challenge: &[u8]) -> Vec<u8> {
    let mut data = oath_tlv(0x71, name);
    data.extend(oath_tlv(OATH_TAG_CHALLENGE, challenge));
    oath_apdu(OATH_CALCULATE, 0, 1, &data)
}

/// The credential's TOTP code, computed here rather than read from the reply.
fn oath_expected_code(alg: u8, secret: &[u8], challenge: &[u8], digits: u8) -> u32 {
    let mac = hmac(alg, secret, challenge).expect("supported algorithm");
    let offset = usize::from(mac[mac.len() - 1] & 0x0F);
    let word = mac
        .get(offset..offset + 4)
        .expect("a supported HMAC is wider than the truncation offset");
    let trunc = u32::from_be_bytes(word.try_into().expect("four bytes")) & 0x7FFF_FFFF;
    trunc % 10u32.pow(u32::from(digits))
}

/// A successful CALCULATE is not just `9000`: the tag and code must be the
/// RFC 4226 truncation of `HMAC(secret, challenge)` this route computed itself.
fn assert_oath_calculate<
    S: rsk_fs::Storage,
    R: rsk_sdk::Rng + 'static,
    VP: rsk_vendor::Platform,
>(
    ccid: &mut CcidApplets<'_, S, R, VP>,
    oath: &mut OathOracle,
    name: &[u8],
    alg: u8,
    secret: &[u8],
    challenge: &[u8],
) {
    let res = script_send(ccid, oath, &oath_calculate(name, challenge));
    assert_eq!(status(&res), Sw::OK, "protected CALCULATE");
    let body = &res[..res.len() - 2];
    let value = rsk_sdk::tlv::find_tag(body, u16::from(OATH_TAG_RESPONSE + 1))
        .expect("CALCULATE succeeded without a code");
    let (digits, code) = value
        .split_first()
        .expect("a CALCULATE code has a digits byte");
    assert_eq!(*digits, 6, "CALCULATE code width");
    assert_eq!(
        code,
        oath_expected_code(alg, secret, challenge, *digits).to_be_bytes(),
        "CALCULATE code is not HMAC(secret, challenge)"
    );
}

/// Drive SET CODE / VALIDATE end to end. The secrets and proofs are computed
/// here from the SELECT challenge, so the route reaches a successful protected
/// CALCULATE without a precomputed HMAC.
pub(super) fn oath_script<
    S: rsk_fs::Storage,
    R: rsk_sdk::Rng + 'static,
    VP: rsk_vendor::Platform,
>(
    ccid: &mut CcidApplets<'_, S, R, VP>,
    oath: &mut OathOracle,
    alg: u8,
    secret_len: u8,
    fill: u8,
    host_challenge: [u8; 8],
    variants: u8,
) {
    let alg = match alg & 0x0F {
        1 => 1,
        2 => 2,
        3 => 3,
        _ => 1,
    };
    let secret_len = usize::from(secret_len).clamp(14, 64);
    let mut secret = vec![fill; secret_len];
    let name = b"script";

    assert!(
        oath_select(ccid, oath).is_none(),
        "code-less SELECT carried a challenge"
    );
    let res = script_send(ccid, oath, &oath_put(name, alg, &secret));
    assert_eq!(status(&res), Sw::OK, "scripted PUT");

    if variants & OATH_MALFORMED != 0 {
        // KEY declares two bytes and carries one: the body never parses.
        let malformed = oath_apdu(OATH_SET_CODE, 0, 0, &[OATH_TAG_KEY, 0x02, alg]);
        let res = script_send(ccid, oath, &malformed);
        assert_ne!(status(&res), Sw::OK, "a malformed SET CODE succeeded");
        assert!(!oath.code_set(), "a malformed SET CODE installed a code");
        // RESPONSE with no CHALLENGE is a syntax error, not a wrong proof.
        let truncated = oath_apdu(OATH_VALIDATE, 0, 0, &[OATH_TAG_RESPONSE, 0x00]);
        let res = script_send(ccid, oath, &truncated);
        assert_ne!(status(&res), Sw::OK, "a malformed VALIDATE succeeded");
    }

    if variants & OATH_WRONG_SET != 0 {
        let mut wrong = hmac(alg, &secret, &host_challenge).expect("supported algorithm");
        wrong[0] ^= 0xFF;
        let res = script_send(
            ccid,
            oath,
            &oath_set_code(alg, &secret, &host_challenge, &wrong),
        );
        assert_ne!(status(&res), Sw::OK, "a wrong SET CODE proof succeeded");
        assert!(!oath.code_set(), "a wrong SET CODE proof installed a code");
    }

    let proof = hmac(alg, &secret, &host_challenge).expect("supported algorithm");
    let res = script_send(
        ccid,
        oath,
        &oath_set_code(alg, &secret, &host_challenge, &proof),
    );
    assert_eq!(status(&res), Sw::OK, "scripted SET CODE");
    assert!(oath.code_set(), "a successful SET CODE left no code");
    // The lock is immediate: no SELECT and no VALIDATE in between.
    let res = script_send(ccid, oath, &oath_calculate(name, &host_challenge));
    assert_eq!(
        status(&res),
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "a protected CALCULATE was served after SET CODE"
    );
    // Removal is behind the same gate as the install.
    let res = script_send(
        ccid,
        oath,
        &oath_apdu(OATH_SET_CODE, 0, 0, &[OATH_TAG_KEY, 0x00]),
    );
    assert_eq!(
        status(&res),
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "an unvalidated SET CODE removal succeeded"
    );
    assert!(oath.code_set(), "a refused removal dropped the code");

    let Some(mut current) = oath_select(ccid, oath) else {
        panic!("SELECT with a code set carried no challenge");
    };

    if variants & OATH_REMOVE != 0 {
        // `73 00` is the access-code gate itself: a locked applet must refuse
        // it, and the refusal must not drop the code.
        let removal = oath_apdu(OATH_SET_CODE, 0, 0, &[OATH_TAG_KEY, 0x00]);
        let res = script_send(ccid, oath, &removal);
        assert_eq!(
            status(&res),
            Sw::SECURITY_STATUS_NOT_SATISFIED,
            "a locked SET CODE removal succeeded"
        );
        assert!(oath.code_set(), "a refused removal dropped the code");
        let Some(fresh) = oath_select(ccid, oath) else {
            panic!("SELECT with a code set carried no challenge");
        };
        current = fresh;
    }

    if variants & OATH_STALE != 0 {
        let stale = current;
        let Some(fresh) = oath_select(ccid, oath) else {
            panic!("SELECT with a code set carried no challenge");
        };
        assert_ne!(stale, fresh, "SELECT reused its challenge");
        let stale_proof = hmac(alg, &secret, &stale).expect("supported algorithm");
        let res = script_send(ccid, oath, &oath_validate(&stale_proof, &host_challenge));
        assert_eq!(status(&res), Sw::WRONG_DATA, "a stale challenge validated");
        current = fresh;
    }

    if variants & OATH_WRONG_VALIDATE != 0 {
        let mut wrong = hmac(alg, &secret, &current).expect("supported algorithm");
        wrong[0] ^= 0xFF;
        let res = script_send(ccid, oath, &oath_validate(&wrong, &host_challenge));
        assert_eq!(
            status(&res),
            Sw::WRONG_DATA,
            "a wrong VALIDATE proof validated"
        );
    }

    let proof = hmac(alg, &secret, &current).expect("supported algorithm");
    let res = script_send(ccid, oath, &oath_validate(&proof, &host_challenge));
    assert_eq!(status(&res), Sw::OK, "scripted VALIDATE");
    let answer = hmac(alg, &secret, &host_challenge).expect("supported algorithm");
    let body = &res[..res.len() - 2];
    assert_eq!(
        rsk_sdk::tlv::find_tag(body, u16::from(OATH_TAG_RESPONSE)),
        Some(answer.as_slice()),
        "VALIDATE answer"
    );

    if variants & OATH_HEALTHY != 0 {
        assert_oath_calculate(ccid, oath, name, alg, &secret, &host_challenge);
    }

    if variants & OATH_REPLACE != 0 {
        let mut replacement = vec![fill ^ 0xA5; secret_len];
        if replacement == secret {
            replacement[0] ^= 0xFF;
        }
        let proof = hmac(alg, &replacement, &host_challenge).expect("supported algorithm");
        let res = script_send(
            ccid,
            oath,
            &oath_set_code(alg, &replacement, &host_challenge, &proof),
        );
        assert_eq!(status(&res), Sw::OK, "scripted replacement SET CODE");
        let res = script_send(ccid, oath, &oath_calculate(name, &host_challenge));
        assert_eq!(
            status(&res),
            Sw::SECURITY_STATUS_NOT_SATISFIED,
            "a protected CALCULATE was served after a replacement"
        );
        let Some(fresh) = oath_select(ccid, oath) else {
            panic!("SELECT with a code set carried no challenge");
        };
        let old = hmac(alg, &secret, &fresh).expect("supported algorithm");
        let res = script_send(ccid, oath, &oath_validate(&old, &host_challenge));
        assert_eq!(
            status(&res),
            Sw::WRONG_DATA,
            "the replaced secret still validated"
        );
        let new = hmac(alg, &replacement, &fresh).expect("supported algorithm");
        let res = script_send(ccid, oath, &oath_validate(&new, &host_challenge));
        assert_eq!(
            status(&res),
            Sw::OK,
            "the replacement secret did not validate"
        );
        secret = replacement;
    }

    if variants & OATH_REMOVE != 0 {
        let res = script_send(
            ccid,
            oath,
            &oath_apdu(OATH_SET_CODE, 0, 0, &[OATH_TAG_KEY, 0x00]),
        );
        assert_eq!(status(&res), Sw::OK, "validated SET CODE removal");
        assert!(!oath.code_set(), "a successful removal left the code set");
        assert!(
            oath_select(ccid, oath).is_none(),
            "SELECT after removal carried a challenge"
        );
        let res = script_send(ccid, oath, &oath_put(b"removed", alg, &secret));
        assert_eq!(status(&res), Sw::OK, "PUT after removal");
        assert_oath_calculate(ccid, oath, b"removed", alg, &secret, &host_challenge);
    }

    if variants & OATH_RESET != 0 && oath.code_set() {
        // A different applet ends the OATH session just as a power reset does.
        let mut mgmt = vec![0x00, 0xA4, 0x04, 0x00];
        mgmt.push(u8::try_from(rsk_mgmt::MANAGEMENT_AID.len()).expect("AID fits one byte"));
        mgmt.extend_from_slice(rsk_mgmt::MANAGEMENT_AID);
        let res = script_send(ccid, oath, &mgmt);
        assert_eq!(status(&res), Sw::OK, "scripted SELECT away from OATH");
        let Some(fresh) = oath_select(ccid, oath) else {
            panic!("SELECT with a code set carried no challenge");
        };
        let res = script_send(ccid, oath, &oath_calculate(name, &host_challenge));
        assert_eq!(
            status(&res),
            Sw::SECURITY_STATUS_NOT_SATISFIED,
            "a protected CALCULATE was served after deselecting OATH"
        );
        let proof = hmac(alg, &secret, &fresh).expect("supported algorithm");
        let res = script_send(ccid, oath, &oath_validate(&proof, &host_challenge));
        assert_eq!(status(&res), Sw::OK, "VALIDATE after deselecting OATH");

        ccid.reset_card();
        oath.reset_card();
        let Some(fresh) = oath_select(ccid, oath) else {
            panic!("SELECT after reset carried no challenge");
        };
        let res = script_send(ccid, oath, &oath_calculate(name, &host_challenge));
        assert_eq!(
            status(&res),
            Sw::SECURITY_STATUS_NOT_SATISFIED,
            "a protected CALCULATE was served after reset_card"
        );
        let proof = hmac(alg, &secret, &fresh).expect("supported algorithm");
        let res = script_send(ccid, oath, &oath_validate(&proof, &host_challenge));
        assert_eq!(status(&res), Sw::OK, "VALIDATE after reset_card");

        // A switch to another applet deselects OATH; coming back must lock.
        let mut away = vec![0x00, 0xA4, 0x04, 0x00];
        away.push(u8::try_from(rsk_mgmt::MANAGEMENT_AID.len()).expect("management AID fits"));
        away.extend_from_slice(rsk_mgmt::MANAGEMENT_AID);
        assert_eq!(
            status(&script_send(ccid, oath, &away)),
            Sw::OK,
            "scripted SELECT away from OATH"
        );
        assert!(
            oath_select(ccid, oath).is_some(),
            "SELECT after deselection carried no challenge"
        );
        let res = script_send(ccid, oath, &oath_calculate(name, &host_challenge));
        assert_eq!(
            status(&res),
            Sw::SECURITY_STATUS_NOT_SATISFIED,
            "a protected CALCULATE was served after a deselect"
        );
    }
}
