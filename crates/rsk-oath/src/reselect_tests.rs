// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Which SELECT keeps OATH's access status. YKOATH has no sentence for it, so the
//! oracle decides: a YubiKey 5.8.0 keeps a VALIDATE through a re-SELECT of the OATH
//! AID (measured twice), as PIV and OpenPGP keep theirs. Driven through the real
//! [`Dispatcher`], which is what decides that a SELECT is a re-SELECT.

use super::*;
use rsk_sdk::Dispatcher;

const OTHER_AID: &[u8] = &[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];
const CODE: [u8; 16] = [0x5A; 16];

/// A second applet, so "SELECT a different valid AID" is expressible.
struct Other;
impl Applet<Fs<RamStorage>> for Other {
    fn aid(&self) -> &'static [u8] {
        OTHER_AID
    }
    fn select(&mut self, _reselect: bool, _fs: &mut Fs<RamStorage>, _res: &mut ResBuf) -> Sw {
        Sw::OK
    }
    fn process(&mut self, _apdu: &Apdu, _fs: &mut Fs<RamStorage>, _res: &mut ResBuf) -> Sw {
        Sw::INS_NOT_SUPPORTED
    }
}

fn go(
    disp: &mut Dispatcher,
    applets: &mut [&mut dyn Applet<Fs<RamStorage>>],
    fs: &mut Fs<RamStorage>,
    raw: &[u8],
) -> (Sw, Vec<u8>) {
    let mut out = [0u8; 2048];
    let mut res = ResBuf::new(&mut out);
    let sw = disp.process(raw, applets, fs, &mut res);
    (sw, res.as_slice().to_vec())
}

fn select_apdu(aid: &[u8]) -> Vec<u8> {
    let mut v = vec![0x00u8, 0xA4, 0x04, 0x00, aid.len() as u8];
    v.extend_from_slice(aid);
    v
}

/// An access code set and VALIDATEd over a fresh selection, then the SELECTs in
/// `sel`, then LIST: 9000 while the validation stands, 6982 once it is gone.
fn list_after(sel: &[&[u8]]) -> Sw {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(StubPresence(Presence::Confirmed, 0));
    let mut oath = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let mut other = Other;
    let mut applets: [&mut dyn Applet<Fs<RamStorage>>; 2] = [&mut oath, &mut other];
    let mut disp = Dispatcher::default();
    let mut send = |raw: &[u8]| go(&mut disp, &mut applets, &mut fs, raw);

    assert_eq!(send(&select_apdu(OATH_AID)).0, Sw::OK);
    let mut key = vec![ALG_HMAC_SHA1];
    key.extend_from_slice(&CODE);
    let mut set = tlv(TAG_KEY, &key);
    set.extend(tlv(TAG_CHALLENGE, &[1u8; 8]));
    set.extend(tlv(TAG_RESPONSE, &hmac_sha1(&CODE, &[1u8; 8])));
    assert_eq!(send(&apdu(INS_SET_CODE, 0, 0, &set)).0, Sw::OK);

    send(&select_apdu(OTHER_AID));
    let (_, body) = send(&select_apdu(OATH_AID));
    let chal = find_tag(&body, TAG_CHALLENGE as u16).unwrap().to_vec();
    let mut val = tlv(TAG_RESPONSE, &hmac_sha1(&CODE, &chal));
    val.extend(tlv(TAG_CHALLENGE, &[9u8; 8]));
    assert_eq!(send(&apdu(INS_VALIDATE, 0, 0, &val)).0, Sw::OK);

    for aid in sel {
        send(&select_apdu(aid));
    }
    send(&apdu(INS_LIST, 0, 0, &[])).0
}

#[test]
fn a_reselect_of_the_oath_aid_keeps_the_validation() {
    assert_eq!(list_after(&[]), Sw::OK, "control: nothing intervened");
    assert_eq!(
        list_after(&[OATH_AID]),
        Sw::OK,
        "a re-SELECT must keep the VALIDATE, as a YubiKey 5.8.0 does"
    );
    assert_eq!(
        list_after(&[&OATH_AID[..7]]),
        Sw::OK,
        "the 7-byte AID ykman sends, the request the YubiKey was measured on"
    );
    assert_eq!(
        list_after(&[OTHER_AID, OATH_AID]),
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "a SELECT elsewhere and back must lock"
    );
}

/// The password-safe PIN is Nitrokey's, so no oracle speaks for it, and it is
/// never inherited across any SELECT: the re-SELECT that keeps a VALIDATE drops it.
#[test]
fn a_reselect_of_the_oath_aid_drops_the_otp_pin() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(StubPresence(Presence::Confirmed, 0));
    let mut oath = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let mut other = Other;
    let mut applets: [&mut dyn Applet<Fs<RamStorage>>; 2] = [&mut oath, &mut other];
    let mut disp = Dispatcher::default();
    let mut send = |raw: &[u8]| go(&mut disp, &mut applets, &mut fs, raw);

    assert_eq!(send(&select_apdu(OATH_AID)).0, Sw::OK);
    let mut cred = put_data(b"bank", 0x21, 6, SECRET_SHA1, false, None);
    cred.extend(tlv(TAG_PWS_PASSWORD, b"s3cr3t"));
    assert_eq!(send(&apdu(INS_PUT, 0, 0, &cred)).0, Sw::OK);
    assert_eq!(
        send(&apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))).0,
        Sw::OK
    );
    let get = apdu(INS_GET_CREDENTIAL, 0, 0, &tlv(TAG_NAME, b"bank"));
    assert_eq!(
        send(&apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))).0,
        Sw::OK
    );
    assert_eq!(
        send(&get).0,
        Sw::OK,
        "control: the verified PIN opens the safe"
    );
    assert_eq!(send(&select_apdu(OATH_AID)).0, Sw::OK);
    assert_eq!(
        send(&get).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "a re-SELECT must not carry the OTP PIN over"
    );
}

/// The rest of what the YubiKey was measured doing on a re-SELECT: it hands out a
/// fresh challenge while the VALIDATE stands, and a validation the OTP PIN minted
/// stands with it, though the password safe the PIN guards closes.
#[test]
fn a_reselect_rotates_the_challenge_and_keeps_a_pin_minted_validation() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(StubPresence(Presence::Confirmed, 0));
    let mut oath = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let mut other = Other;
    let mut applets: [&mut dyn Applet<Fs<RamStorage>>; 2] = [&mut oath, &mut other];
    let mut disp = Dispatcher::default();
    let mut send = |raw: &[u8]| go(&mut disp, &mut applets, &mut fs, raw);

    // The code first: installing one drops any OTP PIN, so the PIN comes after a
    // VALIDATE under that code.
    assert_eq!(send(&select_apdu(OATH_AID)).0, Sw::OK);
    let mut key = vec![ALG_HMAC_SHA1];
    key.extend_from_slice(&CODE);
    let mut set = tlv(TAG_KEY, &key);
    set.extend(tlv(TAG_CHALLENGE, &[1u8; 8]));
    set.extend(tlv(TAG_RESPONSE, &hmac_sha1(&CODE, &[1u8; 8])));
    assert_eq!(send(&apdu(INS_SET_CODE, 0, 0, &set)).0, Sw::OK);
    send(&select_apdu(OTHER_AID));
    let (_, body) = send(&select_apdu(OATH_AID));
    let chal = find_tag(&body, TAG_CHALLENGE as u16).unwrap().to_vec();
    let mut val = tlv(TAG_RESPONSE, &hmac_sha1(&CODE, &chal));
    val.extend(tlv(TAG_CHALLENGE, &[9u8; 8]));
    assert_eq!(send(&apdu(INS_VALIDATE, 0, 0, &val)).0, Sw::OK);
    let mut cred = put_data(b"bank", 0x21, 6, SECRET_SHA1, false, None);
    cred.extend(tlv(TAG_PWS_PASSWORD, b"s3cr3t"));
    assert_eq!(send(&apdu(INS_PUT, 0, 0, &cred)).0, Sw::OK);
    assert_eq!(
        send(&apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))).0,
        Sw::OK
    );

    send(&select_apdu(OTHER_AID));
    let (_, first) = send(&select_apdu(OATH_AID));
    assert_eq!(
        send(&apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))).0,
        Sw::OK
    );
    let (_, second) = send(&select_apdu(OATH_AID));
    assert_ne!(
        find_tag(&first, TAG_CHALLENGE as u16),
        find_tag(&second, TAG_CHALLENGE as u16),
        "a re-SELECT hands out a fresh challenge"
    );
    assert_eq!(
        send(&apdu(INS_LIST, 0, 0, &[])).0,
        Sw::OK,
        "the validation stands"
    );
    assert_eq!(
        send(&apdu(INS_GET_CREDENTIAL, 0, 0, &tlv(TAG_NAME, b"bank"))).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "the password safe closes"
    );
}

/// A code-less applet is open on every SELECT, re-SELECT included. A failed OTP PIN
/// locks the session it failed in, and the next SELECT of OATH reopens it; keeping
/// the lock through a re-SELECT would leave an applet with no code unopenable.
#[test]
fn a_reselect_reopens_a_codeless_applet_a_failed_pin_locked() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(StubPresence(Presence::Confirmed, 0));
    let mut oath = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let mut other = Other;
    let mut applets: [&mut dyn Applet<Fs<RamStorage>>; 2] = [&mut oath, &mut other];
    let mut disp = Dispatcher::default();
    let mut send = |raw: &[u8]| go(&mut disp, &mut applets, &mut fs, raw);

    assert_eq!(send(&select_apdu(OATH_AID)).0, Sw::OK);
    assert_eq!(
        send(&apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))).0,
        Sw::OK
    );
    assert_ne!(
        send(&apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, b"9999"))).0,
        Sw::OK
    );
    assert_eq!(
        send(&apdu(INS_LIST, 0, 0, &[])).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "control: the failed PIN locked this session"
    );
    assert_eq!(send(&select_apdu(OATH_AID)).0, Sw::OK);
    assert_eq!(
        send(&apdu(INS_LIST, 0, 0, &[])).0,
        Sw::OK,
        "a re-SELECT must reopen an applet with no access code"
    );
}
