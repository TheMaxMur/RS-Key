// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! OpenPGP 3.4.1 §4.2 / §7.2.2: a verified PW survives everything but "a RESET of
//! the card, a SELECT to a **different** DF or an internal resetting". Driven
//! through the real [`Dispatcher`], which is what decides an AID is this applet's
//! and whether that makes the SELECT a re-SELECT.

use super::*;
use rsk_fs::storage::ram::RamStorage;
use rsk_sdk::Dispatcher;

const SERIAL_ID: [u8; 8] = [0xAA, 0xBB, 0xCC, 0xDD, 5, 6, 7, 8];
const SERIAL_HASH: [u8; 32] = [0x22; 32];
const PIV_AID: &[u8] = &[
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
];

struct CountRng(u8);
impl Rng for CountRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

/// A second applet, so "SELECT a different valid AID" is expressible.
struct Other;
impl Applet<Fs<RamStorage>> for Other {
    fn aid(&self) -> &'static [u8] {
        PIV_AID
    }
    fn select(&mut self, _reselect: bool, _ctx: &mut Fs<RamStorage>, _res: &mut ResBuf) -> Sw {
        Sw::OK
    }
    fn process(&mut self, _apdu: &Apdu, _ctx: &mut Fs<RamStorage>, _res: &mut ResBuf) -> Sw {
        Sw::INS_NOT_SUPPORTED
    }
}

fn select_apdu(aid: &[u8]) -> Vec<u8> {
    let mut v = std::vec![0x00u8, 0xA4, 0x04, 0x00, aid.len() as u8];
    v.extend_from_slice(aid);
    v
}

/// All three PWs verified, then the given SELECTs, then each PW's status query.
fn status_after(sel: &[&[u8]]) -> [Sw; 3] {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    let dev = Device {
        serial_hash: &SERIAL_HASH,
        serial_id: &SERIAL_ID,
        otp_key: None,
    };
    crate::init::scan_files(&dev, &mut fs, &mut CountRng(0)).unwrap();
    let rng = RefCell::new(CountRng(0));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    let mut other = Other;
    let mut applets: [&mut dyn Applet<Fs<RamStorage>>; 2] = [&mut app, &mut other];
    let mut disp = Dispatcher::default();

    let mut go = |applets: &mut [&mut dyn Applet<Fs<RamStorage>>], raw: &[u8]| {
        let mut out = [0u8; 512];
        let mut res = ResBuf::new(&mut out);
        disp.process(raw, applets, &mut fs, &mut res)
    };
    assert_eq!(
        go(&mut applets, &select_apdu(consts::OPENPGP_AID)),
        Sw::OK,
        "SELECT OpenPGP"
    );
    for (p2, pw) in [
        (0x81u8, &b"123456"[..]),
        (0x82, b"123456"),
        (0x83, b"12345678"),
    ] {
        let mut v = std::vec![0x00u8, 0x20, 0x00, p2, pw.len() as u8];
        v.extend_from_slice(pw);
        assert_eq!(go(&mut applets, &v), Sw::OK, "VERIFY {p2:02X}");
    }
    for aid in sel {
        go(&mut applets, &select_apdu(aid));
    }
    [0x81u8, 0x82, 0x83].map(|p2| go(&mut applets, &[0x00, 0x20, 0x00, p2]))
}

#[test]
fn a_reselect_of_the_openpgp_aid_keeps_the_verified_pws() {
    let armed = [Sw::OK; 3];
    let cleared = [Sw::retries(3); 3];

    assert_eq!(status_after(&[]), armed, "control: nothing intervened");
    assert_eq!(
        status_after(&[consts::OPENPGP_AID]),
        armed,
        "a re-SELECT of the same AID is not a SELECT to a different DF"
    );
    assert_eq!(
        status_after(&[&consts::OPENPGP_AID[..5]]),
        armed,
        "nor is a right-truncated one — measured on a YubiKey 5.7.4"
    );
    assert_eq!(
        status_after(&[&[0xD2, 0x76, 0x00, 0x99]]),
        armed,
        "an AID the ICC does not support never reaches an applet"
    );
    // The one SELECT that MUST still clear, through the dispatcher's `deselect`.
    assert_eq!(
        status_after(&[PIV_AID, consts::OPENPGP_AID]),
        cleared,
        "another application's AID must clear all three"
    );
}
