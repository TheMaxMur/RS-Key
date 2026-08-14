// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! SP 800-73-4 Part 2 §3.1.1: which SELECT keeps the PIV security status and
//! which clears it. Driven through the real [`Dispatcher`] — it is the dispatcher
//! that decides an AID is this applet's and whether that is a re-SELECT, so a
//! test calling `Applet::select` directly would be choosing the answer itself.

use super::*;
use rsk_fs::storage::ram::RamStorage;
use rsk_sdk::Dispatcher;

const SERIAL: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const HASH: [u8; 32] = [0x22; 32];
const DEFAULT_PIN: [u8; 8] = [b'1', b'2', b'3', b'4', b'5', b'6', 0xFF, 0xFF];
const DEFAULT_MGM: [u8; 24] = [
    1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
];

struct TestRng(u64);
impl Rng for TestRng {
    fn fill(&mut self, b: &mut [u8]) {
        for x in b.iter_mut() {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *x = (self.0 >> 33) as u8;
        }
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

/// A second applet, so "SELECT a different valid AID" is expressible.
struct Other;
impl Applet<Fs<RamStorage>> for Other {
    fn aid(&self) -> &'static [u8] {
        &[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]
    }
    fn select(&mut self, _reselect: bool, _ctx: &mut Fs<RamStorage>, _res: &mut ResBuf) -> Sw {
        Sw::OK
    }
    fn process(&mut self, _apdu: &Apdu, _ctx: &mut Fs<RamStorage>, _res: &mut ResBuf) -> Sw {
        Sw::INS_NOT_SUPPORTED
    }
}

/// PIN verified + management key authenticated, then one intervening SELECT, then
/// both statuses read back. `(PIN status, management-gated PUT DATA)`, where
/// `6A80` means the PUT passed the auth check and failed on its bogus object and
/// `6982` means the management status is gone.
fn status_after(sel: &[&[u8]]) -> (Sw, Sw) {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut piv = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut other = Other;
    let mut applets: [&mut dyn Applet<Fs<RamStorage>>; 2] = [&mut piv, &mut other];
    let mut disp = Dispatcher::default();

    assert_eq!(
        go(&mut disp, &mut applets, &mut fs, &select_apdu(PIV_AID)).0,
        Sw::OK
    );
    let mut verify = vec![0x00u8, 0x20, 0x00, 0x80, DEFAULT_PIN.len() as u8];
    verify.extend_from_slice(&DEFAULT_PIN);
    assert_eq!(go(&mut disp, &mut applets, &mut fs, &verify).0, Sw::OK);

    // Management-key mutual auth (AES-192, the default key).
    let (sw, wit) = go(
        &mut disp,
        &mut applets,
        &mut fs,
        &[
            0x00,
            0x87,
            ALGO_AES192,
            0x9B,
            0x04,
            0x7C,
            0x02,
            0x80,
            0x00,
            0x00,
        ],
    );
    assert_eq!(sw, Sw::OK);
    let mut w: [u8; 16] = wit[4..20].try_into().unwrap();
    rsk_crypto::aes_ecb_decrypt_block(&DEFAULT_MGM, &mut w).unwrap();
    let mut step2 = vec![
        0x00u8,
        0x87,
        ALGO_AES192,
        0x9B,
        0x26,
        0x7C,
        0x24,
        0x80,
        0x10,
    ];
    step2.extend_from_slice(&w);
    step2.extend_from_slice(&[0x81, 0x10]);
    step2.extend_from_slice(&[0xA5; 16]);
    step2.push(0x00);
    assert_eq!(go(&mut disp, &mut applets, &mut fs, &step2).0, Sw::OK);

    for aid in sel {
        go(&mut disp, &mut applets, &mut fs, &select_apdu(aid));
    }

    let pin = go(&mut disp, &mut applets, &mut fs, &[0x00, 0x20, 0x00, 0x80]).0;
    let put = go(
        &mut disp,
        &mut applets,
        &mut fs,
        &[0x00, 0xDB, 0x3F, 0xFF, 0x03, 0x5C, 0x01, 0x99],
    )
    .0;
    (pin, put)
}

#[test]
fn a_reselect_of_the_piv_aid_keeps_the_security_status() {
    let armed = (Sw::OK, Sw::WRONG_DATA);
    let cleared = (Sw::retries(3), Sw::SECURITY_STATUS_NOT_SATISFIED);

    assert_eq!(status_after(&[]), armed, "control: nothing intervened");
    // §3.1.1: the AID "or the right-truncated version thereof" — a fix matching
    // only the full value fails the second row, and both are what a YubiKey does.
    assert_eq!(
        status_after(&[PIV_AID]),
        armed,
        "a re-SELECT of the full PIV AID must change nothing"
    );
    assert_eq!(
        status_after(&[&PIV_AID[..9]]),
        armed,
        "a re-SELECT of a right-truncated PIV AID must change nothing"
    );
    // "an invalid AID not supported by the ICC" — the status stays too, and the
    // dispatcher gets there on its own by never reaching an applet.
    assert_eq!(
        status_after(&[&[0xA0, 0x00, 0x00, 0x03, 0x08, 0x99]]),
        armed,
        "an unsupported AID must leave PIV selected and armed"
    );
    // The one SELECT that MUST still clear: a different valid AID.
    assert_eq!(
        status_after(&[&[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01], PIV_AID]),
        cleared,
        "another application's AID must clear the security status"
    );
}
