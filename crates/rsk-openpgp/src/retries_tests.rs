// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! SET PIN RETRIES (INS `F2`) as a YubiKey 5.8.0 answers it, measured 2026-09-30: PW3
//! sets how many tries PW1, the resetting code and PW3 each get, and gives each that
//! many, a blocked PIN included; a byte of 0 leaves its PIN as it is.

use super::*;
use rsk_fs::storage::faults::{Cut, ProbeStuck};
use rsk_fs::storage::ram::RamStorage;
use rsk_sdk::Dispatcher;

const SERIAL_ID: [u8; 8] = [0xAA, 0xBB, 0xCC, 0xDD, 5, 6, 7, 8];
const SERIAL_HASH: [u8; 32] = [0x22; 32];

const SELECT: &[u8] = &[
    0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
];
const TERMINATE: &[u8] = &[0x00, 0xE6, 0x00, 0x00];
const ACTIVATE: &[u8] = &[0x00, 0x44, 0x00, 0x00];
const GET_PW_STATUS: &[u8] = &[0x00, 0xCA, 0x00, 0xC4, 0x00];
const RESET_CODE: &[u8] = b"87654321";
const WRONG_PW: &[u8] = b"99999999";

struct CountRng(u8);
impl Rng for CountRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

fn dev() -> Device<'static> {
    Device {
        serial_hash: &SERIAL_HASH,
        serial_id: &SERIAL_ID,
        otp_key: None,
        latched: false,
    }
}

/// A store as the boot leaves it: scanned, and the applet's files seeded.
fn boot<S: Storage>(storage: S) -> Fs<S> {
    let mut fs = Fs::new(storage);
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    fs
}

fn command(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut apdu = vec![0x00, ins, p1, p2];
    if !data.is_empty() {
        apdu.push(data.len() as u8);
        apdu.extend_from_slice(data);
    }
    apdu
}

fn verify(mode: u8, pw: &[u8]) -> Vec<u8> {
    command(consts::INS_VERIFY, 0x00, mode, pw)
}

fn set_retries(p1: u8, p2: u8, body: &[u8]) -> Vec<u8> {
    command(consts::INS_SET_RETRIES, p1, p2, body)
}

/// One card: the applet and a dispatcher over `fs`. A new one over the same store is a
/// power cycle.
struct Card<'a> {
    app: OpenpgpApplet<'a>,
    disp: Dispatcher,
}

impl<'a> Card<'a> {
    fn new(rng: &'a RefCell<CountRng>, presence: &'a RefCell<crate::AlwaysConfirm>) -> Self {
        Self {
            app: OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, rng, presence),
            disp: Dispatcher::default(),
        }
    }

    fn send<S: Storage>(&mut self, fs: &mut Fs<S>, raw: &[u8]) -> (Vec<u8>, Sw) {
        let mut buf = [0u8; rsk_sdk::applet::RESP_BUILD];
        let mut res = ResBuf::new(&mut buf);
        let mut applets: [&mut dyn rsk_sdk::Applet<Fs<S>>; 1] = [&mut self.app];
        let sw = self.disp.process(raw, &mut applets, fs, &mut res);
        (res.as_slice().to_vec(), sw)
    }

    fn sw<S: Storage>(&mut self, fs: &mut Fs<S>, raw: &[u8]) -> Sw {
        self.send(fs, raw).1
    }

    /// C4's three counters: PW1's, the resetting code's and PW3's tries left.
    fn counters<S: Storage>(&mut self, fs: &mut Fs<S>) -> [u8; 3] {
        let (c4, sw) = self.send(fs, GET_PW_STATUS);
        assert_eq!(sw, Sw::OK, "GET DATA C4");
        [c4[4], c4[5], c4[6]]
    }
}

/// The maxima record, `[01, PW1, RC, PW3]`.
fn maxima<S: Storage>(fs: &mut Fs<S>) -> [u8; 3] {
    let mut rec = [0u8; 4];
    assert_eq!(fs.read(consts::EF_PW_RETRIES, &mut rec), Some(4));
    [rec[1], rec[2], rec[3]]
}

/// PW3 or nothing (`6982`), then exactly three bytes (`6A80` for 0, 2 or 4) with P1
/// and P2 not judged. Each byte 1..=255 is that PIN's tries, 0 leaves it; with no
/// resetting code set its counter stays 0. PW3 stays verified, and a power cycle
/// keeps the new maxima, which a wrong PIN then counts down from and a right one
/// restores.
#[test]
fn set_pin_retries_answers_as_a_yubikey_does() {
    let rng = RefCell::new(CountRng(0));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut fs = boot(RamStorage::new());
    let mut card = Card::new(&rng, &presence);
    assert_eq!(card.sw(&mut fs, SELECT), Sw::OK);
    let refused = card.sw(&mut fs, &set_retries(0, 0, &[5, 6, 7]));
    assert_eq!(refused, Sw::SECURITY_STATUS_NOT_SATISFIED, "no PW3");
    assert_eq!(card.counters(&mut fs), [3, 0, 3]);
    assert_eq!(card.sw(&mut fs, &verify(0x83, consts::PW3_DEFAULT)), Sw::OK);
    for body in [&[][..], &[5, 6], &[5, 6, 7, 8]] {
        let sw = card.sw(&mut fs, &set_retries(0, 0, body));
        assert_eq!(sw, Sw::WRONG_DATA, "a body of {} bytes", body.len());
    }
    assert_eq!(
        card.counters(&mut fs),
        [3, 0, 3],
        "the refusals changed nothing"
    );
    // ((P1, P2), body, C4's three counters after it), in the probe's order.
    type Row = ((u8, u8), [u8; 3], [u8; 3]);
    let rows: [Row; 9] = [
        ((1, 0), [5, 6, 7], [5, 0, 7]),
        ((0, 1), [3, 3, 3], [3, 0, 3]),
        ((0, 0), [0, 0, 0], [3, 0, 3]),
        ((0, 0), [0, 6, 7], [3, 0, 7]),
        ((0, 0), [1, 1, 1], [1, 0, 1]),
        ((0, 0), [0xFF; 3], [0xFF, 0, 0xFF]),
        ((0, 0), [99; 3], [99, 0, 99]),
        ((0, 0), [100; 3], [100, 0, 100]),
        ((0, 0), [5, 6, 7], [5, 0, 7]),
    ];
    for ((p1, p2), body, want) in rows {
        let sw = card.sw(&mut fs, &set_retries(p1, p2, &body));
        assert_eq!(sw, Sw::OK, "F2 {p1:02X} {p2:02X} {body:02X?}");
        assert_eq!(card.counters(&mut fs), want, "C4 after {body:02X?}");
    }
    assert_eq!(
        maxima(&mut fs),
        [5, 6, 7],
        "the RC's maximum is kept without an RC"
    );
    assert_eq!(
        card.sw(&mut fs, &verify(0x83, &[])),
        Sw::OK,
        "PW3 still verified"
    );

    drop(card);
    let mut card = Card::new(&rng, &presence);
    assert_eq!(card.sw(&mut fs, SELECT), Sw::OK);
    assert_eq!(card.counters(&mut fs), [5, 0, 7], "after a power cycle");
    assert_eq!(
        card.sw(&mut fs, &verify(0x81, WRONG_PW)),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(
        card.sw(&mut fs, &verify(0x83, WRONG_PW)),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(card.counters(&mut fs), [4, 0, 6], "one wrong try each");
    assert_eq!(card.sw(&mut fs, &verify(0x81, consts::PW1_DEFAULT)), Sw::OK);
    assert_eq!(card.sw(&mut fs, &verify(0x83, consts::PW3_DEFAULT)), Sw::OK);
    assert_eq!(
        card.counters(&mut fs),
        [5, 0, 7],
        "the PINs unchanged, their maxima back"
    );
}

/// The admin reference's command: PW1 verified in both modes does not stand in for
/// PW3. Not measured on the YubiKey, which was probed with nothing verified.
#[test]
fn set_pin_retries_takes_no_user_status_for_the_admins() {
    let rng = RefCell::new(CountRng(0));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut fs = boot(RamStorage::new());
    let mut card = Card::new(&rng, &presence);
    assert_eq!(card.sw(&mut fs, SELECT), Sw::OK);
    card.sw(&mut fs, &verify(0x83, WRONG_PW));
    assert_eq!(card.counters(&mut fs), [3, 0, 2]);
    assert_eq!(card.sw(&mut fs, &verify(0x81, consts::PW1_DEFAULT)), Sw::OK);
    assert_eq!(card.sw(&mut fs, &verify(0x82, consts::PW1_DEFAULT)), Sw::OK);
    let sw = card.sw(&mut fs, &set_retries(0, 0, &[5, 6, 7]));
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED, "PW1 alone");
    assert_eq!(
        card.counters(&mut fs),
        [3, 0, 2],
        "PW3's spent try stays spent"
    );
}

/// Each byte sets the count to the maximum it sets, whatever count stood before: a
/// lowered maximum over a spent count takes the count to it, not to the maximum it
/// replaces (the measured `F2 01 01 01` gives `C4 01 00 01`).
#[test]
fn a_lowered_maximum_takes_a_spent_count_to_itself() {
    let rng = RefCell::new(CountRng(0));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut fs = boot(RamStorage::new());
    let mut card = Card::new(&rng, &presence);
    assert_eq!(card.sw(&mut fs, SELECT), Sw::OK);
    card.sw(&mut fs, &verify(0x81, WRONG_PW));
    assert_eq!(card.counters(&mut fs), [2, 0, 3]);
    assert_eq!(card.sw(&mut fs, &verify(0x83, consts::PW3_DEFAULT)), Sw::OK);
    assert_eq!(card.sw(&mut fs, &set_retries(0, 0, &[1, 0, 0])), Sw::OK);
    assert_eq!(
        card.counters(&mut fs),
        [1, 0, 3],
        "PW1's count is its new maximum"
    );
    assert_eq!(maxima(&mut fs), [1, 3, 3]);
}

/// A PIN spent to zero is given its tries back, and the value it had still verifies.
#[test]
fn set_pin_retries_unblocks_a_blocked_pin() {
    let rng = RefCell::new(CountRng(0));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut fs = boot(RamStorage::new());
    let mut card = Card::new(&rng, &presence);
    assert_eq!(card.sw(&mut fs, SELECT), Sw::OK);
    for _ in 0..3 {
        card.sw(&mut fs, &verify(0x81, WRONG_PW));
    }
    assert_eq!(card.counters(&mut fs), [0, 0, 3]);
    assert_eq!(
        card.sw(&mut fs, &verify(0x81, consts::PW1_DEFAULT)),
        Sw::PIN_BLOCKED
    );
    assert_eq!(card.sw(&mut fs, &verify(0x83, consts::PW3_DEFAULT)), Sw::OK);
    assert_eq!(card.sw(&mut fs, &set_retries(0, 0, &[5, 6, 7])), Sw::OK);
    assert_eq!(card.counters(&mut fs), [5, 0, 7]);
    assert_eq!(card.sw(&mut fs, &verify(0x81, consts::PW1_DEFAULT)), Sw::OK);
}

/// The resetting code's maximum waits for a resetting code: PUT DATA D3 starts it
/// there, F2 moves it from then on, and a wrong one counts down from it.
#[test]
fn the_reset_code_takes_the_maximum_set_before_it() {
    let rng = RefCell::new(CountRng(0));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut fs = boot(RamStorage::new());
    let mut card = Card::new(&rng, &presence);
    assert_eq!(card.sw(&mut fs, SELECT), Sw::OK);
    assert_eq!(card.sw(&mut fs, &verify(0x83, consts::PW3_DEFAULT)), Sw::OK);
    assert_eq!(card.sw(&mut fs, &set_retries(0, 0, &[5, 6, 7])), Sw::OK);
    assert_eq!(card.counters(&mut fs), [5, 0, 7]);
    let put_rc = command(consts::INS_PUT_DATA, 0x00, 0xD3, RESET_CODE);
    assert_eq!(card.sw(&mut fs, &put_rc), Sw::OK);
    assert_eq!(card.counters(&mut fs), [5, 6, 7], "PUT DATA D3");
    assert_eq!(card.sw(&mut fs, &set_retries(0, 0, &[0, 4, 0])), Sw::OK);
    assert_eq!(card.counters(&mut fs), [5, 4, 7], "F2 00 04 00");
    let wrong_rc = [WRONG_PW, consts::PW1_DEFAULT].concat();
    let reset = command(consts::INS_RESET_RETRY, 0x00, 0x81, &wrong_rc);
    assert_eq!(card.sw(&mut fs, &reset), Sw::SECURITY_STATUS_NOT_SATISFIED);
    assert_eq!(card.counters(&mut fs), [5, 3, 7], "a wrong resetting code");
}

/// TERMINATE DF and ACTIVATE FILE give back the factory 3/3/3, as on a YubiKey 5.8.0.
#[test]
fn terminate_and_activate_restore_the_factory_maxima() {
    let rng = RefCell::new(CountRng(0));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut fs = boot(RamStorage::new());
    let mut card = Card::new(&rng, &presence);
    assert_eq!(card.sw(&mut fs, SELECT), Sw::OK);
    assert_eq!(card.sw(&mut fs, &verify(0x83, consts::PW3_DEFAULT)), Sw::OK);
    assert_eq!(card.sw(&mut fs, &set_retries(0, 0, &[5, 6, 7])), Sw::OK);
    assert_eq!(card.sw(&mut fs, TERMINATE), Sw::OK);
    assert_eq!(card.sw(&mut fs, ACTIVATE), Sw::OK);
    assert_eq!(card.counters(&mut fs), [3, 0, 3]);
    assert_eq!(maxima(&mut fs), [3, 3, 3]);
    assert_eq!(
        card.sw(&mut fs, &verify(0x81, WRONG_PW)),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(card.counters(&mut fs), [2, 0, 3]);
}

/// Fewer tries is what a cut may leave, never more: the counters land before the
/// maxima, so a lowered PIN is never found with its old tries under its new maximum.
#[test]
fn a_cut_never_leaves_a_lowered_pin_its_old_tries() {
    let rng = RefCell::new(CountRng(0));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let setup = || {
        let (cut, medium) = Cut::new();
        let mut fs = boot(cut);
        let mut card = Card::new(&rng, &presence);
        assert_eq!(card.sw(&mut fs, SELECT), Sw::OK);
        assert_eq!(card.sw(&mut fs, &verify(0x83, consts::PW3_DEFAULT)), Sw::OK);
        assert_eq!(card.sw(&mut fs, &set_retries(0, 0, &[10, 0, 10])), Sw::OK);
        medium.clear_ops();
        (card, fs, medium)
    };
    let lower = set_retries(0, 0, &[2, 0, 2]);
    let total = {
        let (mut card, mut fs, medium) = setup();
        assert_eq!(card.sw(&mut fs, &lower), Sw::OK, "fixture");
        medium.ops().len() as u32
    };
    assert!(total > 1, "fixture: nothing to cut");
    for budget in 0..=total {
        let (mut card, mut fs, medium) = setup();
        medium.arm(budget);
        card.sw(&mut fs, &lower);
        medium.arm(u32::MAX);
        drop(card);
        let mut fs = boot(fs.into_storage());
        let mut card = Card::new(&rng, &presence);
        assert_eq!(card.sw(&mut fs, SELECT), Sw::OK);
        let (left, max) = (card.counters(&mut fs), maxima(&mut fs));
        let at = format!("cut after {budget} of {total}: C4 {left:?}, maxima {max:?}");
        assert!(left == [10, 0, 10] || left == [2, 0, 2], "{at}");
        assert!(max == [10, 3, 10] || max == [2, 3, 2], "{at}");
        assert!(
            max == [10, 3, 10] || left == [2, 0, 2],
            "{at}: the maxima landed first"
        );
    }
}

/// A maxima record the flash would not read is not written over: F2 answers `6581`
/// and changes nothing.
#[test]
fn an_unreadable_maxima_record_changes_nothing() {
    let rng = RefCell::new(CountRng(0));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let (probe, medium) = ProbeStuck::new();
    let mut fs = boot(probe);
    let mut card = Card::new(&rng, &presence);
    assert_eq!(card.sw(&mut fs, SELECT), Sw::OK);
    assert_eq!(card.sw(&mut fs, &verify(0x83, consts::PW3_DEFAULT)), Sw::OK);
    medium.stick(Some(consts::EF_PW_RETRIES));
    let sw = card.sw(&mut fs, &set_retries(0, 0, &[5, 6, 7]));
    medium.stick(None);
    assert_eq!(sw, Sw::MEMORY_FAILURE);
    assert_eq!(card.counters(&mut fs), [3, 0, 3]);
    assert_eq!(maxima(&mut fs), [3, 3, 3]);
}
