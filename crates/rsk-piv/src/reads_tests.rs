// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Each PIV command with every flash read it makes failed in turn — the read half
//! of the fault sweep ([`rsk_fs::probe::sweep`]).

use super::*;
use rsk_fs::probe::{Excuse, Traced, sweep};

const OWNER_PIN: [u8; 8] = *b"48162900";
const OWNER_PUK: [u8; 8] = *b"73915400";

/// An applet over its own randomness and presence. Leaked: the applet borrows
/// them for the whole run, and a run is one sweep step.
fn applet() -> PivApplet<'static> {
    let rng: &'static RefCell<TestRng> = Box::leak(Box::new(RefCell::new(TestRng(7))));
    let pres: &'static RefCell<AlwaysConfirm> = Box::leak(Box::new(RefCell::new(AlwaysConfirm)));
    PivApplet::new(SERIAL, HASH, None, rng, pres)
}

fn change(app: &mut PivApplet, fs: &mut Fs<Traced>, p2: u8, old: &[u8], new: &[u8; 8]) {
    let mut msg = old.to_vec();
    msg.extend_from_slice(new);
    assert_eq!(run(app, fs, INS_CHANGE_PIN, 0, p2, &msg).0, Sw::OK);
}

/// A card its owner took over: PIN and PUK off their published defaults.
fn owned(fs: &mut Fs<Traced>) -> PivApplet<'static> {
    fs.scan();
    let mut app = applet();
    select(&mut app, fs);
    change(&mut app, fs, 0x80, &DEFAULT_PIN, &OWNER_PIN);
    change(&mut app, fs, 0x81, &DEFAULT_PUK, &OWNER_PUK);
    app
}

/// The same card on a fresh connection: a new applet session, SELECTed.
fn reconnected(fs: &mut Fs<Traced>) -> PivApplet<'static> {
    owned(fs);
    let mut app = applet();
    select(&mut app, fs);
    app
}

fn sends(
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
) -> impl Fn(&mut Fs<Traced>, &mut PivApplet<'static>) -> Option<Vec<u8>> {
    let data = data.to_vec();
    move |fs, app| answer(run(app, fs, ins, p1, p2, &data))
}

/// A command's response when it answered `9000`.
fn answer((sw, body): (Sw, Vec<u8>)) -> Option<Vec<u8>> {
    (sw == Sw::OK).then_some(body)
}

/// SELECT on a fresh connection runs the boot-time file scan; one faulted probe of
/// the PIN record there once re-seeded the factory PIN over the owner's (0x0995).
/// The PIN is then presented, so a re-seed that only lands in the cache shows too.
#[test]
fn no_faulted_read_at_select_reseeds_a_default_over_the_owners() {
    sweep(
        |fs| {
            owned(fs);
            applet()
        },
        |fs, app| {
            let mut out = [0u8; 256];
            let mut res = ResBuf::new(&mut out);
            if Applet::select(app, false, fs, &mut res) != Sw::OK {
                return None;
            }
            answer(run(app, fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN))
        },
        &[],
    );
}

#[test]
fn a_faulted_read_fails_a_verify_or_answers_it_as_clean() {
    sweep(reconnected, sends(INS_VERIFY, 0, 0x80, &OWNER_PIN), &[]);
}

/// A wrong PIN is refused, fault or no fault. Whether a fault can refund its retry
/// is not this sweep's to judge (an unspent retry is also the state before the
/// spend): the dying-write tests hold that ordering.
#[test]
fn no_faulted_read_admits_the_wrong_pin() {
    sweep(reconnected, sends(INS_VERIFY, 0, 0x80, &DEFAULT_PIN), &[]);
}

#[test]
fn a_faulted_read_fails_a_pin_change_or_lands_it_whole() {
    let mut msg = OWNER_PIN.to_vec();
    msg.extend_from_slice(b"55555555");
    sweep(reconnected, sends(INS_CHANGE_PIN, 0, 0x80, &msg), &[]);
}

/// A blocked PIN reset with the PUK; the wrong PUK is refused and spends one.
#[test]
fn a_faulted_read_fails_an_unblock_or_lands_it_whole() {
    for puk in [OWNER_PUK, DEFAULT_PUK] {
        let mut msg = puk.to_vec();
        msg.extend_from_slice(b"55555555");
        sweep(
            |fs| {
                let mut app = reconnected(fs);
                while run(&mut app, fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN).0 != Sw::PIN_BLOCKED {}
                app
            },
            sends(INS_RESET_RETRY, 0, 0x80, &msg),
            &[],
        );
    }
}

fn authenticated(fs: &mut Fs<Traced>) -> PivApplet<'static> {
    let mut app = reconnected(fs);
    auth_mgm(&mut app, fs);
    app
}

/// GENERATE over an authenticated session. The one excused read is the slot head's
/// own: [`keygen::meta_add_slot`] stores the head alone when the record with its
/// cached point is refused, whatever refused it — the point is a cache GET METADATA
/// derives, and the head is what the new key cannot be used without.
#[test]
fn a_faulted_read_fails_a_generate_or_lands_it_whole() {
    sweep(
        authenticated,
        sends(INS_ASYM_KEYGEN, 0x00, 0x9A, &gen_template(ALGO_ECCP256)),
        &[(
            rsk_fs::EF_META,
            2,
            "a refused head-and-point record falls back to the head",
        )],
    );
}

/// SET MANAGEMENT KEY over an authenticated session, the same algorithm and
/// another. The one excused read is the rewrite of the head, a cache of the record
/// that carries the key with its algorithm: `mgmkey_tests` hold what authenticates.
/// PUT DATA is not swept: it reads nothing, which the sweep refuses as vacuous.
#[test]
fn a_faulted_read_fails_a_management_key_change_or_lands_it_whole() {
    let stale: &[Excuse] = &[(
        rsk_fs::EF_META,
        2,
        "a refused head rewrite leaves the cache stale behind the record's 9000",
    )];
    for (algo, len, excused) in [(ALGO_AES192, 24u8, &[][..]), (ALGO_AES256, 32, stale)] {
        let mut set_key = vec![algo, SLOT_CARDMGM, len];
        set_key.extend(std::iter::repeat_n(0x5A, usize::from(len)));
        sweep(
            authenticated,
            sends(INS_SET_MGMKEY, 0xFF, 0xFF, &set_key),
            excused,
        );
    }
}
