// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! TERMINATE DF and ACTIVATE FILE as a YubiKey 5.8.0 runs them: a terminated applet
//! answers `6285` to every command, SELECT included and across a power cycle, until
//! ACTIVATE FILE puts the factory state back.

use super::*;
use rsk_fs::storage::faults::{Cut, CutMedium, ProbeStuck};
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
const GET_LOGIN: &[u8] = &[0x00, 0xCA, 0x00, 0x5E, 0x00];
const PUT_LOGIN: &[u8] = &[0x00, 0xDA, 0x00, 0x5E, 0x05, b'a', b'l', b'i', b'c', b'e'];
const GET_PRIVATE_3: &[u8] = &[0x00, 0xCA, 0x01, 0x03, 0x00];
const GET_CHALLENGE: &[u8] = &[0x00, 0x84, 0x00, 0x00, 0x08];
/// C4 on a factory card: PW1 valid for one PSO:CDS, the three maximum lengths, the
/// counters 3, 0 (no reset code) and 3.
const C4_FACTORY: &[u8] = &[0x01, 0x7F, 0x7F, 0x7F, 0x03, 0x00, 0x03];

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

fn verify(mode: u8, pw: &[u8]) -> Vec<u8> {
    let mut apdu = vec![0x00, consts::INS_VERIFY, 0x00, mode, pw.len() as u8];
    apdu.extend_from_slice(pw);
    apdu
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
}

/// TERMINATE DF takes PW3 and leaves every command answering `6285`, the SELECT that
/// follows a power cycle included, until ACTIVATE FILE: that answers `9000` and leaves
/// the factory state, a no-op on an applet that was never terminated.
#[test]
fn a_terminated_applet_answers_6285_to_everything_until_activate() {
    let rng = RefCell::new(CountRng(0));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut fs = boot(RamStorage::new());
    let mut card = Card::new(&rng, &presence);
    assert_eq!(card.send(&mut fs, SELECT).1, Sw::OK);
    assert_eq!(
        card.send(&mut fs, TERMINATE).1,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(
        card.send(&mut fs, &verify(0x83, consts::PW3_DEFAULT)).1,
        Sw::OK
    );
    assert_eq!(card.send(&mut fs, PUT_LOGIN).1, Sw::OK);
    // Not terminated, ACTIVATE is a no-op: the login data stays.
    assert_eq!(card.send(&mut fs, ACTIVATE), (vec![], Sw::OK));
    assert_eq!(card.send(&mut fs, GET_LOGIN), (b"alice".to_vec(), Sw::OK));
    assert_eq!(card.send(&mut fs, TERMINATE), (vec![], Sw::OK));

    let refused: [(&str, &[u8]); 7] = [
        ("GET DATA C4", GET_PW_STATUS),
        ("GET DATA 5E", GET_LOGIN),
        ("PUT DATA 5E", PUT_LOGIN),
        ("VERIFY PW3", &verify(0x83, consts::PW3_DEFAULT)),
        ("GET CHALLENGE", GET_CHALLENGE),
        ("TERMINATE DF", TERMINATE),
        ("SELECT", SELECT),
    ];
    for (name, apdu) in refused {
        assert_eq!(card.send(&mut fs, apdu), (vec![], Sw::TERMINATED), "{name}");
    }

    // A power cycle keeps it terminated: a new applet and dispatcher, the same store.
    drop(card);
    let mut card = Card::new(&rng, &presence);
    let mut fs = boot(fs.into_storage());
    assert_eq!(card.send(&mut fs, SELECT), (vec![], Sw::TERMINATED));
    assert_eq!(card.send(&mut fs, GET_PW_STATUS), (vec![], Sw::TERMINATED));
    assert_eq!(card.send(&mut fs, ACTIVATE), (vec![], Sw::OK));
    assert_eq!(
        card.send(&mut fs, GET_PW_STATUS),
        (C4_FACTORY.to_vec(), Sw::OK)
    );
    assert_eq!(card.send(&mut fs, GET_LOGIN), (vec![], Sw::OK));
    assert_eq!(card.send(&mut fs, SELECT), (vec![], Sw::OK));
    assert!(
        !fs.has_data(consts::EF_TERMINATED),
        "the marker outlived ACTIVATE"
    );
}

/// A YubiKey 5.8.0 keeps PW1's and PW3's verified status across TERMINATE and ACTIVATE
/// in one session. Ours keeps it too, and the key each status carries is the factory
/// password's afterwards: the old password's would open nothing ACTIVATE sealed.
#[test]
fn the_verified_statuses_survive_terminate_and_activate() {
    let rng = RefCell::new(CountRng(0));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut fs = boot(RamStorage::new());
    let mut card = Card::new(&rng, &presence);
    let change = |p2: u8, old: &[u8], new: &[u8]| {
        let mut apdu = vec![
            0x00,
            consts::INS_CHANGE_PIN,
            0x00,
            p2,
            (old.len() + new.len()) as u8,
        ];
        apdu.extend_from_slice(old);
        apdu.extend_from_slice(new);
        apdu
    };
    assert_eq!(card.send(&mut fs, SELECT).1, Sw::OK);
    // Passwords of the owner's own, so a status's key is not the factory one already.
    let (pw1, pw3) = (b"654321", b"87654321");
    assert_eq!(
        card.send(&mut fs, &change(0x83, consts::PW3_DEFAULT, pw3))
            .1,
        Sw::OK
    );
    assert_eq!(
        card.send(&mut fs, &change(0x81, consts::PW1_DEFAULT, pw1))
            .1,
        Sw::OK
    );
    for (mode, pw) in [(0x81, &pw1[..]), (0x82, &pw1[..]), (0x83, &pw3[..])] {
        assert_eq!(
            card.send(&mut fs, &verify(mode, pw)).1,
            Sw::OK,
            "VERIFY {mode:02X}"
        );
    }
    assert_eq!(card.send(&mut fs, TERMINATE).1, Sw::OK);
    assert_eq!(card.send(&mut fs, ACTIVATE).1, Sw::OK);

    // No VERIFY since: PW3's status writes an admin DO, PW1's reads DO 0103…
    assert_eq!(card.send(&mut fs, PUT_LOGIN).1, Sw::OK);
    assert_eq!(card.send(&mut fs, GET_PRIVATE_3).1, Sw::OK);
    // …PW3's key opens the DEK ACTIVATE sealed, so a key generates under it…
    let p256 = [
        consts::ALGO_ECDSA,
        0x2A,
        0x86,
        0x48,
        0xCE,
        0x3D,
        0x03,
        0x01,
        0x07,
    ];
    let mut put_attr = vec![0x00, consts::INS_PUT_DATA, 0x00, 0xC1, p256.len() as u8];
    put_attr.extend_from_slice(&p256);
    assert_eq!(card.send(&mut fs, &put_attr).1, Sw::OK);
    let (public, sw) = card.send(&mut fs, &[0x00, 0x47, 0x80, 0x00, 0x02, 0xB6, 0x00, 0x00]);
    assert_eq!(sw, Sw::OK, "GENERATE under the standing PW3 status");
    assert_eq!(&public[..2], &[0x7F, 0x49]);
    // …and PW1's opens it to sign with that key.
    let mut cds = vec![0x00, consts::INS_PSO, 0x9E, 0x9A, 0x20];
    cds.extend_from_slice(&[0x42; 32]);
    cds.push(0x00);
    assert_eq!(
        card.send(&mut fs, &cds).1,
        Sw::OK,
        "PSO:CDS under the standing PW1 status"
    );
}

/// A card with login data under a verified PW3 on a medium that can be cut. With
/// `torn`, a TERMINATE cut right after its marker, the worst case ACTIVATE meets:
/// terminated with everything still there.
fn cut_card<'a>(
    rng: &'a RefCell<CountRng>,
    presence: &'a RefCell<crate::AlwaysConfirm>,
    torn: bool,
) -> (Card<'a>, Fs<Cut>, CutMedium) {
    let (cut, medium) = Cut::new();
    let mut fs = boot(cut);
    let mut card = Card::new(rng, presence);
    card.send(&mut fs, SELECT);
    card.send(&mut fs, &verify(0x83, consts::PW3_DEFAULT));
    card.send(&mut fs, PUT_LOGIN);
    if torn {
        medium.arm(1);
        card.send(&mut fs, TERMINATE);
        medium.arm(u32::MAX);
        let mut fs = boot(fs.into_storage());
        let mut card = Card::new(rng, presence);
        assert_eq!(card.send(&mut fs, SELECT).1, Sw::TERMINATED, "fixture");
        assert_eq!(card.send(&mut fs, GET_LOGIN).1, Sw::TERMINATED, "fixture");
        return (card, fs, medium);
    }
    (card, fs, medium)
}

/// TERMINATE lands its marker FIRST and ACTIVATE FILE clears it LAST, so a cut at any
/// point of either, a power cycle after it, leaves the card as it was or terminated,
/// never active over what the wipe did not reach.
#[test]
fn a_cut_leaves_the_applet_whole_or_terminated() {
    let rng = RefCell::new(CountRng(0));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let measure = |command: &[u8], torn: bool| {
        let (mut card, mut fs, medium) = cut_card(&rng, &presence, torn);
        medium.clear_ops();
        assert_eq!(card.send(&mut fs, command).1, Sw::OK, "fixture");
        medium.ops().len() as u32
    };
    let rows = [
        (TERMINATE, false, measure(TERMINATE, false)),
        (ACTIVATE, true, measure(ACTIVATE, true)),
    ];
    for (command, torn, total) in rows {
        assert!(total > 1, "fixture: nothing to cut");
        for budget in 0..total {
            let (mut card, mut fs, medium) = cut_card(&rng, &presence, torn);
            medium.arm(budget);
            card.send(&mut fs, command);
            medium.arm(u32::MAX);

            drop(card);
            let mut card = Card::new(&rng, &presence);
            let mut fs = boot(fs.into_storage());
            let at = format!("{:02X} cut after {budget} of {total}", command[1]);
            match card.send(&mut fs, SELECT).1 {
                // Only a TERMINATE cut before its first write leaves the card as it was.
                Sw::OK => {
                    assert!(command == TERMINATE && budget == 0, "{at}: active");
                    assert_eq!(card.send(&mut fs, GET_LOGIN).0, b"alice", "{at}");
                }
                Sw::TERMINATED => {
                    assert_eq!(card.send(&mut fs, ACTIVATE).1, Sw::OK, "{at}");
                    let factory = (C4_FACTORY.to_vec(), Sw::OK);
                    assert_eq!(card.send(&mut fs, GET_PW_STATUS), factory, "{at}");
                    assert_eq!(card.send(&mut fs, GET_LOGIN).0, b"", "{at}");
                }
                sw => panic!("{at}: SELECT answered {sw:?}"),
            }
        }
    }
}

/// A marker the medium would not read is neither answer: taken for "active" the card
/// would serve what TERMINATE was wiping, taken for "terminated" an ACTIVATE would wipe
/// a live card. Every command answers `6581` until a SELECT reads the marker again.
#[test]
fn an_unreadable_marker_answers_6581_and_wipes_nothing() {
    let rng = RefCell::new(CountRng(0));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let (probe, medium) = ProbeStuck::new();
    let mut fs = boot(probe);
    let mut card = Card::new(&rng, &presence);
    assert_eq!(card.send(&mut fs, SELECT).1, Sw::OK);
    assert_eq!(
        card.send(&mut fs, &verify(0x83, consts::PW3_DEFAULT)).1,
        Sw::OK
    );
    assert_eq!(card.send(&mut fs, PUT_LOGIN).1, Sw::OK);
    assert_eq!(card.send(&mut fs, TERMINATE).1, Sw::OK);
    medium.stick(Some(consts::EF_TERMINATED));
    for (name, apdu) in [
        ("SELECT", SELECT),
        ("ACTIVATE", ACTIVATE),
        ("GET DATA C4", GET_PW_STATUS),
    ] {
        assert_eq!(
            card.send(&mut fs, apdu),
            (vec![], Sw::MEMORY_FAILURE),
            "{name}"
        );
    }
    assert!(
        medium.value(consts::EF_TERMINATED).is_some(),
        "ACTIVATE cleared the marker"
    );
    medium.stick(None);
    assert_eq!(card.send(&mut fs, SELECT).1, Sw::TERMINATED);
    assert_eq!(card.send(&mut fs, ACTIVATE).1, Sw::OK);
}

/// The marker is no data object and no record the applet's own wipe sweeps, or the
/// wipe it stands over would take it first; the device-wide wipe removes it last.
#[test]
fn the_marker_is_outside_the_sweep_and_a_gate_of_the_device_wipe() {
    assert!(!terminate::is_openpgp_fid(consts::EF_TERMINATED));
    assert!(terminate::is_openpgp_gate_fid(consts::EF_TERMINATED));
    let rng = RefCell::new(CountRng(0));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut fs = boot(RamStorage::new());
    let mut card = Card::new(&rng, &presence);
    card.send(&mut fs, SELECT);
    let get = [0x00, 0xCA, 0x10, 0xA2, 0x00];
    assert_eq!(
        card.send(&mut fs, &get).1,
        Sw::WRONG_P1P2,
        "GET DATA serves no marker"
    );
}

/// The dual-core RSA keygen runs ahead of `process`, with PW3's standing status in
/// hand, so it asks the lifecycle too: a terminated applet generates nothing there, and
/// the fall-through to `process` answers `6285`.
#[test]
fn the_rsa_keygen_fast_path_generates_nothing_on_a_terminated_applet() {
    let rng = RefCell::new(CountRng(0));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut fs = boot(RamStorage::new());
    let mut card = Card::new(&rng, &presence);
    card.send(&mut fs, SELECT);
    assert_eq!(
        card.send(&mut fs, &verify(0x83, consts::PW3_DEFAULT)).1,
        Sw::OK
    );
    let sig = [0xB6, 0x00];
    assert!(
        matches!(
            card.app.rsa_generate_params(&mut fs, 0x80, 0x00, &sig),
            Ok(Some(_))
        ),
        "fixture: the default SIG slot is RSA and PW3 is verified"
    );
    assert_eq!(card.send(&mut fs, TERMINATE).1, Sw::OK);
    assert_eq!(
        card.app.rsa_generate_params(&mut fs, 0x80, 0x00, &sig),
        Err(Sw::TERMINATED)
    );
}
