// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::init::scan_files;
use crate::pin::{change_pin, verify};
use alloc::vec;
use alloc::vec::Vec;
use rsk_fs::storage::ram::RamStorage;

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
        serial_hash: &[0x44; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    }
}

fn setup() -> (Fs<RamStorage>, Session) {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    (fs, Session::new())
}

fn admin<S: Storage>(fs: &mut Fs<S>, sess: &mut Session) {
    assert_eq!(
        verify(
            &dev(),
            fs,
            sess,
            &mut CountRng(0),
            0x00,
            PW3_MODE83,
            PW3_DEFAULT
        ),
        Sw::OK
    );
}

fn write<S: Storage>(fs: &mut Fs<S>, sess: &mut Session, body: &[u8]) -> Sw {
    put_kdf(&dev(), fs, sess, &mut CountRng(7), body)
}

/// The 8-byte user hash and admin hash `gpg` computes; their VALUES are opaque to
/// the card, so the tests only need them to be distinct and 32 bytes long.
const HASH_PW1: [u8; 32] = [0xA1; 32];
const HASH_PW3: [u8; 32] = [0xB3; 32];

/// A bare `kdf-setup`: three salts, 110 bytes.
fn three_salts() -> [u8; THREE_SALTS_LEN] {
    let mut d = [0u8; THREE_SALTS_LEN];
    d[0..3].copy_from_slice(&[0x81, 0x01, 0x03]);
    d[3..6].copy_from_slice(&[0x82, 0x01, 0x08]);
    d[6..8].copy_from_slice(&[0x83, 0x04]);
    d[12..14].copy_from_slice(&[0x84, 0x08]);
    d[22..24].copy_from_slice(&[0x85, 0x08]);
    d[32..34].copy_from_slice(&[0x86, 0x08]);
    d[42..44].copy_from_slice(&[0x87, 0x20]);
    d[44..76].copy_from_slice(&HASH_PW1);
    d[76..78].copy_from_slice(&[0x88, 0x20]);
    d[78..110].copy_from_slice(&HASH_PW3);
    d
}

/// `kdf-setup single`: one salt, 90 bytes.
fn single_salt() -> [u8; SINGLE_SALT_LEN] {
    let mut d = [0u8; SINGLE_SALT_LEN];
    d[0..3].copy_from_slice(&[0x81, 0x01, 0x03]);
    d[3..6].copy_from_slice(&[0x82, 0x01, 0x08]);
    d[6..8].copy_from_slice(&[0x83, 0x04]);
    d[12..14].copy_from_slice(&[0x84, 0x08]);
    d[22..24].copy_from_slice(&[0x87, 0x20]);
    d[24..56].copy_from_slice(&HASH_PW1);
    d[56..58].copy_from_slice(&[0x88, 0x20]);
    d[58..90].copy_from_slice(&HASH_PW3);
    d
}

/// The lockout of #104, from the reporter's side: after `kdf-setup`, `gpg` sends
/// the KDF output and never the passphrase again. Both references must take it.
#[test]
fn kdf_setup_moves_both_references_to_the_do_hashes() {
    let (mut fs, mut sess) = setup();
    admin(&mut fs, &mut sess);
    assert_eq!(write(&mut fs, &mut sess, &three_salts()), Sw::OK);

    let mut s = Session::new();
    assert_eq!(
        verify(
            &dev(),
            &mut fs,
            &mut s,
            &mut CountRng(0),
            0x00,
            PW3_MODE83,
            &HASH_PW3
        ),
        Sw::OK,
        "PW3 must verify against the 0x88 hash"
    );
    let mut s = Session::new();
    assert_eq!(
        verify(
            &dev(),
            &mut fs,
            &mut s,
            &mut CountRng(0),
            0x00,
            PW1_MODE81,
            &HASH_PW1
        ),
        Sw::OK,
        "PW1 must verify against the 0x87 hash"
    );
    // And the raw passwords are gone — a card that still took them would be
    // advertising a KDF it does not apply.
    let mut s = Session::new();
    assert_eq!(
        verify(
            &dev(),
            &mut fs,
            &mut s,
            &mut CountRng(0),
            0x00,
            PW3_MODE83,
            PW3_DEFAULT
        ),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
}

/// The DO is stored verbatim: `gpg` reads it back to learn the salt and iteration
/// count it must feed the KDF, so the card keeping only the two hashes it acted on
/// would leave every later VERIFY unable to compute what it sends.
#[test]
fn the_do_is_stored_verbatim_for_the_host_to_read_back() {
    let (mut fs, mut sess) = setup();
    admin(&mut fs, &mut sess);
    let body = three_salts();
    assert_eq!(write(&mut fs, &mut sess, &body), Sw::OK);
    let mut buf = [0u8; THREE_SALTS_LEN];
    let n = fs.read(EF_KDF, &mut buf).unwrap();
    assert_eq!(&buf[..n], &body[..]);
}

/// `kdf-setup single` shares one salt between the two references but still ships
/// both hashes; the card reads them from the shorter layout's offsets.
#[test]
fn single_salt_layout_is_accepted() {
    let (mut fs, mut sess) = setup();
    admin(&mut fs, &mut sess);
    assert_eq!(write(&mut fs, &mut sess, &single_salt()), Sw::OK);
    let mut s = Session::new();
    assert_eq!(
        verify(
            &dev(),
            &mut fs,
            &mut s,
            &mut CountRng(0),
            0x00,
            PW1_MODE81,
            &HASH_PW1
        ),
        Sw::OK
    );
}

/// The DEK travels with the references: PSO and key import unwrap it through the
/// session key a VERIFY establishes, so a re-seed that moved only the verifiers
/// would leave a card that authenticates and then cannot decrypt anything.
#[test]
fn the_dek_opens_under_both_new_references() {
    let (mut fs, mut sess) = setup();
    admin(&mut fs, &mut sess);
    assert_eq!(write(&mut fs, &mut sess, &three_salts()), Sw::OK);

    for (p2, pin) in [(PW3_MODE83, &HASH_PW3), (PW1_MODE81, &HASH_PW1)] {
        let mut s = Session::new();
        assert_eq!(
            verify(&dev(), &mut fs, &mut s, &mut CountRng(0), 0x00, p2, pin),
            Sw::OK
        );
        let mut dek = Secret::<[u8; DEK_SIZE]>::zeroed();
        assert_eq!(
            pin::load_dek(&dev(), &mut fs, &s, &mut dek),
            Ok(()),
            "the DEK must unseal under the re-seeded {p2:#04x} reference"
        );
    }
}

/// `gpg` sends `hash(old) || hash(new)`, split at the STORED length — the whole
/// reason the old code's `63C2` looked like a wrong PIN (#104): it compared the
/// first 8 bytes of a 32-byte hash.
#[test]
fn change_reference_data_works_under_kdf() {
    let (mut fs, mut sess) = setup();
    admin(&mut fs, &mut sess);
    assert_eq!(write(&mut fs, &mut sess, &three_salts()), Sw::OK);

    let new = [0xC7u8; 32];
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(&HASH_PW3);
    data[32..].copy_from_slice(&new);
    let mut s = Session::new();
    assert_eq!(
        change_pin(
            &dev(),
            &mut fs,
            &mut s,
            &mut CountRng(3),
            0x00,
            PW3_MODE83,
            &data
        ),
        Sw::OK
    );
    let mut s = Session::new();
    assert_eq!(
        verify(
            &dev(),
            &mut fs,
            &mut s,
            &mut CountRng(0),
            0x00,
            PW3_MODE83,
            &new
        ),
        Sw::OK
    );
}

/// Gnuk's `num_prv_keys` guard and the YubiKey's: with a key on the card the
/// re-seed would publish the factory passwords beside it.
#[test]
fn a_card_holding_a_key_refuses_the_do() {
    for slot in [EF_PK_SIG, EF_PK_DEC, EF_PK_AUT] {
        let (mut fs, mut sess) = setup();
        admin(&mut fs, &mut sess);
        fs.put(slot.get(), &[0xAB; 40]).unwrap();
        assert_eq!(
            write(&mut fs, &mut sess, &three_salts()),
            Sw::CONDITIONS_NOT_SATISFIED,
            "a key in {:#06x} must block the KDF DO",
            slot.get()
        );
        // Refused means untouched, both halves: the DO and the reference.
        let mut buf = [0u8; 8];
        let n = fs.read(EF_KDF, &mut buf).unwrap();
        assert_eq!(&buf[..n], KDF_OFF);
        let mut s = Session::new();
        assert_eq!(
            verify(
                &dev(),
                &mut fs,
                &mut s,
                &mut CountRng(0),
                0x00,
                PW3_MODE83,
                PW3_DEFAULT
            ),
            Sw::OK
        );
    }
}

/// Turning KDF back off puts the raw factory passwords back, because that is what
/// `gpg` starts sending again the moment the DO reads `81 01 00`.
#[test]
fn kdf_off_returns_the_references_to_the_raw_defaults() {
    let (mut fs, mut sess) = setup();
    admin(&mut fs, &mut sess);
    assert_eq!(write(&mut fs, &mut sess, &three_salts()), Sw::OK);

    let mut s = Session::new();
    assert_eq!(
        verify(
            &dev(),
            &mut fs,
            &mut s,
            &mut CountRng(0),
            0x00,
            PW3_MODE83,
            &HASH_PW3
        ),
        Sw::OK
    );
    assert_eq!(write(&mut fs, &mut s, KDF_OFF), Sw::OK);

    let mut s = Session::new();
    assert_eq!(
        verify(
            &dev(),
            &mut fs,
            &mut s,
            &mut CountRng(0),
            0x00,
            PW3_MODE83,
            PW3_DEFAULT
        ),
        Sw::OK
    );
    let mut s = Session::new();
    assert_eq!(
        verify(
            &dev(),
            &mut fs,
            &mut s,
            &mut CountRng(0),
            0x00,
            PW1_MODE81,
            PW1_DEFAULT
        ),
        Sw::OK
    );
    let mut buf = [0u8; 8];
    let n = fs.read(EF_KDF, &mut buf).unwrap();
    assert_eq!(&buf[..n], KDF_OFF, "GET DATA F9 must read back 'off'");
}

/// An empty body is refused, and the references stay where they are. Gnuk takes
/// it as the DO's delete and drops the keystrings — a silent return to `123456` /
/// `12345678` — and no host ever sends one, so this is the cheap half of strict.
#[test]
fn an_empty_body_is_refused() {
    let (mut fs, mut sess) = setup();
    admin(&mut fs, &mut sess);
    assert_eq!(write(&mut fs, &mut sess, &three_salts()), Sw::OK);
    let mut s = Session::new();
    assert_eq!(
        verify(
            &dev(),
            &mut fs,
            &mut s,
            &mut CountRng(0),
            0x00,
            PW3_MODE83,
            &HASH_PW3
        ),
        Sw::OK
    );
    assert_eq!(write(&mut fs, &mut s, &[]), Sw::WRONG_DATA);
    // The DO stands, the reference stands, and so does the session that asked.
    let mut buf = [0u8; THREE_SALTS_LEN];
    let n = fs.read(EF_KDF, &mut buf).unwrap();
    assert_eq!(&buf[..n], &three_salts()[..]);
    assert!(s.has_pw3, "a refused write must not drop the access status");
    let mut s = Session::new();
    assert_eq!(
        verify(
            &dev(),
            &mut fs,
            &mut s,
            &mut CountRng(0),
            0x00,
            PW1_MODE81,
            &HASH_PW1
        ),
        Sw::OK
    );
}

/// A body that only resembles the DO would re-seed both references from bytes at
/// guessed offsets. Every mutation of the accepted shape is refused, and the
/// references are left where they were.
#[test]
fn a_malformed_body_is_refused_and_changes_nothing() {
    let good = three_salts();
    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("one byte short", good[..THREE_SALTS_LEN - 1].to_vec()),
        ("one byte long", [&good[..], &[0][..]].concat()),
        ("between the two lengths", good[..100].to_vec()),
        ("kdf-off with a trailing byte", vec![0x81, 0x01, 0x00, 0x00]),
    ];
    // Both bytes of every field, named apart: a length byte that is not compared
    // and a tag byte that is not are different defects, and a shared label would
    // let one mutation's kill be read as the other's.
    for (name, off) in [
        (("tag 81 wrong", "length of 81 wrong"), 0usize),
        (("tag 82 wrong", "length of 82 wrong"), 3),
        (("tag 83 wrong", "length of 83 wrong"), 6),
        (("tag 84 wrong", "length of 84 wrong"), 12),
        (("tag 85 wrong", "length of 85 wrong"), 22),
        (("tag 86 wrong", "length of 86 wrong"), 32),
        (("tag 87 wrong", "length of 87 wrong"), 42),
        (("tag 88 wrong", "length of 88 wrong"), 76),
    ] {
        let mut d = good.to_vec();
        d[off] ^= 0xff;
        cases.push((name.0, d));
        let mut d = good.to_vec();
        d[off + 1] ^= 0xff; // the length byte of the same field
        cases.push((name.1, d));
    }
    for (name, body) in cases {
        let (mut fs, mut sess) = setup();
        admin(&mut fs, &mut sess);
        assert_eq!(
            write(&mut fs, &mut sess, &body),
            Sw::WRONG_DATA,
            "{name} ({} bytes) must be refused",
            body.len()
        );
        let mut buf = [0u8; 8];
        let n = fs.read(EF_KDF, &mut buf).unwrap();
        assert_eq!(&buf[..n], KDF_OFF, "{name} must leave the DO alone");
        let mut s = Session::new();
        assert_eq!(
            verify(
                &dev(),
                &mut fs,
                &mut s,
                &mut CountRng(0),
                0x00,
                PW3_MODE83,
                PW3_DEFAULT
            ),
            Sw::OK,
            "{name} must leave PW3 alone"
        );
    }
}

/// The DO is the admin's, like every other one PUT DATA writes — and the check is
/// the handler's own, not only the dispatch's, since this is a public entry point.
#[test]
fn the_do_needs_pw3() {
    let (mut fs, mut sess) = setup();
    assert_eq!(
        write(&mut fs, &mut sess, &three_salts()),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    // PW1 is not the admin, whichever mode raised it.
    for p2 in [PW1_MODE81, PW1_MODE82] {
        let mut s = Session::new();
        assert_eq!(
            verify(
                &dev(),
                &mut fs,
                &mut s,
                &mut CountRng(0),
                0x00,
                p2,
                PW1_DEFAULT
            ),
            Sw::OK
        );
        assert_eq!(
            write(&mut fs, &mut s, &three_salts()),
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );
    }
}

/// The DO carries a salt for the resetting code but no initial hash for it, so an
/// RC set under the old regime can only be deactivated — leaving it live would
/// hand `RESET RETRY` P1=0 a verifier `gpg` has stopped addressing.
#[test]
fn an_existing_reset_code_is_deactivated() {
    let (mut fs, mut sess) = setup();
    admin(&mut fs, &mut sess);
    assert_eq!(
        pin::put_reset_code(
            &dev(),
            &mut fs,
            &mut sess,
            &mut CountRng(5),
            b"reset-code-1"
        ),
        Sw::OK
    );
    assert!(fs.has_data(EF_RC));
    assert_eq!(write(&mut fs, &mut sess, &three_salts()), Sw::OK);
    assert!(!fs.has_data(EF_RC), "the RC verifier must be gone");
    assert!(!fs.has_key(EF_DEK_RC), "the RC's DEK copy must be gone");
    let mut pw = [0u8; 8];
    let n = fs.read(EF_PW_PRIV, &mut pw).unwrap();
    assert!(n > pw_retry_idx(EF_RC));
    assert_eq!(
        pw[pw_retry_idx(EF_RC)],
        0,
        "the RC counter must be deactivated"
    );
}

/// A YubiKey 5.7.4 keeps the access status across this write — measured, `PUT
/// DATA 5E` straight after `PUT DATA F9` with no re-VERIFY answers `9000`. Ours
/// keeps it too, but a status is only worth keeping if the session key under it
/// still opens the DEK, which the re-seed has just re-sealed.
#[test]
fn the_access_status_survives_and_still_opens_the_dek() {
    let (mut fs, mut sess) = setup();
    admin(&mut fs, &mut sess);
    assert_eq!(write(&mut fs, &mut sess, &three_salts()), Sw::OK);
    assert!(sess.has_pw3, "a YubiKey keeps PW3 standing here");

    let mut dek = Secret::<[u8; DEK_SIZE]>::zeroed();
    assert_eq!(
        pin::load_dek(&dev(), &mut fs, &sess, &mut dek),
        Ok(()),
        "the standing session must open the DEK the re-seal produced"
    );
    // …and the surviving status is a working one: an admin DO write goes through
    // with no re-VERIFY, which is the observable a host sees.
    assert_eq!(
        crate::putdata::put_data(&mut fs, &sess, EF_LOGIN_DATA, b"alice"),
        Sw::OK
    );
}

/// PW1's session follows the same way, so a card that had both references
/// standing does not come out of the write with one of them holding a stale key.
#[test]
fn a_standing_pw1_session_follows_the_re_seed_too() {
    let (mut fs, mut sess) = setup();
    assert_eq!(
        verify(
            &dev(),
            &mut fs,
            &mut sess,
            &mut CountRng(0),
            0x00,
            PW1_MODE81,
            PW1_DEFAULT
        ),
        Sw::OK
    );
    admin(&mut fs, &mut sess);
    assert_eq!(write(&mut fs, &mut sess, &three_salts()), Sw::OK);
    assert!(sess.has_pw1 && sess.has_pw3);
    // `load_dek` prefers the PW1 copy when PW1/PW2 stand, so this reads the one
    // that would still be sealed under the old password if PW1 had been skipped.
    let mut dek = Secret::<[u8; DEK_SIZE]>::zeroed();
    assert_eq!(pin::load_dek(&dev(), &mut fs, &sess, &mut dek), Ok(()));
}

/// The generic DO writer must not be a second way in: it stores bytes and moves
/// no reference, which is the shape of the defect (#104).
#[test]
fn the_generic_do_writer_refuses_the_kdf_tag() {
    let (mut fs, mut sess) = setup();
    admin(&mut fs, &mut sess);
    assert_eq!(
        crate::putdata::put_data(&mut fs, &sess, EF_KDF, &three_salts()),
        Sw::CONDITIONS_NOT_SATISFIED
    );
}

/// The retry counters come back with the references: a card whose PW1 was two
/// tries from blocked must not carry that budget onto a password its owner has
/// not had a chance to get wrong yet.
#[test]
fn the_retry_counters_are_restored() {
    let (mut fs, mut sess) = setup();
    let mut s = Session::new();
    assert_eq!(
        verify(
            &dev(),
            &mut fs,
            &mut s,
            &mut CountRng(0),
            0x00,
            PW1_MODE81,
            b"wrong1"
        ),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    admin(&mut fs, &mut sess);
    assert_eq!(write(&mut fs, &mut sess, &three_salts()), Sw::OK);
    let mut pw = [0u8; 8];
    let n = fs.read(EF_PW_PRIV, &mut pw).unwrap();
    assert!(n > pw_retry_idx(EF_PW3));
    assert_eq!(pw[pw_retry_idx(EF_PW1)], PW_RETRIES_DEFAULT);
    assert_eq!(pw[pw_retry_idx(EF_PW3)], PW_RETRIES_DEFAULT);
}

/// The layout table is what makes the fixed offsets safe to index; a test holds
/// the two totals so a shifted row cannot pass by moving the const assertion too.
#[test]
fn the_layouts_describe_gpgs_two_lengths() {
    assert_eq!(SINGLE_SALT_LEN, 90);
    assert_eq!(THREE_SALTS_LEN, 110);
    assert_eq!(single_salt().len(), SINGLE_SALT_LEN);
    assert_eq!(three_salts().len(), THREE_SALTS_LEN);
}

/// Whether `pw` verifies reference `mode` on a fresh session.
fn verifies<S: Storage>(fs: &mut Fs<S>, mode: u8, pw: &[u8]) -> bool {
    let mut s = Session::new();
    verify(&dev(), fs, &mut s, &mut CountRng(0), 0x00, mode, pw) == Sw::OK
}

/// `kdf-setup` cut at every mutation, then the boot a cut leads to (`scan_files`).
/// No order keeps the DO and the references in step, so the claim is the weaker
/// one the command's comment makes: some admin password always verifies — the old
/// one or the DO's — and from it a re-run of the same command completes the setup.
/// No cut ends in a card its admin cannot get back into.
#[test]
fn a_torn_kdf_setup_always_leaves_the_admin_a_way_back() {
    let body = three_salts();
    rsk_fs::cut::sweep(
        || {
            let (cut, medium) = rsk_fs::storage::faults::Cut::new();
            let mut fs = Fs::new(cut);
            fs.scan();
            scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
            (fs, medium)
        },
        |fs| {
            // The VERIFY is cut too: its retry bookkeeping is an append of its own.
            let mut sess = Session::new();
            let rng = &mut CountRng(0);
            verify(&dev(), fs, &mut sess, rng, 0x00, PW3_MODE83, PW3_DEFAULT) == Sw::OK
                && write(fs, &mut sess, &body) == Sw::OK
        },
        |fs, budget, completed, medium| {
            let _ = scan_files(&dev(), fs, &mut CountRng(9));
            let pw3 = [PW3_DEFAULT, &HASH_PW3[..]]
                .into_iter()
                .find(|pw| verifies(fs, PW3_MODE83, pw))
                .unwrap_or_else(|| {
                    panic!(
                        "budget {budget}: no admin password verifies — {:?}",
                        medium.ops()
                    )
                });
            if completed {
                assert_eq!(pw3, &HASH_PW3[..], "budget {budget}: reported done, is not");
            }
            let mut sess = Session::new();
            assert_eq!(
                verify(
                    &dev(),
                    fs,
                    &mut sess,
                    &mut CountRng(0),
                    0x00,
                    PW3_MODE83,
                    pw3
                ),
                Sw::OK
            );
            assert_eq!(
                write(fs, &mut sess, &body),
                Sw::OK,
                "budget {budget}: the re-run did not heal — {:?}",
                medium.ops()
            );
            assert!(
                verifies(fs, PW3_MODE83, &HASH_PW3) && verifies(fs, PW1_MODE81, &HASH_PW1),
                "budget {budget}: after the re-run a reference is not at its DO hash — {:?}",
                medium.ops()
            );
        },
    );
}
