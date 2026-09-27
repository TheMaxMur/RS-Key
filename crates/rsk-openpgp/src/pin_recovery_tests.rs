// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::cut::{Snap, sweep_recovery};

const NEW: &[u8] = b"87654321";

/// The PW3 the card answers to now, read off its verifier record so the probe
/// spends no retry: a harness that guessed would drain the counter across the
/// nested runs and blame the card for it.
fn in_force(d: &Device, fs: &mut Fs<Snap>) -> &'static [u8] {
    let mut rec = [0u8; 34];
    let new = d.pin_derive_verifier(NEW);
    match fs.read(EF_PW3, &mut rec) {
        Some(34) if rec[2..] == *new.expose() => NEW,
        _ => PW3_DEFAULT,
    }
}

/// A session on the PW3 in force.
fn standing(d: &Device, fs: &mut Fs<Snap>) -> Option<Session> {
    let mut sess = Session::new();
    let pin = in_force(d, fs);
    let sw = verify(d, fs, &mut sess, &mut CountRng(0), 0x00, PW3_MODE83, pin);
    (sw == Sw::OK).then_some(sess)
}

/// The compound failure behind `change_pin_is_recoverable_at_every_write_it_makes`:
/// a PW3 change cut at every write, then the recovery `load_dek` runs for the next
/// session cut at every write of its own, then a healthy session. The card must
/// still answer to one PW3 and that PW3 must open the same DEK, with no stage left.
#[test]
fn a_pw3_change_torn_twice_still_opens_the_same_dek() {
    let d = dev();
    let want = std::cell::RefCell::new(None);
    sweep_recovery(
        |fs| {
            scan_files(&d, fs, &mut CountRng(0)).unwrap();
            let mut sess = Session::new();
            let sw = verify(
                &d,
                fs,
                &mut sess,
                &mut CountRng(0),
                0x00,
                PW3_MODE83,
                PW3_DEFAULT,
            );
            assert_eq!(sw, Sw::OK);
            let mut dek = Secret::<[u8; DEK_SIZE]>::zeroed();
            load_dek(&d, fs, &sess, &mut dek).unwrap();
            *want.borrow_mut() = Some(*dek.expose());
            sess
        },
        |fs, sess| {
            let mut data = PW3_DEFAULT.to_vec();
            data.extend_from_slice(NEW);
            change_pin(&d, fs, sess, &mut CountRng(3), 0x00, PW3_MODE83, &data);
        },
        |fs| {
            if let Some(sess) = standing(&d, fs) {
                let _ = load_dek(&d, fs, &sess, &mut Secret::<[u8; DEK_SIZE]>::zeroed());
            }
        },
        |fs, first, second| {
            let sess = standing(&d, fs)
                .unwrap_or_else(|| panic!("cuts {first}/{second}: neither PW3 verifies"));
            let mut got = Secret::<[u8; DEK_SIZE]>::zeroed();
            load_dek(&d, fs, &sess, &mut got).unwrap_or_else(|e| {
                panic!("cuts {first}/{second}: the standing PW3 cannot open the DEK: {e:?}")
            });
            assert_eq!(
                Some(*got.expose()),
                *want.borrow(),
                "cuts {first}/{second}: recovered a different key"
            );
            assert!(
                !fs.has_key(EF_DEK_STAGE_PW3),
                "cuts {first}/{second}: a stage survived a recovered card"
            );
        },
    );
}
