// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::faults::RemoveStuck;
use rsk_fs::storage::ram::RamStorage;

use crate::files::key_fid;

const SERIAL: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const HASH: [u8; 32] = [0x22; 32];
const OTP: [u8; 32] = [0x44; 32];

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

fn new_fs() -> Fs<RamStorage> {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    fs
}

fn dev(otp: Option<&'static [u8; 32]>) -> Device<'static> {
    Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: otp,
        latched: false,
    }
}

/// The cap is checked before the nonce is drawn, so an over-long plaintext costs
/// no randomness and leaves no half-written record for the next read to find.
#[test]
fn a_plaintext_over_the_cap_is_refused_and_writes_nothing() {
    let mut fs = new_fs();
    let fid = key_fid(SLOT_AUTHENTICATION);
    let over = [0x5Au8; MAX_PLAIN + 1];
    assert_eq!(
        seal_put(&dev(None), &mut fs, &mut TestRng(1), fid, &over),
        Err(Sw::WRONG_LENGTH)
    );
    assert!(!fs.has_key(fid), "a refused seal left a record behind");
}

/// A record too short to hold its own `nonce ‖ tag` framing cannot be a blob this
/// applet wrote. It must answer MEMORY_FAILURE rather than underflow `pt_len` —
/// the at-rest corruption class [`rsk_fs`] exists to fail closed on.
#[test]
fn a_record_shorter_than_its_framing_is_memory_failure() {
    let mut fs = new_fs();
    let fid = key_fid(SLOT_AUTHENTICATION);
    for n in [1usize, NONCE_LEN + TAG_LEN - 1] {
        let junk = vec![0xEEu8; n];
        fs.put_key(fid, Sealed::wrap(&junk)).unwrap();
        let mut out = Secret::<[u8; MAX_PLAIN]>::zeroed();
        assert_eq!(
            seal_read(&dev(None), &mut fs, fid, &mut out),
            Err(Sw::MEMORY_FAILURE),
            "a {n}-byte record was not refused"
        );
    }
}

/// The caller's buffer is measured against the plaintext the record claims, before
/// anything is decrypted into it.
#[test]
fn an_output_buffer_under_the_plaintext_is_refused() {
    let mut fs = new_fs();
    let fid = key_fid(SLOT_AUTHENTICATION);
    let plain = [0x11u8; 40];
    seal_put(&dev(None), &mut fs, &mut TestRng(2), fid, &plain).unwrap();
    let mut small = Secret::<[u8; 39]>::zeroed();
    assert_eq!(
        seal_read(&dev(None), &mut fs, fid, &mut small),
        Err(Sw::WRONG_LENGTH)
    );
    let mut exact = Secret::<[u8; 40]>::zeroed();
    assert_eq!(seal_read(&dev(None), &mut fs, fid, &mut exact), Ok(40));
    assert_eq!(*exact.expose(), plain);
}

/// A blob that opens under neither generation is corrupt, and the migration pass
/// leaves it exactly as it found it: re-sealing garbage under the fuse key would
/// destroy the evidence and make the corruption look like a current record.
#[test]
fn a_slot_that_opens_under_neither_generation_is_left_untouched() {
    let mut fs = new_fs();
    let fid = key_fid(SLOT_AUTHENTICATION);
    let junk = [0xEEu8; NONCE_LEN + 8 + TAG_LEN];
    fs.put_key(fid, Sealed::wrap(&junk)).unwrap();
    assert!(
        !migrate_kbase(&dev(Some(&OTP)), &mut fs, &mut TestRng(3)),
        "a record no arm opens is not counted as left: it would hold the lock off for ever"
    );
    let mut back = [0u8; MAX_BLOB];
    let n = fs
        .read_key(fid, &mut back)
        .expect("the record is still there");
    assert_eq!(
        &back[..n],
        &junk[..],
        "the migration rewrote a corrupt slot"
    );
}

/// An EC blob is `curve_id ‖ scalar`, so one byte carries no scalar at all. The
/// length is checked before `curve_from_id`, which would otherwise answer for a
/// record that has nothing to decode.
#[test]
fn an_ec_blob_without_a_scalar_is_refused() {
    let mut fs = new_fs();
    let fid = key_fid(SLOT_AUTHENTICATION);
    seal_put(&dev(None), &mut fs, &mut TestRng(4), fid, &[3]).unwrap();
    assert_eq!(
        load_ec_key(&dev(None), &mut fs, fid).err(),
        Some(Sw::MEMORY_FAILURE)
    );
}

/// The at-rest lap is re-armed BEFORE the re-seal it covers, and the re-seal is
/// gated on that: a medium that cannot drop `EF_HARDENED` leaves the slot under
/// the old arm rather than writing a fresh blob behind a stale marker.
#[test]
fn a_slot_is_not_re_sealed_while_the_lap_stays_armed_shut() {
    let (backend, medium) = RemoveStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    let fid = key_fid(SLOT_AUTHENTICATION);
    let plain = [0x77u8; 32];
    seal_put(&dev(None), &mut fs, &mut TestRng(5), fid, &plain).unwrap();
    medium.refuse(Some(rsk_fs::EF_HARDENED));
    assert!(
        migrate_kbase(&dev(Some(&OTP)), &mut fs, &mut TestRng(6)),
        "the slot the refusal left under the old arm is reported"
    );
    let mut out = Secret::<[u8; MAX_PLAIN]>::zeroed();
    assert_eq!(
        seal_read(&dev(None), &mut fs, fid, &mut out),
        Ok(32),
        "the slot was re-sealed although the lap could not be re-armed"
    );
}

/// A read the flash failed is not a slot with nothing left in it: whichever read of
/// the slot the fault lands on, or every read, the pass moved the pre-OTP key or
/// reports it.
#[test]
fn a_faulted_read_of_a_pre_otp_slot_is_never_reported_clear() {
    let fid = key_fid(SLOT_AUTHENTICATION);
    for fault in [None, Some(0), Some(1), Some(2), Some(3)] {
        let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
        let mut fs = Fs::new(backend);
        fs.scan();
        seal_put(&dev(None), &mut fs, &mut TestRng(5), fid, &[0x77u8; 32]).unwrap();
        let before = medium.value(fid.get());
        match fault {
            None => medium.stick(Some(fid.get())),
            Some(skip) => medium.stick_after(fid.get(), skip),
        }
        let left = migrate_kbase(&dev(Some(&OTP)), &mut fs, &mut TestRng(6));
        medium.stick(None);
        assert!(
            left || medium.value(fid.get()) != before,
            "fault {fault:?}: reported clear over the pre-OTP key it never moved"
        );
    }
}
