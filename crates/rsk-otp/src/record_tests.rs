// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::Rng;
use rsk_fs::storage::ram::RamStorage;

#[path = "record_plaintext_tests.rs"]
mod plaintext;

struct CountRng(u8);
impl Rng for CountRng {
    fn fill(&mut self, b: &mut [u8]) {
        for x in b {
            *x = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

const SERIAL: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const HASH: [u8; 32] = [0x22; 32];

fn dev() -> Device<'static> {
    Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
        latched: false,
    }
}

fn new_fs() -> Fs<RamStorage> {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    fs
}

/// Seal `stored` into slot `fid` as a build would have left it.
fn seed(fs: &mut Fs<RamStorage>, fid: u16, stored: &[u8]) {
    let rec = SlotRecord::from_bytes(stored).unwrap();
    assert!(seal::seal_put(
        &dev(),
        fs,
        &mut CountRng(1),
        KeyFid::new(fid),
        &rec
    ));
}

/// A full record: `cfg` bytes, then a tail holding `counter`.
fn full(cfg: u8, counter: u16) -> [u8; SLOT_SIZE] {
    let mut rec = [cfg; SLOT_SIZE];
    rec[CONFIG_SIZE..].fill(0);
    rec[CONFIG_SIZE..CONFIG_SIZE + 2].copy_from_slice(&counter.to_be_bytes());
    rec
}

fn counter(rec: &SlotRecord) -> u16 {
    u16::from_be_bytes([rec.expose()[CONFIG_SIZE], rec.expose()[CONFIG_SIZE + 1]])
}

#[test]
fn a_read_leaves_nothing_of_the_record_it_replaces() {
    // `migrate_seal` and the status readers reuse one record across slots, so a
    // legacy slot read after a full one must not inherit that one's counter.
    let mut fs = new_fs();
    seed(&mut fs, EF_OTP_SLOT1, &full(0x11, 7));
    seed(&mut fs, EF_OTP_SLOT1 + 1, &[0x22; CONFIG_SIZE]);
    let mut rec = SlotRecord::vacant();
    assert_eq!(
        rec.try_read(&dev(), &mut fs, EF_OTP_SLOT1),
        Ok(Some(SLOT_SIZE))
    );
    assert_eq!(
        rec.try_read(&dev(), &mut fs, EF_OTP_SLOT1 + 1),
        Ok(Some(CONFIG_SIZE))
    );
    assert_eq!(rec.expose()[CONFIG_SIZE..], [0; SLOT_SIZE - CONFIG_SIZE]);
    assert_eq!(rec.stored().len(), CONFIG_SIZE);
}

#[test]
fn a_verbatim_read_keeps_the_stored_length() {
    // A swap and the boot re-seal write `stored()`, so a legacy record stays one.
    let mut fs = new_fs();
    seed(&mut fs, EF_OTP_SLOT1, &[0x33; CONFIG_SIZE]);
    fs.put(EF_OTP_SLOT1 + 1, &[0x44; CONFIG_SIZE]).unwrap();
    let mut rec = SlotRecord::vacant();
    assert_eq!(
        rec.try_read(&dev(), &mut fs, EF_OTP_SLOT1),
        Ok(Some(CONFIG_SIZE))
    );
    assert_eq!(rec.stored(), &[0x33; CONFIG_SIZE]);
    assert_eq!(
        rec.try_read_plaintext(&mut fs, EF_OTP_SLOT1 + 1),
        Ok(Some(CONFIG_SIZE))
    );
    assert_eq!(rec.stored(), &[0x44; CONFIG_SIZE]);
}

#[test]
fn a_fid_outside_the_slots_reads_as_no_record() {
    // The applet stores host bytes next door (0xBB10..), and those must not come
    // back as a record with a tail the host wrote.
    let beyond = EF_OTP_SLOT_LAST + 1;
    let mut fs = new_fs();
    seed(&mut fs, beyond, &full(0x55, 9));
    fs.put(beyond + 1, &[0x66; CONFIG_SIZE]).unwrap();
    let mut rec = SlotRecord::vacant();
    assert_eq!(rec.try_read(&dev(), &mut fs, beyond), Ok(None));
    assert_eq!(rec.try_read_plaintext(&mut fs, beyond + 1), Ok(None));
    assert!(rec.stored().is_empty());
}

#[test]
fn every_move_leaves_a_full_record() {
    // A legacy record that moves must reach flash whole, or the new tail is dropped
    // and the next read replays the old one.
    let mut hotp = [0u8; CONFIG_SIZE];
    hotp[OFF_UID + 4..OFF_UID + 6].copy_from_slice(&0x0102u16.to_be_bytes());
    let mut rec = SlotRecord::from_bytes(&hotp).unwrap();
    assert_eq!(rec.press_hotp(), 0x0102);
    assert_eq!(rec.expose()[CONFIG_SIZE..], 0x0103u64.to_be_bytes());
    assert_eq!(rec.stored().len(), SLOT_SIZE);

    let mut rec = SlotRecord::from_bytes(&[0; CONFIG_SIZE]).unwrap();
    assert_eq!(rec.press_yubico(9), (1, 10, true));
    assert_eq!((counter(&rec), rec.stored().len()), (1, SLOT_SIZE));

    let mut rec = SlotRecord::from_bytes(&[0; CONFIG_SIZE]).unwrap();
    assert!(rec.cycle_bump());
    assert_eq!((counter(&rec), rec.stored().len()), (1, SLOT_SIZE));

    let mut rec = SlotRecord::from_bytes(&[0; CONFIG_SIZE]).unwrap();
    rec.reconfigure(&[0x77; CONFIG_SIZE]);
    assert_eq!(rec.stored()[CONFIG_SIZE..], [0; SLOT_SIZE - CONFIG_SIZE]);
    assert_eq!(rec.stored().len(), SLOT_SIZE);
}

#[test]
fn a_short_record_moves_its_counter_from_zero() {
    // No build wrote 53..59 bytes, but one that reads that long holds no counter,
    // and every build before the type moved it from zero.
    let mut stored = [0u8; CONFIG_SIZE + 3];
    stored[CONFIG_SIZE..].copy_from_slice(&[0x00, 0x05, 0xAA]);
    let mut rec = SlotRecord::from_bytes(&stored).unwrap();
    assert!(rec.cycle_bump());
    assert_eq!(rec.expose()[CONFIG_SIZE..], [0, 1, 0, 0, 0, 0, 0, 0]);

    let mut rec = SlotRecord::from_bytes(&stored).unwrap();
    assert_eq!(rec.press_yubico(0), (1, 1, true));
    assert_eq!(rec.expose()[CONFIG_SIZE..], [0, 1, 0, 0, 0, 0, 0, 0]);

    // A HOTP one computes from the programmed factor, not from its partial tail.
    stored[OFF_UID + 4..OFF_UID + 6].copy_from_slice(&0x0102u16.to_be_bytes());
    stored[CONFIG_SIZE..].copy_from_slice(&[0x00, 0x00, 0x09]);
    let mut rec = SlotRecord::from_bytes(&stored).unwrap();
    assert_eq!(rec.press_hotp(), 0x0102);
    assert_eq!(rec.expose()[CONFIG_SIZE..], 0x0103u64.to_be_bytes());
}

#[test]
fn update_carries_the_tail_and_configure_restarts_it() {
    let mut rec = SlotRecord::from_bytes(&full(0x11, 7)).unwrap();
    rec.reconfigure(&[0x22; CONFIG_SIZE]);
    assert_eq!(rec.stored()[..CONFIG_SIZE], [0x22; CONFIG_SIZE]);
    assert_eq!(counter(&rec), 7);
    rec.configure(&[0x33; CONFIG_SIZE]);
    assert_eq!(rec.stored()[..CONFIG_SIZE], [0x33; CONFIG_SIZE]);
    assert_eq!(rec.stored()[CONFIG_SIZE..], [0; SLOT_SIZE - CONFIG_SIZE]);
}
