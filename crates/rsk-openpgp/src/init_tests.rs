// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::ram::RamStorage;

/// Deterministic counter RNG for tests.
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
        serial_hash: &[0x11; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    }
}

fn fresh() -> Fs<RamStorage> {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    fs
}

#[test]
fn creates_all_default_files() {
    let mut fs = fresh();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();

    // DEK files are 77 bytes, format byte 0x03.
    for fid in [EF_DEK_PW1, EF_DEK_PW3] {
        assert_eq!(fs.size(fid.get()), Some(DEK_FILE_SIZE));
        let mut b = [0u8; 1];
        fs.read(fid.get(), &mut b);
        assert_eq!(b[0], DEK_FORMAT_V3);
    }
    // The resetting code ships DEACTIVATED: no RC verifier and no RC-sealed DEK.
    assert_eq!(fs.size(EF_DEK_RC.get()), None);
    let mut rc = [0u8; 34];
    assert!(fs.read(EF_RC, &mut rc).is_none());
    // PIN verifiers: [len, 1, verifier(32)].
    let mut rec = [0u8; 34];
    fs.read(EF_PW1, &mut rec);
    assert_eq!(rec[0], 6);
    assert_eq!(rec[1], PIN_FORMAT_V1);
    let mut rec3 = [0u8; 34];
    fs.read(EF_PW3, &mut rec3);
    assert_eq!(rec3[0], 8);

    assert_eq!(fs.size(EF_SIG_COUNT), Some(3));
    let mut pw = [0u8; 7];
    fs.read(EF_PW_PRIV, &mut pw);
    // RC retry counter (index 5) is 0: the resetting code ships deactivated.
    assert_eq!(&pw, &[0x01, 127, 127, 127, 3, 0, 3]);
    assert!(fs.has_data(EF_KDF));
    assert!(fs.has_data(EF_SEX));
    assert!(fs.has_data(EF_PW_RETRIES));
}

#[test]
fn dek_decrypts_under_default_pin() {
    let mut fs = fresh();
    let d = dev();
    scan_files(&d, &mut fs, &mut CountRng(0)).unwrap();

    // The wrapped DEK is recoverable with the default PW1 session key.
    let mut blob = [0u8; DEK_FILE_SIZE];
    let n = fs.read(EF_DEK_PW1.get(), &mut blob).unwrap();
    assert_eq!(blob[0], DEK_FORMAT_V3);
    let session = d.pin_derive_session(PW1_DEFAULT);
    let mut dek = [0u8; DEK_SIZE];
    let m = d
        .decrypt_with_aad(&session, &blob[1..n], PinKdf::V2, &mut dek)
        .unwrap();
    assert_eq!(m, DEK_SIZE);
    // RC and PW3 are the same blob sealed under PW3 and decrypt to the same DEK.
    let mut blob3 = [0u8; DEK_FILE_SIZE];
    fs.read(EF_DEK_PW3.get(), &mut blob3);
    let session3 = d.pin_derive_session(PW3_DEFAULT);
    let mut dek3 = [0u8; DEK_SIZE];
    d.decrypt_with_aad(&session3, &blob3[1..], PinKdf::V2, &mut dek3)
        .unwrap();
    assert_eq!(dek, dek3);
}

/// The record firmware 0x07F7..=0x0852 wrote: no RC verifier, but a live RC
/// error counter (index 5).
const PW_STATUS_LEGACY: &[u8] = &[0x01, 127, 127, 127, 3, 3, 3];

fn rc_counter<S: rsk_fs::Storage>(fs: &mut Fs<S>) -> u8 {
    let mut pw = [0u8; 7];
    fs.read(EF_PW_PRIV, &mut pw).unwrap();
    pw[pw_retry_idx(EF_RC)]
}

#[test]
fn legacy_rc_counter_is_zeroed_when_no_reset_code_exists() {
    let mut fs = fresh();
    fs.put(EF_PW_PRIV, PW_STATUS_LEGACY).unwrap();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();

    assert!(!fs.has_data(EF_RC), "no RC was ever set on this card");
    assert_eq!(
        rc_counter(&mut fs),
        0,
        "DO C4 must not advertise an absent RC"
    );
}

#[test]
fn a_real_reset_code_keeps_its_retry_counter() {
    let mut fs = fresh();
    let d = dev();
    fs.put(EF_PW_PRIV, PW_STATUS_LEGACY).unwrap();
    put_pin_verifier(&mut fs, &d, EF_RC, b"87654321").unwrap();
    scan_files(&d, &mut fs, &mut CountRng(0)).unwrap();

    assert!(fs.has_data(EF_RC), "an admin-set RC survives init");
    assert_eq!(rc_counter(&mut fs), 3);
}

#[test]
fn the_default_reset_code_is_deleted_and_its_counter_cleared() {
    let mut fs = fresh();
    let d = dev();
    fs.put(EF_PW_PRIV, PW_STATUS_LEGACY).unwrap();
    put_pin_verifier(&mut fs, &d, EF_RC, PW3_DEFAULT).unwrap();
    scan_files(&d, &mut fs, &mut CountRng(0)).unwrap();

    assert!(!fs.has_data(EF_RC), "the 0x07F6-era backdoor RC is removed");
    assert_eq!(rc_counter(&mut fs), 0);
}

#[test]
fn is_idempotent() {
    let mut fs = fresh();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    let mut first = [0u8; DEK_FILE_SIZE];
    fs.read(EF_DEK_PW1.get(), &mut first);
    // A second run with a different RNG must not rewrite existing files.
    scan_files(&dev(), &mut fs, &mut CountRng(200)).unwrap();
    let mut second = [0u8; DEK_FILE_SIZE];
    fs.read(EF_DEK_PW1.get(), &mut second);
    assert_eq!(first, second);
}

#[test]
fn an_overlong_pw_status_record_cannot_panic_the_rc_settle() {
    // Same clamp as `pin::check_pin`: `Fs::read` reports the stored length, and an
    // unclamped `&pw[..n]` here would panic on the pre-USB boot path.
    let mut fs = fresh();
    let mut overlong = PW_STATUS_LEGACY.to_vec();
    overlong.resize(16, 0xAA);
    fs.put(EF_PW_PRIV, &overlong).unwrap();

    settle_rc_retry_counter(&mut fs).unwrap();
    assert_eq!(
        rc_counter(&mut fs),
        0,
        "DO C4 must not advertise an absent RC"
    );
}

#[test]
fn maxima_an_older_build_moved_are_restored_at_boot() {
    // A card that took `PUT DATA 00 C4 = 01 06 06 06` under a build that copied
    // the whole body announced max 6 for the rest of its life: PUT DATA writes
    // the flag only now, and no other writer touches these bytes. gpg reads the
    // announcement as the limit, so the owner could never set a longer PIN again.
    let mut fs = fresh();
    fs.put(EF_PW_PRIV, &[0x01, 6, 6, 6, 3, 0, 3]).unwrap();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();

    let mut pw = [0u8; 7];
    let n = fs.read(EF_PW_PRIV, &mut pw).unwrap();
    assert_eq!(&pw[1..4], &PW_STATUS_DEFAULT[1..4], "the announced maxima");
    // Only those three bytes: the flag the owner set and the retry counters stay.
    assert_eq!(pw[0], 0x01);
    assert_eq!(&pw[4..n], &[3, 0, 3]);

    // Idempotent, and it does not resurrect a shorter record's missing bytes.
    let mut short = fresh();
    short.put(EF_PW_PRIV, &[0x00, 6]).unwrap();
    settle_pw_status_maxima(&mut short).unwrap();
    let mut got = [0u8; 7];
    let n = short.read(EF_PW_PRIV, &mut got).unwrap();
    assert_eq!(&got[..n], &[0x00, PW_STATUS_DEFAULT[1]]);
}

/// E70: `SEX_VALUES` narrowed to the set a YubiKey accepts — `{'1','2','9'}` —
/// and `'0'`, which older builds seeded, is no longer in it. Boot repairs the
/// stranded byte rather than leaving a card that can read `5F35` and not write it
/// back. Both directions, because the second is the one that catches a per-boot
/// flash write on a card that needs no repair.
#[test]
fn boot_settles_a_sex_code_outside_the_value_list() {
    // `Fs::read` reports the value's FULL stored length, so clamp before slicing —
    // a stale row longer than the buffer would panic instead of failing.
    let sex_of = |fs: &mut Fs<RamStorage>| {
        let mut b = [0u8; 4];
        let n = fs.read(EF_SEX, &mut b).unwrap();
        b[..n.min(b.len())].to_vec()
    };
    // Every shape a provisioned card could be holding: the `'0'` firmware through
    // 0x08F1 wrote, another ISO 5218 code we never accepted, an absent DO, and two
    // lengths no value list can describe.
    for stale in [Some(&b"0"[..]), Some(b"3"), None, Some(b""), Some(b"19")] {
        let mut fs = fresh();
        scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
        match stale {
            None => fs.delete(EF_SEX).unwrap(),
            Some(v) => fs.put(EF_SEX, v).unwrap(),
        }
        scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
        assert_eq!(
            sex_of(&mut fs),
            SEX_DEFAULT,
            "not settled from {stale:02X?}"
        );
        // …and the boot after it writes nothing, or the repair is a wear bug.
        let writes = fs.write_gen();
        scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
        assert_eq!(
            fs.write_gen(),
            writes,
            "a settled card rewrote 5F35 on boot"
        );
        assert_eq!(sex_of(&mut fs), SEX_DEFAULT);
    }

    // A code the card does accept is the cardholder's, not ours to overwrite.
    for keep in SEX_VALUES {
        let mut fs = fresh();
        scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
        fs.put(EF_SEX, &[*keep]).unwrap();
        let writes = fs.write_gen();
        scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
        assert_eq!(sex_of(&mut fs), [*keep], "boot moved an accepted code");
        assert_eq!(fs.write_gen(), writes, "boot rewrote an accepted code");
    }
}

/// A repair the store REFUSES leaves the old byte and the next boot retries. The
/// budget also pins the cost: zero writes fails, one write is enough, so the
/// repair is exactly one `put` — and on an already-provisioned card it is the
/// FIRST write `scan_files` makes, which is what makes that count meaningful.
///
/// This models a rejected write, not a torn one: the flash's own power-cut
/// behaviour (an append-only CRC'd item, so a cut leaves the previous value live)
/// belongs to `rsk-store` and `fuzz/fuzz_targets/power_cut.rs`, not here.
#[test]
fn a_refused_sex_repair_leaves_the_old_byte_and_retries() {
    let (store, budget) = DyingStorage::new();
    let mut fs = Fs::new(store);
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    fs.put(EF_SEX, b"0").unwrap();
    let mut b = [0u8; 4];

    // Nothing else in `scan_files` writes on an already-provisioned card, so the
    // first refused write IS the repair.
    budget.set(0);
    assert_eq!(
        scan_files(&dev(), &mut fs, &mut CountRng(0)),
        Err(Error::Storage)
    );
    let n = fs.read(EF_SEX, &mut b).unwrap();
    assert_eq!(&b[..n], b"0", "a refused write must not eat the old value");

    // One write is the whole repair, and the boot after it is free.
    budget.set(1);
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    let n = fs.read(EF_SEX, &mut b).unwrap();
    assert_eq!(&b[..n], SEX_DEFAULT);
    budget.set(0);
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
}

/// `RamStorage` whose writes fail once `budget` runs out. A verbatim second copy
/// of `pin_tests`\' own: hoisting it into a shared `#[cfg(test)]` module is a
/// refactor of two other files, so it is left for one rather than folded in here.
struct DyingStorage {
    inner: RamStorage,
    budget: std::rc::Rc<std::cell::Cell<usize>>,
}

impl DyingStorage {
    fn new() -> (Self, std::rc::Rc<std::cell::Cell<usize>>) {
        let budget = std::rc::Rc::new(std::cell::Cell::new(usize::MAX));
        (
            Self {
                inner: RamStorage::new(),
                budget: budget.clone(),
            },
            budget,
        )
    }
    fn spend(&mut self) -> rsk_sdk::error::Result<()> {
        match self.budget.get() {
            0 => Err(rsk_sdk::error::Error::MemoryFatal),
            n => {
                self.budget.set(n - 1);
                Ok(())
            }
        }
    }
}

impl rsk_fs::Storage for DyingStorage {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.inner.read(fid, buf)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
        self.spend()?;
        self.inner.write(fid, data)
    }
    fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
        self.spend()?;
        self.inner.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.inner.size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(f)
    }
}
