// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! At-rest hardening scrub proof.
//!
//! `sequential-storage` is append-only: an overwrite leaves the prior value in
//! the log and `remove_item` only flips a header CRC, so a superseded payload
//! survives in flash — recoverable from a raw dump — until its page is
//! reclaimed. The device re-seals every secret from the chip-serial root to the
//! OTP root at the first OTP boot (`migrate_keydev_boot` & friends), which
//! overwrites them and thus strands the *weaker* chip-serial-sealed copies on
//! flash. `FlashStorage::compact` scrubs those by driving the ring a full lap so
//! every page is migrated forward and sector-erased.
//!
//! This test runs that exact churn on the same `sequential-storage` +
//! `MockFlashBase` stack the power-cut target uses, then reads the **raw** flash
//! bytes to prove the superseded secret is physically gone while the live value
//! survives. Mutation guard: a no-op (or short) compaction leaves the remnant
//! and fails the final assertion — the first assert documents that the remnant
//! genuinely exists before the scrub.

use std::cell::RefCell;
use std::rc::Rc;

use embassy_futures::block_on;
use embedded_storage_async::nor_flash::{ErrorType, MultiwriteNorFlash, NorFlash, ReadNorFlash};
use sequential_storage::cache::Cache as SsCache;
use sequential_storage::cache::key_pointers::ArrayKeyPointers;
use sequential_storage::cache::page_pointers::ArrayPagePointers;
use sequential_storage::cache::page_states::ArrayPageStates;
use sequential_storage::map::{MapConfig, MapStorage};
use sequential_storage::mock_flash::{MockFlashBase, MockFlashError, WriteCountCheck};

// One 32 KiB ring (8 × 4 KiB pages, 4-byte words) — small enough that a full
// lap completes in a test, same geometry as the power-cut target's main map.
const WORD: usize = 4;
const PAGE_WORDS: usize = 1024;
const PAGES: usize = 8;
type Mock = MockFlashBase<PAGES, WORD, PAGE_WORDS>;
const SECTOR: usize = 4096;
const PARTITION_LEN: usize = PAGES * SECTOR;
const RANGE: core::ops::Range<u32> = 0..(PARTITION_LEN as u32);
// See `kv_durability`: derived from the published ceiling, never a literal.
const KV_BUF: usize = rsk_fs::MAX_VALUE_BYTES + 2;
type Cache =
    SsCache<ArrayPageStates<PAGES>, ArrayPagePointers<PAGES>, ArrayKeyPointers<u16, 16>, u16>;
type Store = MapStorage<u16, SharedMock, Cache>;

// The churn parameters mirror `firmware/src/flash_storage.rs` exactly; only the
// partition length differs (scaled to the test ring).
const SCRUB_FILLER_FID: u16 = rsk_fs::EF_SCRUB_FILLER;
const SCRUB_FILLER: [u8; 1024] = [0xA5; 1024];

#[derive(Clone)]
struct SharedMock(Rc<RefCell<Mock>>);

impl ErrorType for SharedMock {
    type Error = MockFlashError;
}
impl ReadNorFlash for SharedMock {
    const READ_SIZE: usize = <Mock as ReadNorFlash>::READ_SIZE;
    async fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        block_on(self.0.borrow_mut().read(offset, bytes))
    }
    fn capacity(&self) -> usize {
        self.0.borrow().capacity()
    }
}
impl NorFlash for SharedMock {
    const WRITE_SIZE: usize = <Mock as NorFlash>::WRITE_SIZE;
    const ERASE_SIZE: usize = <Mock as NorFlash>::ERASE_SIZE;
    async fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        block_on(self.0.borrow_mut().erase(from, to))
    }
    async fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        block_on(self.0.borrow_mut().write(offset, bytes))
    }
}
impl MultiwriteNorFlash for SharedMock {}

/// A full garbage-collection lap — the body of `FlashStorage::compact`, scaled
/// to `PARTITION_LEN`. Writing one partition's worth (+ a sector) of throwaway
/// records forces the ring head all the way around, reclaiming (migrating then
/// sector-erasing) every page that held data at entry.
fn churn_full_lap(map: &mut Store, buf: &mut [u8]) {
    let writes = (PARTITION_LEN + SECTOR).div_ceil(SCRUB_FILLER.len());
    for i in 0..writes {
        let mut v = SCRUB_FILLER;
        v[0] = i as u8;
        let filler: &[u8] = &v;
        block_on(map.store_item::<&[u8]>(buf, &SCRUB_FILLER_FID, &filler)).unwrap();
    }
    block_on(map.remove_item(buf, &SCRUB_FILLER_FID)).unwrap();
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn churn_lap_physically_scrubs_superseded_secret() {
    // Last arg = MockFlash's source-pointer `alignment_check`. It is OFF here: the
    // stack `[u8; N]` buffers are align-1 and happen to land 4-aligned on a real
    // machine but not under miri (which runs this test in deep-checks), and the
    // RP2350 QSPI write does not require source alignment anyway. This test proves
    // the scrub, not flash alignment strictness — which the libfuzzer flash
    // targets (kv_durability / power_cut) already exercise with the check ON.
    let flash = Rc::new(RefCell::new(Mock::new(
        WriteCountCheck::Disabled,
        None,
        false,
    )));
    let mut map = Store::new(
        SharedMock(flash.clone()),
        MapConfig::new(RANGE),
        Cache::new(
            ArrayPageStates::new(),
            ArrayPagePointers::new(),
            ArrayKeyPointers::new(),
        ),
    );
    let mut buf = [0u8; KV_BUF];

    // EF_KEY_DEV. Distinctive ASCII so the raw-byte scan can't collide with the
    // 0xA5 filler or sequential-storage's binary headers.
    const SEED_FID: u16 = 0xCC00;
    let pre_otp: &[u8] = b"REMNANT-pre-OTP-seed-ciphertext-1";
    let otp: &[u8] = b"LIVE-OTP-resealed-seed-ciphertxt2";

    // Pre-OTP seal, then the boot migration re-seals under the OTP root — an
    // overwrite of the same FID.
    block_on(map.store_item::<&[u8]>(&mut buf, &SEED_FID, &pre_otp)).unwrap();
    block_on(map.store_item::<&[u8]>(&mut buf, &SEED_FID, &otp)).unwrap();

    // The append-only log still holds the weaker pre-OTP copy: this is the
    // remnant a flash dump would recover (the bug being fixed).
    assert!(
        contains(flash.borrow().as_bytes(), pre_otp),
        "pre-condition: the superseded pre-OTP seed must exist in raw flash"
    );
    assert!(contains(flash.borrow().as_bytes(), otp));

    churn_full_lap(&mut map, &mut buf);

    // Live value preserved…
    let got = block_on(map.fetch_item::<&[u8]>(&mut buf, &SEED_FID))
        .unwrap()
        .expect("the OTP-sealed seed must survive the lap");
    assert_eq!(got, otp, "live value corrupted by the scrub lap");

    // …and the weaker remnant physically erased from flash.
    assert!(
        !contains(flash.borrow().as_bytes(), pre_otp),
        "the pre-OTP seed remnant must be physically scrubbed from raw flash"
    );
}
