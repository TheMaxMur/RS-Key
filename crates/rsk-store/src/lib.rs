// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! [`rsk_fs::Storage`] (FID → bytes) over two `sequential-storage` map partitions.
//!
//! The split is the point: the hot per-operation counters live in their own small
//! partition so their churn reclaims only their own pages, instead of advancing
//! the main ring into the credential pages and paying a multi-second cold
//! migration. [`is_counter_fid`] is the routing table.
//!
//! Generic over the flash and the two caches, so the same code runs on the
//! device's QSPI, on `sequential-storage`'s power-cuttable mock (the `power_cut`
//! fuzz target, which used to torture a hand-written mirror of this file) and on
//! a file behind `tools/emu`. A store that only the firmware could instantiate is
//! a store nothing could test.

// Host test builds link `std`: the RAM NOR flash the suite runs the store over
// wants a heap, and no test code reaches the firmware image.
#![cfg_attr(not(test), no_std)]

use core::ops::Range;

use embassy_futures::block_on;
use embedded_storage_async::nor_flash::{MultiwriteNorFlash, NorFlash};
use sequential_storage::cache::CacheImpl;
use sequential_storage::map::{MapConfig, MapStorage};

use rsk_fs::Storage;
use rsk_sdk::error::{Error, Result};

/// Scratch for one map op; must fit the largest stored key+value (EF_META ≤ 1 KiB).
const KV_BUF: usize = 2048;

// The 2-byte FID shares the scratch with the value, so the per-value ceiling the
// `Storage` trait publishes is exactly two under it.
const _: () = assert!(rsk_fs::MAX_VALUE_BYTES == KV_BUF - 2);

/// Flash erase-sector size (RP2350 QSPI), = one `sequential-storage` page.
const SECTOR: usize = 4096;

/// Transient FID the [`Storage::compact`] lap churns to advance the main ring.
/// Routed to main (not a counter FID), it never reaches `Fs` and is removed at
/// the end of the lap — pick a slot no protocol uses (the FIDO 0xCExx fixed-file
/// block tops out at `EF_DEVICE_PIN` 0xCE20; creds start at 0xCF00, so 0xCEFE is free).
/// Shared with `rsk_fs`, which must skip it in `Fs::scan`: `compact` writes it
/// straight through the backend, so counting it as a dynamic file cost a live key
/// its registration at the cap (audit run-36).
const SCRUB_FILLER_FID: u16 = rsk_fs::EF_SCRUB_FILLER;
/// One throwaway record's payload during the scrub lap. Larger ⇒ fewer
/// `store_item` calls; must fit `KV_BUF` alongside the 2-byte key.
const SCRUB_FILLER: [u8; 1024] = [0xA5; 1024];

/// FID → bytes persistence over the two flash partitions (see [`is_counter_fid`]).
pub struct SeqStorage<
    F: NorFlash + MultiwriteNorFlash + Clone,
    CM: CacheImpl<u16>,
    CC: CacheImpl<u16>,
> {
    main: MapStorage<u16, F, CM>,
    counter: MapStorage<u16, F, CC>,
    buf: [u8; KV_BUF],
    /// Bytes one [`Storage::compact`] lap must push through the main ring to
    /// sweep it. Taken from the range, not a build constant: the `power_cut`
    /// fuzz target's ring is 8 pages against the board's 352, and a lap sized for
    /// the wrong one either misses pages it must scrub or writes 44× too much.
    main_len: usize,
    /// Whether the last `read`/`size` FAILED rather than finding the key absent —
    /// `Storage::last_error`. Both collapse into `None`, and `Fs` caches the second
    /// as a decided absence, so without this a transient fault opened every gate
    /// that reads `has_data` for the rest of the boot (audit run-36).
    last_err: bool,
}

/// Route the hot per-operation counters to the dedicated counter partition so their
/// churn never reclaims a credential/key page in the main partition. Values are
/// `EF_COUNTER` (FIDO 0xC000), `EF_CRED_CTR` (FIDO per-credential signature counters,
/// 0xC001 — rewritten on every getAssertion), `EF_SIG_COUNT` (OpenPGP 0x0093) and the
/// vendor test counter (0xCC01).
pub fn is_counter_fid(fid: u16) -> bool {
    matches!(fid, 0xC000 | 0xC001 | 0x0093 | 0xCC01)
}

impl<F: NorFlash + MultiwriteNorFlash + Clone, CM: CacheImpl<u16>, CC: CacheImpl<u16>>
    SeqStorage<F, CM, CC>
{
    /// `main_range` / `counter_range` are erase-aligned, non-overlapping
    /// flash-offset windows (on the device, from `memory.x`); `flash` is a handle
    /// both partitions can hold, since `MapStorage` takes it by value.
    pub fn new(
        flash: F,
        main_range: Range<u32>,
        counter_range: Range<u32>,
        main_cache: CM,
        counter_cache: CC,
    ) -> Self {
        let main_len = (main_range.end - main_range.start) as usize;
        Self {
            main: MapStorage::new(flash.clone(), MapConfig::new(main_range), main_cache),
            counter: MapStorage::new(flash, MapConfig::new(counter_range), counter_cache),
            buf: [0; KV_BUF],
            main_len,
            last_err: false,
        }
    }
}

// sequential-storage is async-only; the blocking flash is wrapped in BlockingAsync,
// whose futures are ready on first poll, so block_on drives them synchronously.
impl<F: NorFlash + MultiwriteNorFlash + Clone, CM: CacheImpl<u16>, CC: CacheImpl<u16>> Storage
    for SeqStorage<F, CM, CC>
{
    const MAX_VALUE: usize = rsk_fs::MAX_VALUE_BYTES;
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        let fetched = if is_counter_fid(fid) {
            block_on(self.counter.fetch_item::<&[u8]>(&mut self.buf, &fid))
        } else {
            block_on(self.main.fetch_item::<&[u8]>(&mut self.buf, &fid))
        };
        // Distinguish "absent" from "the read failed" for `Fs`, which memoises the
        // first as a decided fact — see `Storage::last_error`.
        self.last_err = fetched.is_err();
        let value = fetched.ok()??;
        let n = value.len().min(buf.len());
        buf[..n].copy_from_slice(&value[..n]);
        Some(value.len())
    }

    fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
        if is_counter_fid(fid) {
            block_on(self.counter.store_item::<&[u8]>(&mut self.buf, &fid, &data))
        } else {
            block_on(self.main.store_item::<&[u8]>(&mut self.buf, &fid, &data))
        }
        .map_err(|_| Error::MemoryFatal)
    }

    fn remove(&mut self, fid: u16) -> Result<()> {
        if is_counter_fid(fid) {
            block_on(self.counter.remove_item(&mut self.buf, &fid))
        } else {
            block_on(self.main.remove_item(&mut self.buf, &fid))
        }
        .map_err(|_| Error::MemoryFatal)
    }

    fn size(&mut self, fid: u16) -> Option<usize> {
        let fetched = if is_counter_fid(fid) {
            block_on(self.counter.fetch_item::<&[u8]>(&mut self.buf, &fid))
        } else {
            block_on(self.main.fetch_item::<&[u8]>(&mut self.buf, &fid))
        };
        self.last_err = fetched.is_err();
        let value = fetched.ok()??;
        Some(value.len())
    }

    fn last_error(&self) -> bool {
        self.last_err
    }

    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        // Both partitions must complete before an un-yielded FID counts as absent:
        // `Fs::scan`'s `decided.fill` trusts only a globally complete enumeration.
        // Run both regardless of the first's result so `f` still sees every key it
        // can (the `&&` here is over the outcomes, not a short-circuit of the walk).
        let main_done = for_each_in(&mut self.main, &mut self.buf, f);
        let counter_done = for_each_in(&mut self.counter, &mut self.buf, f);
        main_done && counter_done
    }

    /// Physically scrub superseded records from the **main** partition (where
    /// every secret lives) by driving its `sequential-storage` ring a full lap.
    ///
    /// The library's `store_item` (overwrite) only appends, and `remove_item`
    /// only flips a header CRC — both leave the prior payload in flash, readable
    /// from a raw dump until the page is reclaimed. A page is reclaimed (its live
    /// items migrated forward, then the whole 4 KiB sector erased) only when the
    /// ring head needs it. So we write one partition's worth of throwaway records
    /// to force the head all the way around: every page that held data at entry
    /// is swept and erased, and the superseded copy of any migrated secret — in
    /// particular the chip-serial-sealed pre-OTP seed left by
    /// `migrate_keydev_boot` — is physically destroyed.
    ///
    /// One lap needs at most the main partition's length in fresh writes (less by however
    /// much live data is relocated en route), so `MAIN_LEN + SECTOR` guarantees a
    /// full sweep no matter how full the partition is. The counter partition holds
    /// only non-secret counters and churns on its own, so it is left untouched.
    /// This is a one-shot, multi-second provisioning cost (see the `EF_HARDENED`
    /// gate in `main`); it is crash-safe — an interrupted lap leaves the store in
    /// a valid state and re-runs on the next boot.
    fn compact(&mut self) -> Result<()> {
        let writes = (self.main_len + SECTOR).div_ceil(SCRUB_FILLER.len());
        let mut lap = Ok(());
        for i in 0..writes {
            let mut v = SCRUB_FILLER;
            v[0] = i as u8; // distinct payloads (defensive; store always appends)
            if block_on(self.main.store_item::<&[u8]>(
                &mut self.buf,
                &SCRUB_FILLER_FID,
                &v.as_slice(),
            ))
            .is_err()
            {
                lap = Err(Error::MemoryFatal);
                break;
            }
        }
        // Remove the filler on the FAILURE path too, not just the success one. An
        // early return left a live 1024-byte record behind, and `Fs::scan` counted
        // it against the dynamic-file budget until the next completed lap cleaned it
        // up (audit run-36); `is_fido_fid` does not cover it, so `authenticatorReset`
        // never would.
        block_on(self.main.remove_item(&mut self.buf, &SCRUB_FILLER_FID))
            .map_err(|_| Error::MemoryFatal)?;
        lap
    }
}

/// Iterate every live key in one partition (used by `for_each_key` over both).
/// Returns `true` iff the walk reached its natural `None` terminator, i.e. it
/// enumerated every live key. `MapItemIter::next` reaches `None` only after
/// cycling the full ring; the sole early exit is a genuine flash READ FAULT
/// (`Err`), which a NOR power cut never produces (a torn write yields deterministic
/// bytes, not a read error). A `false` return therefore flags a truncated
/// enumeration the caller must not read as "those keys are absent".
fn for_each_in<F: NorFlash + MultiwriteNorFlash, C: CacheImpl<u16>>(
    map: &mut MapStorage<u16, F, C>,
    buf: &mut [u8],
    f: &mut dyn FnMut(u16),
) -> bool {
    let Ok(mut iter) = block_on(map.fetch_all_items(buf)) else {
        return false;
    };
    loop {
        match block_on(iter.next::<&[u8]>(buf)) {
            Ok(Some((key, _))) => f(key),
            Ok(None) => return true,
            Err(_) => return false,
        }
    }
}

#[cfg(test)]
mod tests;
