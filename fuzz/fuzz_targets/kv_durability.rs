// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Storage-layer power-cut durability: does `sequential-storage` itself lose (or
//! roll back) a COMMITTED value across a power-cut during page migration?
//!
//! Complements `power_cut` (which torments the whole rsk-fs stack) by driving ONE
//! `MapStorage` partition DIRECTLY — no `rsk-fs`, no present-cache, no EF_META
//! meta-blob logic — so a durability failure here pins the fault to the
//! dependency (or our use of it), not the `Fs` layer. This isolation is what
//! proved the present-cache false-absent bug (the `0x077B`→`0x077C` fix) lived in
//! our cache, not the store: this target stays clean while `power_cut` reproduced
//! it. Key index 0 is rewritten on most ops to mirror EF_META — the hottest key,
//! rewritten whole on every `meta_add`, and so the one most exposed to a torn
//! migration. The flash is sized small (8 pages) so reclaim/migration happens
//! within a single exec.
//!
//! Contract asserted (same as the on-device promise): after any number of
//! power-cuts + reboots, every key whose write/remove returned cleanly reads
//! back EXACTLY; only the one operation interrupted by the cut may be ambiguous
//! (its old value or its new value — never a third, older value).

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use embassy_futures::block_on;
use embedded_storage_async::nor_flash::{ErrorType, MultiwriteNorFlash, NorFlash, ReadNorFlash};
use libfuzzer_sys::fuzz_target;
use sequential_storage::cache::Cache as SsCache;
use sequential_storage::cache::key_pointers::ArrayKeyPointers;
use sequential_storage::cache::page_pointers::ArrayPagePointers;
use sequential_storage::cache::page_states::ArrayPageStates;
use sequential_storage::map::{MapConfig, MapStorage};
use sequential_storage::mock_flash::{MockFlashBase, MockFlashError, Operation, WriteCountCheck};

const WORD: usize = 4;
const PAGE_WORDS: usize = 1024;
type Mock = MockFlashBase<8, WORD, PAGE_WORDS>;
const RANGE: core::ops::Range<u32> = 0..(8 * 4096);
// The device's scratch, derived rather than copied: `rsk-store` asserts
// `MAX_VALUE_BYTES == KV_BUF - 2`, so a literal here silently stops mirroring the
// store the moment that ceiling moves (it did, 2046 -> 4078).
const KV_BUF: usize = rsk_fs::MAX_VALUE_BYTES + 2;
type Cache = SsCache<ArrayPageStates<8>, ArrayPagePointers<8>, ArrayKeyPointers<u16, 16>, u16>;

// Key 0 is the "hot" key (EF_META analog); the rest are cold occupants that make
// migration copy real data.
const KEYS: [u16; 5] = [0xE010, 0xB000, 0xB001, 0xB002, 0xB003];

#[derive(Clone)]
struct SharedMock {
    flash: Rc<RefCell<Mock>>,
    dead: Rc<Cell<bool>>,
}

impl ErrorType for SharedMock {
    type Error = MockFlashError;
}
impl ReadNorFlash for SharedMock {
    const READ_SIZE: usize = <Mock as ReadNorFlash>::READ_SIZE;
    async fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        block_on(self.flash.borrow_mut().read(offset, bytes))
    }
    fn capacity(&self) -> usize {
        self.flash.borrow().capacity()
    }
}
impl NorFlash for SharedMock {
    const WRITE_SIZE: usize = <Mock as NorFlash>::WRITE_SIZE;
    const ERASE_SIZE: usize = <Mock as NorFlash>::ERASE_SIZE;
    async fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        if self.dead.get() {
            return Err(MockFlashError::EarlyShutoff(from, Operation::Erase));
        }
        let r = block_on(self.flash.borrow_mut().erase(from, to));
        if matches!(r, Err(MockFlashError::EarlyShutoff(..))) {
            self.dead.set(true);
        }
        r
    }
    async fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        if self.dead.get() {
            return Err(MockFlashError::EarlyShutoff(offset, Operation::Write));
        }
        let r = block_on(self.flash.borrow_mut().write(offset, bytes));
        if matches!(r, Err(MockFlashError::EarlyShutoff(..))) {
            self.dead.set(true);
        }
        r
    }
}
impl MultiwriteNorFlash for SharedMock {}

type Store = MapStorage<u16, SharedMock, Cache>;

fn read_key(store: &mut Store, buf: &mut [u8], k: u16) -> Option<Vec<u8>> {
    let v = block_on(store.fetch_item::<&[u8]>(buf, &k)).ok()??;
    Some(v.to_vec())
}

enum Pending {
    Write(u16, Vec<u8>),
    Remove(u16),
}

fn reboot_verify(
    shared: &SharedMock,
    committed: &mut HashMap<u16, Vec<u8>>,
    mut pending: Option<Pending>,
) {
    loop {
        shared.dead.set(false);
        let mut store = Store::new(
            shared.clone(),
            MapConfig::new(RANGE),
            Cache::new(
                ArrayPageStates::new(),
                ArrayPagePointers::new(),
                ArrayKeyPointers::new(),
            ),
        );
        let mut buf = [0u8; KV_BUF];

        // Resolve the interrupted op from what the flash actually holds.
        match &pending {
            Some(Pending::Write(k, new)) => {
                let got = read_key(&mut store, &mut buf, *k);
                if shared.dead.get() {
                    continue;
                }
                let old = committed.get(k).cloned();
                assert!(
                    got == old || got.as_ref() == Some(new),
                    "torn write: neither old nor new (rollback past committed)"
                );
                match got {
                    Some(v) => committed.insert(*k, v),
                    None => committed.remove(k),
                };
            }
            Some(Pending::Remove(k)) => {
                let got = read_key(&mut store, &mut buf, *k);
                if shared.dead.get() {
                    continue;
                }
                let old = committed.get(k).cloned();
                assert!(got == old || got.is_none(), "torn remove: garbage");
                match got {
                    Some(v) => committed.insert(*k, v),
                    None => committed.remove(k),
                };
            }
            None => {}
        }
        if shared.dead.get() {
            continue;
        }
        pending = None;

        // Durability sweep: every committed key reads back exactly.
        let mut clean = true;
        for (k, v) in committed.iter() {
            let got = read_key(&mut store, &mut buf, *k);
            if shared.dead.get() {
                clean = false;
                break;
            }
            assert_eq!(
                got.as_deref(),
                Some(v.as_slice()),
                "committed value lost or rolled back after cut"
            );
        }
        if clean {
            return;
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let flash = Rc::new(RefCell::new(Mock::new(
        WriteCountCheck::Disabled,
        None,
        true,
    )));
    let dead = Rc::new(Cell::new(false));
    let shared = SharedMock { flash, dead };
    let mut store = Store::new(
        shared.clone(),
        MapConfig::new(RANGE),
        Cache::new(
            ArrayPageStates::new(),
            ArrayPagePointers::new(),
            ArrayKeyPointers::new(),
        ),
    );
    let mut buf = [0u8; KV_BUF];

    let mut committed: HashMap<u16, Vec<u8>> = HashMap::new();
    let mut tag: u8 = 0;

    let mut it = data.iter().copied();
    while let Some(b) = it.next() {
        // Bias key selection hard toward index 0 (the hot EF_META analog).
        let ki = if b & 0x80 != 0 {
            0
        } else {
            ((b >> 3) % 5) as usize
        };
        let key = KEYS[ki];
        tag = tag.wrapping_add(0x35);

        if b & 0x40 != 0
            && !shared.dead.get()
            && shared.flash.borrow().bytes_until_shutoff.is_none()
        {
            let hi = it.next().unwrap_or(0);
            let lo = it.next().unwrap_or(64);
            shared.flash.borrow_mut().bytes_until_shutoff =
                Some(u32::from_be_bytes([0, 0, hi & 0x0F, lo]));
        }

        let mut pending = None;
        match b & 3 {
            0 | 1 => {
                let len = (it.next().unwrap_or(0) as usize).min(96);
                let v: Vec<u8> = (0..len).map(|j| (j as u8) ^ tag).collect();
                let r = block_on(store.store_item::<&[u8]>(&mut buf, &key, &v.as_slice()));
                if !shared.dead.get() {
                    r.expect("clean store must succeed");
                    committed.insert(key, v);
                } else {
                    pending = Some(Pending::Write(key, v));
                }
            }
            2 => {
                let r = block_on(store.remove_item(&mut buf, &key));
                if !shared.dead.get() {
                    r.expect("clean remove must succeed");
                    committed.remove(&key);
                } else {
                    pending = Some(Pending::Remove(key));
                }
            }
            _ => {
                // Clean reboot — full re-mount and durability check.
                reboot_verify(&shared, &mut committed, None);
                store = Store::new(
                    shared.clone(),
                    MapConfig::new(RANGE),
                    Cache::new(
                        ArrayPageStates::new(),
                        ArrayPagePointers::new(),
                        ArrayKeyPointers::new(),
                    ),
                );
                continue;
            }
        }

        if shared.dead.get() {
            reboot_verify(&shared, &mut committed, pending);
            store = Store::new(
                shared.clone(),
                MapConfig::new(RANGE),
                Cache::new(
                    ArrayPageStates::new(),
                    ArrayPagePointers::new(),
                    ArrayKeyPointers::new(),
                ),
            );
        }
    }
});
