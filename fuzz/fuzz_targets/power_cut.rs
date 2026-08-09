// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Power-cut torture for the rsk-fs flash stack. `fs_ops` proves the `Fs`
//! bookkeeping over clean reboots; this target cuts the power *mid-write* and
//! *mid-erase*. The stack is the device's own — [`rsk_store::SeqStorage`], the
//! same two `sequential-storage` map partitions with the same FID routing — over
//! `MockFlashBase` and its byte-granular `bytes_until_shutoff` injector, sized
//! small (8 + 4 pages) so page migration and reclaim, where a torn write hurts
//! most, happen within a fuzz exec.
//!
//! It used to be a hand-written mirror of `firmware/src/flash_storage.rs`, which
//! could only ever be as right as whoever last synced it — and it had drifted: no
//! `last_error` (so the torture could not see a read fault reported as one), no
//! `compact` (the scrub lap went unfuzzed), and one counter FID missing from the
//! routing. Torturing the shipped code removes that whole class of doubt.
//!
//! The fuzzer drives Fs/meta ops with a shadow model and arms a cut budget at
//! chosen points. Once a cut fires, a `dead` latch fails every further
//! mutation until "reboot" — a dead device cannot keep writing (`Fs::delete`
//! swallows the `meta_delete` error and would otherwise continue). On reboot
//! the whole stack is rebuilt with FRESH caches (RAM does not survive) over
//! the same flash bytes, and the model is checked: the interrupted operation
//! may have landed or not (atomicity — old or new value, never garbage, and
//! for `delete` never value-gone-but-meta-alive, the inverse of its documented
//! order), every *committed* file must read back exactly (durability — a
//! spurious `None` here is the on-device "seed lost, regenerate" disaster),
//! and the live key set must match. Cuts landing inside the post-cut repair
//! or the next mount are themselves survived by rebooting again.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, HashMap};
use std::rc::Rc;

use embassy_futures::block_on;
use embedded_storage_async::nor_flash::{ErrorType, MultiwriteNorFlash, NorFlash, ReadNorFlash};
use libfuzzer_sys::fuzz_target;
use rsk_fs::{EF_META, Fs};
use rsk_store::SeqStorage;
use sequential_storage::cache::Cache;
use sequential_storage::cache::key_pointers::ArrayKeyPointers;
use sequential_storage::cache::page_pointers::ArrayPagePointers;
use sequential_storage::cache::page_states::ArrayPageStates;
use sequential_storage::mock_flash::{MockFlashBase, MockFlashError, Operation, WriteCountCheck};

// One 48 KiB flash: pages 0..8 main, 8..12 counter (4 KiB pages, 4-byte words).
const WORD: usize = 4;
const PAGE_WORDS: usize = 1024;
type Mock = MockFlashBase<12, WORD, PAGE_WORDS>;
const MAIN_RANGE: core::ops::Range<u32> = 0..(8 * 4096);
const COUNTER_RANGE: core::ops::Range<u32> = (8 * 4096)..(12 * 4096);
const META_MAX: usize = 1024;

type MainCache = Cache<ArrayPageStates<8>, ArrayPagePointers<8>, ArrayKeyPointers<u16, 32>, u16>;
type CounterCache = Cache<ArrayPageStates<4>, ArrayPagePointers<4>, ArrayKeyPointers<u16, 4>, u16>;

// Five main-partition FIDs plus every counter-routed one
// (`rsk_store::is_counter_fid`) — both partitions get torn. The mirror this
// replaced listed only three of the four; `EF_CRED_CTR` (0xC001), rewritten on
// every getAssertion, was the one it missed.
const FIDS: [u16; 9] = [
    0xB000, 0xB001, 0xB002, 0xB003, 0xB004, 0xC000, 0xC001, 0x0093, 0xCC01,
];

/// The `SharedFlash` analog: one mock flash shared by both partitions, plus
/// the power latch. Mutations after a fired cut fail without touching flash.
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
    async fn read(
        &mut self,
        offset: u32,
        bytes: &mut [u8],
    ) -> core::result::Result<(), Self::Error> {
        block_on(self.flash.borrow_mut().read(offset, bytes))
    }
    fn capacity(&self) -> usize {
        self.flash.borrow().capacity()
    }
}
impl NorFlash for SharedMock {
    const WRITE_SIZE: usize = <Mock as NorFlash>::WRITE_SIZE;
    const ERASE_SIZE: usize = <Mock as NorFlash>::ERASE_SIZE;
    async fn erase(&mut self, from: u32, to: u32) -> core::result::Result<(), Self::Error> {
        if self.dead.get() {
            return Err(MockFlashError::EarlyShutoff(from, Operation::Erase));
        }
        let r = block_on(self.flash.borrow_mut().erase(from, to));
        if matches!(r, Err(MockFlashError::EarlyShutoff(..))) {
            self.dead.set(true);
        }
        r
    }
    async fn write(&mut self, offset: u32, bytes: &[u8]) -> core::result::Result<(), Self::Error> {
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

/// The device's store over the cuttable mock. Errors are collapsed exactly as
/// the firmware collapses them, because this *is* the firmware's collapsing.
type TortureStorage = SeqStorage<SharedMock, MainCache, CounterCache>;

fn new_storage(flash: SharedMock) -> TortureStorage {
    TortureStorage::new(
        flash,
        MAIN_RANGE,
        COUNTER_RANGE,
        MainCache::new(
            ArrayPageStates::new(),
            ArrayPagePointers::new(),
            ArrayKeyPointers::new(),
        ),
        CounterCache::new(
            ArrayPageStates::new(),
            ArrayPagePointers::new(),
            ArrayKeyPointers::new(),
        ),
    )
}

/// What the power cut interrupted — the only operation whose outcome is
/// allowed to be ambiguous after the reboot.
enum Pending {
    Put(u16, Vec<u8>),
    Delete(u16),
    MetaAdd(u16, Vec<u8>, bool),
    MetaDelete(u16),
}

/// Reboot until a mount + full model check completes without a (re-armed or
/// repair-triggered) cut, resolving `pending` ambiguity on the first stable
/// observation. The cut budget self-disarms when it fires, so this loop
/// terminates.
fn reboot_verify(
    shared: &SharedMock,
    fs: &mut Fs<TortureStorage>,
    val: &mut HashMap<u16, Vec<u8>>,
    meta: &mut HashMap<u16, Vec<u8>>,
    mut pending: Option<Pending>,
) {
    loop {
        shared.dead.set(false);
        *fs = Fs::new(new_storage(shared.clone()));
        fs.scan();
        if shared.dead.get() {
            continue; // the cut landed inside the mount/repair — die again
        }

        // Resolve the interrupted op from what the flash actually holds.
        let mut buf = [0u8; 256];
        match &pending {
            Some(Pending::Put(f, new)) => {
                let got = fs.read(*f, &mut buf).map(|n| buf[..n.min(256)].to_vec());
                let old = val.get(f).cloned();
                assert!(
                    got == old || got.as_deref() == Some(new),
                    "torn put: neither old nor new"
                );
                match got {
                    Some(v) => val.insert(*f, v),
                    None => val.remove(f),
                };
            }
            Some(Pending::Delete(f)) => {
                let got_v = fs.read(*f, &mut buf).map(|n| buf[..n.min(256)].to_vec());
                let mut mb = [0u8; 256];
                let got_m = fs.meta_find(*f, &mut mb).map(|n| mb[..n.min(256)].to_vec());
                let old_v = val.get(f).cloned();
                let old_m = meta.get(f).cloned();
                // delete drops meta FIRST: value-gone-but-meta-alive is the
                // one state the order forbids.
                let ok = (got_v == old_v && got_m == old_m)
                    || (got_v == old_v && got_m.is_none())
                    || (got_v.is_none() && got_m.is_none());
                assert!(ok, "torn delete: forbidden intermediate state");
                match got_v {
                    Some(v) => val.insert(*f, v),
                    None => val.remove(f),
                };
                match got_m {
                    Some(m) => meta.insert(*f, m),
                    None => meta.remove(f),
                };
            }
            Some(Pending::MetaAdd(f, new, fits)) => {
                let mut mb = [0u8; 256];
                let got = fs.meta_find(*f, &mut mb).map(|n| mb[..n.min(256)].to_vec());
                let old = meta.get(f).cloned();
                assert!(
                    got == old || (*fits && got.as_deref() == Some(new)),
                    "torn meta_add: neither old nor new"
                );
                match got {
                    Some(m) => meta.insert(*f, m),
                    None => meta.remove(f),
                };
            }
            Some(Pending::MetaDelete(f)) => {
                let mut mb = [0u8; 256];
                let got = fs.meta_find(*f, &mut mb).map(|n| mb[..n.min(256)].to_vec());
                let old = meta.get(f).cloned();
                assert!(got == old || got.is_none(), "torn meta_delete: garbage");
                match got {
                    Some(m) => meta.insert(*f, m),
                    None => meta.remove(f),
                };
            }
            None => {}
        }
        if shared.dead.get() {
            continue; // a repair write inside the resolution reads was cut
        }
        pending = None; // resolved against stable flash — now committed

        // Durability sweep: every committed file and meta record must read
        // back exactly; the key set must be the model's (EF_META may linger
        // physically after the last meta record's delete was cut).
        let mut clean = true;
        for f in FIDS {
            let got = fs.read(f, &mut buf).map(|n| buf[..n.min(256)].to_vec());
            let mut mb = [0u8; 256];
            let got_m = fs.meta_find(f, &mut mb).map(|n| mb[..n.min(256)].to_vec());
            if shared.dead.get() {
                clean = false;
                break;
            }
            assert_eq!(got, val.get(&f).cloned(), "committed file lost or changed");
            assert_eq!(
                got_m,
                meta.get(&f).cloned(),
                "committed meta lost or changed"
            );
        }
        if !clean {
            continue;
        }
        let mut live = BTreeSet::new();
        fs.for_each_key(&mut |k| {
            live.insert(k);
        });
        if shared.dead.get() {
            continue;
        }
        let want: BTreeSet<u16> = val.keys().copied().collect();
        assert!(live.is_superset(&want), "committed key missing after cut");
        assert!(
            live.difference(&want).all(|&k| k == EF_META),
            "unexpected key after cut"
        );
        if !meta.is_empty() {
            assert!(live.contains(&EF_META));
        }
        return;
    }
}

fuzz_target!(|data: &[u8]| {
    let flash = Rc::new(RefCell::new(Mock::new(
        // Twice, not OnceOnly: remove_item rewrites the header once (erase_data,
        // crc=None), which OnceOnly would false-flag; this catches a 3rd write.
        WriteCountCheck::Twice,
        None,
        true,
    )));
    let dead = Rc::new(Cell::new(false));
    let shared = SharedMock {
        flash: flash.clone(),
        dead: dead.clone(),
    };
    let mut fs = Fs::new(new_storage(shared.clone()));
    fs.scan();

    let mut val: HashMap<u16, Vec<u8>> = HashMap::new();
    let mut meta: HashMap<u16, Vec<u8>> = HashMap::new();
    let mut tag: u8 = 0;

    let mut it = data.iter().copied();
    while let Some(b) = it.next() {
        let fid = FIDS[((b >> 3) & 7) as usize];
        tag = tag.wrapping_add(0x35);

        // Bit 6 arms the power cut: the budget (in flash bytes touched by
        // writes/erases) decides where inside the op — or a later one, or the
        // next mount's repair — the lights go out.
        if b & 0x40 != 0 {
            let m = flash.borrow().bytes_until_shutoff.is_none();
            if m && !dead.get() {
                let hi = it.next().unwrap_or(0);
                let lo = it.next().unwrap_or(64);
                flash.borrow_mut().bytes_until_shutoff =
                    Some(u32::from_be_bytes([0, 0, hi & 0x0F, lo]));
            }
        }

        let mut pending = None;
        match b & 7 {
            0 => {
                let len = (it.next().unwrap_or(0) as usize).min(64);
                let v: Vec<u8> = (0..len).map(|j| (j as u8) ^ tag).collect();
                let r = fs.put(fid, &v);
                if !dead.get() {
                    r.unwrap();
                    val.insert(fid, v);
                } else {
                    pending = Some(Pending::Put(fid, v));
                }
            }
            1 => {
                let cap = (it.next().unwrap_or(0) as usize).min(255);
                let mut buf = [0u8; 255];
                let got = fs.read(fid, &mut buf[..cap]);
                if !dead.get() {
                    match val.get(&fid) {
                        Some(v) => {
                            let n = got.expect("present file must read");
                            assert_eq!(n, v.len());
                            let m = n.min(cap);
                            assert_eq!(&buf[..m], &v[..m]);
                        }
                        None => assert!(got.is_none()),
                    }
                }
            }
            2 => {
                let r = fs.delete(fid);
                if !dead.get() {
                    r.unwrap();
                    val.remove(&fid);
                    meta.remove(&fid);
                } else {
                    pending = Some(Pending::Delete(fid));
                }
            }
            3 => {
                let len = (it.next().unwrap_or(0) as usize).min(64);
                let v: Vec<u8> = (0..len).map(|j| (j as u8) ^ tag).collect();
                let rebuilt: usize = meta
                    .iter()
                    .filter(|(f, _)| **f != fid)
                    .map(|(_, m)| 4 + m.len())
                    .sum::<usize>()
                    + 4
                    + len;
                let fits = rebuilt <= META_MAX;
                let r = fs.meta_add(fid, &v);
                if !dead.get() {
                    if fits {
                        r.unwrap();
                        meta.insert(fid, v);
                    } else {
                        assert!(r.is_err());
                    }
                } else {
                    pending = Some(Pending::MetaAdd(fid, v, fits));
                }
            }
            4 => {
                let mut out = [0u8; 64];
                let got = fs.meta_find(fid, &mut out);
                if !dead.get() {
                    match meta.get(&fid) {
                        Some(v) => {
                            let n = got.expect("present meta must be found");
                            assert_eq!(n, v.len());
                            let m = n.min(out.len());
                            assert_eq!(&out[..m], &v[..m]);
                        }
                        None => assert!(got.is_none()),
                    }
                }
            }
            5 => {
                let r = fs.meta_delete(fid);
                if !dead.get() {
                    r.unwrap();
                    meta.remove(&fid);
                } else {
                    pending = Some(Pending::MetaDelete(fid));
                }
            }
            6 => {
                // Clean reboot — same full re-mount and model check.
                reboot_verify(&shared, &mut fs, &mut val, &mut meta, None);
                continue;
            }
            _ => {
                if !dead.get() {
                    let mut buf = [0u8; 0];
                    match val.get(&fid) {
                        Some(v) => assert_eq!(fs.read(fid, &mut buf), Some(v.len())),
                        None => assert_eq!(fs.read(fid, &mut buf), None),
                    }
                }
            }
        }

        if dead.get() {
            reboot_verify(&shared, &mut fs, &mut val, &mut meta, pending);
        }
    }
});
