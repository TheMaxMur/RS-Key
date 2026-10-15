// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![cfg_attr(not(test), no_main)]

//! Stateful `Fs` fuzzing against a shadow model. `fs_meta` parses one corrupt
//! blob; this one drives an attacker-chosen *sequence* of file-system
//! operations — put / read / delete / meta_add / meta_find / meta_delete /
//! reboot — over one storage image and checks every result against a
//! `HashMap` reference model. The interesting logic is the `Fs` bookkeeping,
//! not `RamStorage`: the meta side-store rebuild (replace, delete, the exact
//! `META_MAX` NoMemory boundary), the dynamic-file registry surviving an
//! `into_storage` → `scan` reboot, and the read contract every caller must
//! honor — the copy truncates to the buffer, the returned length does not
//! (the mgmt READ CONFIG panic was a caller missing exactly that).
//!
//! FIDs come from a pool of 8 so operations collide constantly; EF_META is
//! never written directly (no applet does), so the meta model stays exact.

use std::collections::{BTreeSet, HashMap};

#[cfg(not(test))]
use libfuzzer_sys as fuzzing;
use rsk_fs::storage::ram::RamStorage;
use rsk_fs::{EF_META, Fs};

const META_MAX: usize = 1024;

pub(crate) fn exercise(data: &[u8]) {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    let mut model: HashMap<u16, Vec<u8>> = HashMap::new();
    let mut meta: HashMap<u16, Vec<u8>> = HashMap::new();
    let mut tag: u8 = 0;

    let mut it = data.iter().copied();
    while let Some(b) = it.next() {
        let fid = 0xB000u16 + ((b >> 3) & 7) as u16;
        // A fresh fill byte per op, so a stale read can't masquerade as the
        // current value.
        tag = tag.wrapping_add(0x35);
        match b & 7 {
            0 => {
                // put: never fails here (the dynamic registry holds 256, the
                // pool is 8).
                let len = it.next().unwrap_or(0) as usize;
                let v: Vec<u8> = (0..len).map(|j| (j as u8) ^ tag).collect();
                fs.put(fid, &v).unwrap();
                model.insert(fid, v);
            }
            1 => {
                // read into a caller-chosen view: full length back, copy
                // clamped to the buffer.
                let cap = (it.next().unwrap_or(0) as usize).min(255);
                let mut buf = [0u8; 255];
                let got = fs.read(fid, &mut buf[..cap]);
                match model.get(&fid) {
                    Some(v) => {
                        let n = got.expect("present file must read");
                        assert_eq!(n, v.len());
                        let m = n.min(cap);
                        assert_eq!(&buf[..m], &v[..m]);
                    }
                    None => assert!(got.is_none()),
                }
            }
            2 => {
                // delete drops contents AND metadata.
                fs.delete(fid).unwrap();
                model.remove(&fid);
                meta.remove(&fid);
            }
            3 => {
                // meta_add: succeeds iff the rebuilt store fits META_MAX, and
                // a NoMemory must leave the store untouched (later finds
                // verify that through the unchanged model).
                let len = it.next().unwrap_or(0) as usize;
                let v: Vec<u8> = (0..len).map(|j| (j as u8) ^ tag).collect();
                let rebuilt: usize = meta
                    .iter()
                    .filter(|(f, _)| **f != fid)
                    .map(|(_, m)| 4 + m.len())
                    .sum::<usize>()
                    + 4
                    + len;
                let r = fs.meta_add(fid, &v);
                if rebuilt <= META_MAX {
                    r.unwrap();
                    meta.insert(fid, v);
                } else {
                    assert!(r.is_err());
                }
            }
            4 => {
                // meta_find mirrors the read contract on the side-store.
                let mut out = [0u8; 64];
                let got = fs.meta_find(fid, &mut out);
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
            5 => {
                fs.meta_delete(fid).unwrap();
                meta.remove(&fid);
            }
            6 => {
                // Reboot: rebuild the Fs over the same image and rescan; both
                // models must keep matching afterwards.
                let storage = fs.into_storage();
                fs = Fs::new(storage);
                fs.scan();
            }
            _ => {
                // size / has_data, plus the global key set: exactly the model
                // files, with EF_META present iff any metadata lives.
                match model.get(&fid) {
                    Some(v) => {
                        assert_eq!(fs.size(fid), Some(v.len()));
                        assert_eq!(fs.has_data(fid), !v.is_empty());
                    }
                    None => {
                        assert_eq!(fs.size(fid), None);
                        assert!(!fs.has_data(fid));
                    }
                }
                let mut live = BTreeSet::new();
                fs.for_each_key(&mut |f| {
                    live.insert(f);
                });
                let mut want: BTreeSet<u16> = model.keys().copied().collect();
                if !meta.is_empty() {
                    want.insert(EF_META);
                }
                assert_eq!(live, want);
            }
        }
    }
}

#[cfg(not(test))]
fuzzing::fuzz_target!(|data: &[u8]| exercise(data));
