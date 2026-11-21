// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use std::vec::Vec;

struct BoundStorage {
    inner: RamStorage,
    read: Result<Option<usize>>,
    write: Result<bool>,
    reads: Vec<u16>,
    writes: Vec<(u16, Vec<u8>)>,
}

impl Storage for BoundStorage {
    fn read(&mut self, fid: u16, out: &mut [u8]) -> Option<usize> {
        self.inner.read(fid, out)
    }

    fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
        self.inner.write(fid, data)
    }

    fn remove(&mut self, fid: u16) -> Result<()> {
        self.inner.remove(fid)
    }

    fn size(&mut self, fid: u16) -> Option<usize> {
        self.inner.size(fid)
    }

    fn for_each_key(&mut self, visit: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(visit)
    }

    fn read_bound_counter(&mut self, fid: u16, out: &mut [u8]) -> Result<Option<usize>> {
        self.reads.push(fid);
        if let Ok(Some(length)) = self.read {
            let count = length.min(out.len());
            out[..count].copy_from_slice(&b"sealed"[..count]);
        }
        self.read
    }

    fn write_bound_counter(&mut self, fid: u16, sealed: &[u8]) -> Result<bool> {
        self.writes.push((fid, sealed.to_vec()));
        self.write
    }
}

#[test]
fn bound_counter_reads_forward_the_owner_buffer_absence_and_error_without_a_write() {
    let owner = KeyFid::new(crate::counter::OATH_FIRST + 7);
    for outcome in [Ok(Some(6)), Ok(None), Err(Error::MemoryFatal)] {
        let mut fs = Fs::new(BoundStorage {
            inner: RamStorage::new(),
            read: outcome,
            write: Ok(false),
            reads: Vec::new(),
            writes: Vec::new(),
        });
        let mut out = [0xA5; 2];
        assert_eq!(fs.read_bound_counter(owner, &mut out), outcome);
        assert_eq!(fs.storage.reads, vec![owner.get()]);
        assert_eq!(
            out,
            if outcome == Ok(Some(6)) {
                *b"se"
            } else {
                [0xA5; 2]
            }
        );
        assert_eq!(fs.write_gen(), 0);
        assert!(fs.storage.writes.is_empty());
    }
}

#[test]
fn bound_counter_publication_forwards_bytes_and_only_success_advances_generation() {
    let owner = KeyFid::new(crate::counter::OATH_FIRST + 13);
    for outcome in [Ok(true), Ok(false), Err(Error::MemoryFatal)] {
        for before in [0, u32::MAX] {
            let mut fs = Fs::new(BoundStorage {
                inner: RamStorage::new(),
                read: Ok(None),
                write: outcome,
                reads: Vec::new(),
                writes: Vec::new(),
            });
            fs.write_gen = before;
            assert_eq!(
                fs.write_bound_counter(owner, Sealed::wrap(b"sealed")),
                outcome
            );
            assert_eq!(fs.storage.writes, vec![(owner.get(), b"sealed".to_vec())]);
            assert_eq!(
                fs.write_gen(),
                if outcome == Ok(true) {
                    before.wrapping_add(1)
                } else {
                    before
                }
            );
            assert!(fs.storage.reads.is_empty());
        }
    }
}

#[test]
fn backends_without_a_bound_journal_request_fallback_without_touching_the_owner() {
    let mut fs = fs();
    let owner = KeyFid::new(crate::counter::OATH_FIRST);
    fs.put_key(owner, Sealed::wrap(b"credential")).unwrap();
    let generation = fs.write_gen();
    let mut out = [0xA5; 10];
    assert_eq!(fs.read_bound_counter(owner, &mut out), Ok(None));
    assert_eq!(out, [0xA5; 10]);
    assert_eq!(
        fs.write_bound_counter(owner, Sealed::wrap(b"counter")),
        Ok(false)
    );
    assert_eq!(fs.write_gen(), generation);
    assert_eq!(fs.read_key(owner, &mut out), Some(10));
    assert_eq!(&out, b"credential");
}
