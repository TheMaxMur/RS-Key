// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn metadata_reservation_failures_preserve_existing_records_without_a_write() {
    let mut fs = Fs::new(CountingStorage::new());
    fs.meta_add(KEY_DEV, b"original").unwrap();
    for (fid, reserve) in [
        (KEY_DEV + 1, META_MAX),
        (KEY_DEV + 1, usize::MAX),
        (KEY_DEV + 1, META_MAX - 8),
        (KEY_DEV, META_MAX - META_REC_HDR),
    ] {
        let writes = fs.storage.write_calls;
        assert_eq!(
            fs.meta_add_reserve(fid, b"new", reserve),
            Err(Error::NoMemory)
        );
        assert_eq!(fs.storage.write_calls, writes);
        let mut out = [0xA5; 16];
        assert_eq!(fs.meta_find(KEY_DEV, &mut out), Some(8));
        assert_eq!(&out[..8], b"original");
        assert_eq!(fs.meta_find(KEY_DEV + 1, &mut out), None);
    }
    fs.meta_add_reserve(KEY_DEV + 1, b"new", 8).unwrap();
    let mut fs = Fs::new(fs.into_storage());
    fs.scan();
    let mut out = [0u8; 16];
    assert_eq!(fs.meta_find(KEY_DEV, &mut out), Some(8));
    assert_eq!(&out[..8], b"original");
    assert_eq!(fs.meta_find(KEY_DEV + 1, &mut out), Some(3));
    assert_eq!(&out[..3], b"new");
}

struct MarkerRefusingCompact {
    inner: TearableCompact,
    marker_refusals: u8,
}

impl Storage for MarkerRefusingCompact {
    fn read(&mut self, fid: u16, out: &mut [u8]) -> Option<usize> {
        self.inner.read(fid, out)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
        if fid == crate::EF_HARDENED && self.marker_refusals != 0 {
            self.marker_refusals -= 1;
            return Err(Error::MemoryFatal);
        }
        self.inner.write(fid, data)
    }
    fn remove(&mut self, fid: u16) -> Result<()> {
        self.inner.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.inner.size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(f)
    }
    fn compact(&mut self) -> Result<()> {
        self.inner.compact()
    }
}

#[test]
fn a_failed_lap_and_repeated_marker_failures_retry_across_fresh_mounts() {
    let mut storage = MarkerRefusingCompact {
        inner: TearableCompact::new(true),
        marker_refusals: 2,
    };
    storage.write(KEY_DEV, b"live").unwrap();
    for lap in 1..=4 {
        let mut fs = Fs::new(storage);
        fs.scan();
        crate::run_at_rest_lap(&mut fs);
        storage = fs.into_storage();
        assert_eq!(storage.inner.laps, lap);
        assert_eq!(storage.exists(crate::EF_HARDENED), lap == 4);
        let mut out = [0u8; 4];
        assert_eq!(storage.read(KEY_DEV, &mut out), Some(4));
        assert_eq!(&out, b"live");
        storage.inner.tears = false;
    }
    let mut fs = Fs::new(storage);
    fs.scan();
    crate::run_at_rest_lap(&mut fs);
    let mut storage = fs.into_storage();
    assert_eq!(
        storage.inner.laps, 4,
        "a completed lap must gate the next boot"
    );
    assert_eq!(storage.marker_refusals, 0);
    assert!(storage.exists(crate::EF_HARDENED));
}
