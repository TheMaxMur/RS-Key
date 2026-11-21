// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::storage::StorageAction;

struct LifecycleStorage {
    inner: RamStorage,
    closed: bool,
    refuse: bool,
    mounts: usize,
    administration: std::vec::Vec<(StorageAction, [u8; 16])>,
}

impl LifecycleStorage {
    fn new(refuse: bool) -> Self {
        Self {
            inner: RamStorage::new(),
            closed: false,
            refuse,
            mounts: 0,
            administration: std::vec::Vec::new(),
        }
    }
}

impl Storage for LifecycleStorage {
    fn root_closed(&self) -> bool {
        self.closed
    }
    fn mount(&mut self) -> Result<()> {
        self.mounts += 1;
        if self.refuse {
            Err(Error::MemoryFatal)
        } else {
            Ok(())
        }
    }
    fn administer(&mut self, action: StorageAction, epoch: [u8; 16]) -> Result<()> {
        self.administration.push((action, epoch));
        if self.refuse {
            Err(Error::Blocked)
        } else {
            Ok(())
        }
    }
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
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(f)
    }
}

#[test]
fn storage_root_closure_is_the_backends_current_answer() {
    let mut fs = Fs::new(LifecycleStorage::new(false));
    assert!(!fs.storage_root_closed());
    fs.storage.closed = true;
    assert!(fs.storage_root_closed());
}

#[test]
fn mounting_storage_delegates_and_invalidates_absence_even_on_refusal() {
    for refuse in [false, true] {
        let mut fs = Fs::new(LifecycleStorage::new(refuse));
        assert_eq!(fs.try_exists(KEY_DEV), Ok(false));
        fs.storage.inner.write(KEY_DEV, b"new authority").unwrap();
        assert_eq!(
            fs.mount_storage(),
            if refuse {
                Err(Error::MemoryFatal)
            } else {
                Ok(())
            },
            "mount must preserve the backend result"
        );
        assert_eq!(fs.storage.mounts, 1, "mount must reach the backend");
        assert_eq!(fs.free_dynamic(), 0);
        assert_eq!(fs.try_exists(KEY_DEV), Ok(true));
    }
}

#[test]
fn storage_administration_preserves_action_epoch_result_and_invalidates_absence() {
    for action in [StorageAction::Initialize, StorageAction::ImportLegacy] {
        for refuse in [false, true] {
            let mut fs = Fs::new(LifecycleStorage::new(refuse));
            assert_eq!(fs.try_exists(KEY_DEV), Ok(false));
            fs.storage.inner.write(KEY_DEV, b"new authority").unwrap();
            let epoch = [0x4B; 16];
            assert_eq!(
                fs.administer_storage(action, epoch),
                if refuse { Err(Error::Blocked) } else { Ok(()) },
                "administration must preserve the backend result"
            );
            assert_eq!(fs.storage.administration, [(action, epoch)]);
            assert_eq!(fs.free_dynamic(), 0);
            assert_eq!(fs.try_exists(KEY_DEV), Ok(true));
        }
    }
}

#[test]
fn visible_write_generation_advances_after_put_overwrite_and_delete() {
    let mut fs = fs();
    assert_eq!(fs.write_gen(), 0);
    fs.put(KEY_DEV, b"old owner").unwrap();
    assert_eq!(fs.write_gen(), 1);
    fs.put(KEY_DEV, b"new owner").unwrap();
    assert_eq!(fs.write_gen(), 2);
    assert_eq!(fs.read(KEY_DEV, &mut [0; 16]), Some(9));
    assert_eq!(fs.write_gen(), 2);
    fs.delete(KEY_DEV).unwrap();
    assert_eq!(fs.write_gen(), 3);
    fs.delete(KEY_DEV).unwrap();
    assert_eq!(fs.write_gen(), 3);
}

#[test]
fn conditional_rescrub_rearms_only_the_write_over_a_pre_otp_copy() {
    let mut fs = fs();
    fs.put(crate::EF_HARDENED, &[1]).unwrap();
    assert!(crate::request_rescrub_if(&mut fs, false).unwrap().is_none());
    assert!(fs.has_data(crate::EF_HARDENED));
    assert!(crate::request_rescrub_if(&mut fs, true).unwrap().is_some());
    assert!(!fs.has_data(crate::EF_HARDENED));
}
