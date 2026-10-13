// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::{StorageAction, StorageState};
use rsk_sdk::error::Error;
use std::cell::Cell;
use std::rc::Rc;

struct Recovery {
    inner: RamStorage,
    error: Error,
    action: StorageAction,
    calls: Rc<Cell<usize>>,
}

impl Storage for Recovery {
    fn read(&mut self, fid: u16, output: &mut [u8]) -> Option<usize> {
        self.inner.read(fid, output)
    }
    fn write(&mut self, fid: u16, value: &[u8]) -> rsk_sdk::error::Result<()> {
        self.inner.write(fid, value)
    }
    fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
        self.inner.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.inner.size(fid)
    }
    fn for_each_key(&mut self, visit: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(visit)
    }
    fn state(&self) -> StorageState {
        StorageState::Recovery
    }
    fn administer(&mut self, action: StorageAction, epoch: [u8; 16]) -> rsk_sdk::error::Result<()> {
        assert_eq!(action, self.action);
        assert_ne!(epoch, [0; 16]);
        self.calls.set(self.calls.get() + 1);
        Err(self.error)
    }
}

#[test]
fn recovery_serves_its_status_and_bootsel_but_refuses_other_storage_and_time_access() {
    let rng = RefCell::new(LcgRng(7));
    let platform = RefCell::new(FakePlatform::default());
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = lock_app(&rng, &platform, &presence, None);
    let mut ready = Fs::new(RamStorage::new());
    let status = apdu(0x80, INS_READ, 0x08, 0, &[]);
    assert_eq!(run(&mut app, &mut ready, &status), (Sw::OK, vec![2, 1]));
    let calls = Rc::new(Cell::new(0));
    let mut fs = Fs::new(Recovery {
        inner: RamStorage::new(),
        error: Error::MemoryFatal,
        action: StorageAction::Initialize,
        calls: Rc::clone(&calls),
    });
    fs.scan();
    assert_eq!(run(&mut app, &mut fs, &status), (Sw::OK, vec![2, 0]));
    assert_eq!(
        run(&mut app, &mut fs, &apdu(0x80, INS_READ, 0x01, 0, &[])),
        (Sw::MEMORY_FAILURE, vec![])
    );
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &apdu(0x80, INS_WRITE, 0x02, 0x02, &1u32.to_be_bytes())
        ),
        (Sw::MEMORY_FAILURE, vec![])
    );
    assert_eq!(platform.borrow().time, None);
    assert_eq!(calls.get(), 0);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &apdu(0x80, INS_REBOOT_BOOTSEL, 1, 0, &[])
        ),
        (Sw::OK, vec![])
    );
    assert_eq!(platform.borrow().reboots, [true]);
}

#[test]
fn refused_storage_administration_keeps_its_distinct_status_and_does_not_reboot() {
    for (error, status) in [
        (Error::Blocked, Sw::CONDITIONS_NOT_SATISFIED),
        (Error::MemoryFatal, Sw::MEMORY_FAILURE),
    ] {
        for (p1, action, magic) in [
            (0, StorageAction::Initialize, &b"INITV2"[..]),
            (1, StorageAction::ImportLegacy, &b"IMPORTV2"[..]),
        ] {
            let calls = Rc::new(Cell::new(0));
            let mut inner = RamStorage::new();
            inner.write(0xB000, b"owner").unwrap();
            let mut fs = Fs::new(Recovery {
                inner,
                error,
                action,
                calls: Rc::clone(&calls),
            });
            fs.scan();
            let rng = RefCell::new(LcgRng(7));
            let platform = RefCell::new(FakePlatform::default());
            let presence = RefCell::new(AlwaysConfirm);
            let mut app = lock_app(&rng, &platform, &presence, None);
            let generation = fs.write_gen();
            assert_eq!(
                run(&mut app, &mut fs, &apdu(0x80, INS_STORAGE, p1, 0, magic)),
                (status, Vec::new())
            );
            assert_eq!(calls.get(), 1);
            assert!(platform.borrow().reboots.is_empty());
            assert_eq!(fs.write_gen(), generation);
            let mut owner = [0; 5];
            assert_eq!(fs.read(0xB000, &mut owner), Some(5));
            assert_eq!(&owner, b"owner");
        }
    }
}
