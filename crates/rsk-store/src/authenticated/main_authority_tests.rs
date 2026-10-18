// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::{Effect, Io, Rule};

#[derive(Clone, Copy)]
enum Change {
    Write,
    DeleteSnapshot,
    Rekey,
}

fn change<F: MultiwriteNorFlash + Clone>(
    main: &mut Main<F, UncachedMap>,
    action: Change,
) -> Result<()> {
    match action {
        Change::Write => main.write(&KEY, 0xB000, Some(b"new")),
        Change::DeleteSnapshot => main.write(&KEY, 0xB000, None),
        Change::Rekey => main.rekey(&KEY, &[0x47; 32], RootArm::Otp),
    }
}

#[test]
fn verified_publication_survives_a_second_replica_failure_and_live_replay() {
    for (action, replay_abort) in [
        (Change::Write, false),
        (Change::Write, true),
        (Change::DeleteSnapshot, false),
        (Change::Rekey, false),
    ] {
        let baseline = crate::tests::fault_flash_for_authenticated_tests();
        let mut main = main_on(baseline.clone());
        main.initialize(&KEY, 0, &Directory::new()).unwrap();
        main.write(&KEY, 0xB000, Some(b"old")).unwrap();
        if matches!(action, Change::DeleteSnapshot) {
            loop {
                let scan = main.journals[0]
                    .scan(&KEY, &mut Directory::<MAX_MAIN_ENTRIES>::new())
                    .unwrap();
                if main.journals[0].capacity() - scan.next < u32::try_from(2 * DELTA_BYTES).unwrap()
                {
                    break;
                }
                main.write(&KEY, 0xB000, Some(b"old")).unwrap();
            }
        }
        let current = main.resolve(&KEY).unwrap().unwrap();
        let layout = super::super::super::Layout::new(
            32768..32768 + super::super::super::storage::AUTHORITY_BYTES,
        )
        .unwrap();
        let second = match action {
            Change::Write => {
                layout.main[1].start + current.scans[1].next + u32::try_from(DELTA_BYTES).unwrap()
            }
            Change::DeleteSnapshot | Change::Rekey => layout.main[current.source].start,
        };
        assert_eq!(main.read(&KEY, 0xB000, &mut []), Ok(Some(3)));
        let old = baseline.image();
        let replay = if replay_abort {
            let abort_flash = crate::tests::fault_flash_for_authenticated_tests();
            abort_flash.replace_image_before_read(0, old.clone());
            let mut abort = main_on(abort_flash.clone());
            assert_eq!(abort.read(&KEY, 0xB000, &mut []), Ok(Some(3)));
            let checkpoint = abort.checkpoint(&KEY, current.sequence + 1).unwrap();
            for journal in &mut abort.journals {
                journal
                    .write_snapshot(checkpoint, &KEY, &abort.directory)
                    .unwrap();
            }
            abort_flash.image()
        } else {
            old.clone()
        };
        baseline.arm(&[]);
        change(&mut main, action).unwrap();
        let programs: Vec<_> = baseline
            .events()
            .into_iter()
            .filter(|event| event.0 == Io::Program)
            .collect();
        let skip = programs.iter().position(|event| event.1 == second).unwrap();
        let flash = crate::tests::fault_flash_for_authenticated_tests();
        flash.replace_image_before_read(0, old.clone());
        let mut main = main_on(flash.clone());
        assert_eq!(main.read(&KEY, 0xB000, &mut []), Ok(Some(3)));
        flash.arm(&[Rule {
            io: Io::Program,
            skip,
            effect: Effect::Refuse,
            latched: true,
        }]);
        assert_eq!(change(&mut main, action), Err(Error::MemoryFatal));
        assert!(flash.hits().first().is_some_and(|&hits| hits > 0));
        flash.clear();
        flash.replace_image_before_read(0, replay.clone());
        main.configure(EPOCH, RootArm::PreOtp);
        flash.arm(&[]);
        for _ in 0..2 {
            assert_eq!(
                main.read(&KEY, 0xB000, &mut [0; 3]),
                Err(Error::MemoryFatal)
            );
            assert_eq!(main.read(&KEY, 0xB001, &mut []), Err(Error::MemoryFatal));
            assert_eq!(main.for_each_key(&KEY, |_| {}), Err(Error::MemoryFatal));
            assert_eq!(
                main.write(&KEY, 0xB001, Some(b"other")),
                Err(Error::MemoryFatal)
            );
            assert_eq!(flash.image(), replay);
            assert!(flash.events().iter().all(|event| event.0 == Io::Read));
        }
    }
}

#[test]
fn a_same_sequence_directory_substitution_cannot_invent_mounted_absence() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut main = main_on(flash.clone());
    main.initialize(&KEY, 0, &Directory::new()).unwrap();
    main.write(&KEY, 0xB000, Some(b"owner")).unwrap();
    assert_eq!(main.read(&KEY, 0xB000, &mut []), Ok(Some(5)));
    let mut changed = Directory::<MAX_MAIN_ENTRIES>::new();
    changed
        .apply(Entry::live(main.identity, &KEY, 0xB001, 1, b"other").unwrap())
        .unwrap();
    let checkpoint = Checkpoint {
        entries: 1,
        digest: changed.digest(main.identity, &KEY, 1).unwrap(),
        ..main.checkpoint(&KEY, 1).unwrap()
    };
    for journal in &mut main.journals {
        journal.write_snapshot(checkpoint, &KEY, &changed).unwrap();
    }
    let before = flash.image();
    main.configure(EPOCH, RootArm::PreOtp);
    flash.arm(&[]);
    for _ in 0..2 {
        assert_eq!(main.read(&KEY, 0xB000, &mut []), Err(Error::MemoryFatal));
        assert_eq!(flash.image(), before);
        assert!(flash.events().iter().all(|event| event.0 == Io::Read));
    }
}

#[test]
fn a_failed_unpublished_write_can_be_cancelled_and_retried_in_the_same_backend() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut main = main_on(flash.clone());
    main.initialize(&KEY, 0, &Directory::new()).unwrap();
    main.write(&KEY, 0xB000, Some(b"owner")).unwrap();
    assert_eq!(main.read(&KEY, 0xB000, &mut []), Ok(Some(5)));
    flash.arm(&[Rule {
        io: Io::Program,
        skip: 0,
        effect: Effect::Refuse,
        latched: true,
    }]);
    assert_eq!(
        main.write(&KEY, 0xB000, Some(b"failed")),
        Err(Error::MemoryFatal)
    );
    assert!(flash.hits().first().is_some_and(|&hits| hits > 0));
    flash.clear();
    let mut out = [0; 5];
    assert_eq!(main.read(&KEY, 0xB000, &mut out), Ok(Some(5)));
    assert_eq!(&out, b"owner");
    main.write(&KEY, 0xB000, Some(b"retry")).unwrap();
    assert_eq!(main.read(&KEY, 0xB000, &mut out), Ok(Some(5)));
    assert_eq!(&out, b"retry");
}

#[test]
fn bounded_warm_reads_leave_the_entire_scratch_clean_through_length_changes_and_fallbacks() {
    let mut main = main();
    main.initialize(&KEY, 0, &Directory::new()).unwrap();
    for length in [0, 1, 2, 3, 4, 5, 31, 32, 33, rsk_fs::MAX_VALUE_BYTES] {
        let value = std::vec![0x5a; length];
        main.write(&KEY, 0xB000, Some(&value)).unwrap();
        let mut out = std::vec![0; length];
        for _ in 0..2 {
            assert_eq!(main.read(&KEY, 0xB000, &mut out), Ok(Some(length)));
            assert_eq!(out, value);
            assert!(main.buffer.expose().iter().all(|&byte| byte == 0));
        }
        main.write(&KEY, 0xB001, Some(b"small")).unwrap();
        assert_eq!(main.read(&KEY, 0xB000, &mut []), Ok(Some(length)));
        assert_eq!(main.read(&KEY, 0xB001, &mut []), Ok(Some(5)));
        assert!(main.buffer.expose().iter().all(|&byte| byte == 0));
        main.map.invalidate_cache();
        assert_eq!(main.read(&KEY, 0xB001, &mut []), Ok(Some(5)));
        assert!(main.buffer.expose().iter().all(|&byte| byte == 0));
        assert_eq!(main.read(&KEY, 0xB002, &mut []), Ok(None));
        assert!(main.buffer.expose().iter().all(|&byte| byte == 0));
    }
}

#[test]
fn a_partially_filled_read_error_wipes_the_entire_bounded_span_including_padding() {
    use core::cell::Cell;
    use embedded_storage_async::nor_flash::{ErrorType, NorFlash, ReadNorFlash};
    use std::rc::Rc;
    #[derive(Clone)]
    struct DirtyRead {
        flash: crate::tests::FaultFlash,
        fail_body: Rc<Cell<bool>>,
        hits: Rc<Cell<usize>>,
    }
    impl ErrorType for DirtyRead {
        type Error = crate::tests::FlashFault;
    }
    impl ReadNorFlash for DirtyRead {
        const READ_SIZE: usize = 1;
        async fn read(
            &mut self,
            offset: u32,
            bytes: &mut [u8],
        ) -> core::result::Result<(), Self::Error> {
            if self.fail_body.get() && bytes.len() == 4 {
                self.hits.set(self.hits.get() + 1);
                bytes.fill(0x5a);
                return Err(crate::tests::FlashFault);
            }
            self.flash.read(offset, bytes).await
        }
        fn capacity(&self) -> usize {
            self.flash.capacity()
        }
    }
    impl NorFlash for DirtyRead {
        const WRITE_SIZE: usize = 4;
        const ERASE_SIZE: usize = 4096;
        async fn write(
            &mut self,
            offset: u32,
            bytes: &[u8],
        ) -> core::result::Result<(), Self::Error> {
            self.flash.write(offset, bytes).await
        }
        async fn erase(&mut self, from: u32, to: u32) -> core::result::Result<(), Self::Error> {
            self.flash.erase(from, to).await
        }
    }
    impl MultiwriteNorFlash for DirtyRead {}
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let fail_body = Rc::new(Cell::new(false));
    let hits = Rc::new(Cell::new(0));
    let mut main = main_on(DirtyRead {
        flash,
        fail_body: fail_body.clone(),
        hits: hits.clone(),
    });
    main.initialize(&KEY, 0, &Directory::new()).unwrap();
    main.write(&KEY, 0xB000, Some(b"x")).unwrap();
    assert_eq!(main.read(&KEY, 0xB000, &mut []), Ok(Some(1)));
    fail_body.set(true);
    assert_eq!(main.read(&KEY, 0xB000, &mut []), Err(Error::MemoryFatal));
    assert_eq!(hits.get(), 1);
    assert!(main.buffer.expose().iter().all(|&byte| byte == 0));
    assert!(main.read_cache.is_none());
    fail_body.set(false);
    assert_eq!(main.read(&KEY, 0xB000, &mut []), Ok(Some(1)));
    assert_eq!(main.read(&KEY, 0xB000, &mut []), Ok(Some(1)));
    assert!(main.buffer.expose().iter().all(|&byte| byte == 0));
}
