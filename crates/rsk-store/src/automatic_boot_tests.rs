// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn boot_automatically_migrates_legacy_without_administration() {
    let flash = provision_legacy();
    let mut fs = rsk_fs::Fs::new(managed(&flash, source()));
    fs.scan();
    assert_eq!(fs.try_read(CRED, &mut [0; 32]), Err(Error::MemoryFatal));
    fs.boot_storage([0x4B; 16]).unwrap();
    assert_imported(&mut fs.into_storage());
    assert_imported(&mut managed(&flash, source()));
}

fn unmounted(flash: &FaultFlash) -> ManagedStore {
    Managed::new_unmounted(
        flash.clone(),
        MAIN,
        MAIN.end..MAIN.end + 128 * 1024,
        source(),
        cache,
    )
}

#[test]
fn boot_initializes_blank_media_and_preserves_active_records_without_writes() {
    let flash = FaultFlash::new();
    let mut store = managed(&flash, source());
    store.boot([0x4B; 16]).unwrap();
    assert_eq!(store.state(), StorageState::Ready);
    assert_eq!(store.read(CRED, &mut []), None);
    assert!(!store.last_error());
    store.write(CRED, b"owner").unwrap();
    let saved = flash.inner.bytes.borrow().clone();
    flash.arm(&[]);
    let mut reboot = unmounted(&flash);
    reboot.boot([0x5A; 16]).unwrap();
    assert_eq!(reboot.read(CRED, &mut [0; 32]), Some(5));
    assert_eq!(*flash.inner.bytes.borrow(), saved);
    assert!(flash.events().iter().all(|event| event.0 == Io::Read));
}

#[test]
fn automatic_import_read_faults_refuse_before_any_mutation() {
    let flash = provision_legacy();
    let saved = flash.inner.bytes.borrow().clone();
    flash.arm(&[]);
    unmounted(&flash).boot([0x4B; 16]).unwrap();
    let reads = flash
        .events()
        .iter()
        .take_while(|event| event.0 == Io::Read)
        .count();
    assert!(reads > 0);
    for skip in 0..reads {
        *flash.inner.bytes.borrow_mut() = saved.clone();
        flash.arm(&[Rule {
            io: Io::Read,
            skip,
            effect: Effect::Refuse,
            latched: false,
        }]);
        let mut store = unmounted(&flash);
        assert!(store.boot([0x4B; 16]).is_err(), "read {skip}");
        assert_eq!(store.state(), StorageState::Recovery);
        assert_eq!(flash.hits(), [1]);
        assert_eq!(
            *flash.inner.bytes.borrow(),
            saved,
            "read {skip} changed media"
        );
        assert!(flash.events().iter().all(|event| event.0 == Io::Read));
    }
}

#[test]
fn automatic_boot_never_imports_missing_or_damaged_v2_authority() {
    let flash = provision_legacy();
    unmounted(&flash).boot([0x4B; 16]).unwrap();
    let saved = flash.inner.bytes.borrow().clone();
    let layout = crate::authenticated::Layout::new(MAIN.end..MAIN.end + 128 * 1024).unwrap();
    for erase in [false, true] {
        *flash.inner.bytes.borrow_mut() = saved.clone();
        for range in layout.main.iter().chain(&layout.counter) {
            let header = &mut flash.inner.bytes.borrow_mut()
                [range.start as usize..range.start as usize + 128];
            if erase {
                header.fill(0xFF);
            } else {
                header[80] ^= 0x80;
            }
        }
        let damaged = flash.inner.bytes.borrow().clone();
        flash.arm(&[]);
        let mut reboot = unmounted(&flash);
        assert_eq!(reboot.boot([0x5A; 16]), Err(Error::MemoryFatal));
        assert_eq!(reboot.state(), StorageState::Recovery);
        assert_eq!(*flash.inner.bytes.borrow(), damaged);
        assert!(flash.events().iter().all(|event| event.0 == Io::Read));
    }
}

#[test]
fn damaged_activation_and_unverifiable_v2_headers_cannot_trigger_import() {
    let flash = provision_legacy();
    unmounted(&flash).boot([0x4B; 16]).unwrap();
    let positions: Vec<_> = flash
        .inner
        .bytes
        .borrow()
        .windows(8)
        .enumerate()
        .filter_map(|(index, bytes)| (bytes == b"RSKACT02").then_some(index))
        .collect();
    assert!(!positions.is_empty());
    for position in positions {
        flash.inner.bytes.borrow_mut()[position] ^= 0x80;
    }
    let layout = crate::authenticated::Layout::new(MAIN.end..MAIN.end + 128 * 1024).unwrap();
    for range in layout.main.iter().chain(&layout.counter) {
        flash.inner.bytes.borrow_mut()[range.start as usize + 80] ^= 0x80;
    }
    let damaged = flash.inner.bytes.borrow().clone();
    flash.arm(&[]);
    let mut reboot = unmounted(&flash);
    assert_eq!(reboot.boot([0x5A; 16]), Err(Error::MemoryFatal));
    assert_eq!(reboot.state(), StorageState::Recovery);
    assert_eq!(*flash.inner.bytes.borrow(), damaged);
    assert!(flash.events().iter().all(|event| event.0 == Io::Read));
}

#[test]
fn automatic_import_rejects_nonlegacy_pages_without_repairing_them() {
    for partition in [MAIN, MAIN.end..MAIN.end + 128 * 1024] {
        for damage in [0, 1, 2, 3] {
            let flash = provision_legacy();
            let page = partition.end as usize - FaultFlash::ERASE_SIZE;
            let mut media = flash.inner.bytes.borrow_mut();
            match damage {
                0 => media[page] = 0x52,
                1 => media[page + 20] = 0,
                2 => media[page + FaultFlash::ERASE_SIZE - 1] = 0,
                3 => media[page..page + FaultFlash::WRITE_SIZE.max(FaultFlash::READ_SIZE)].fill(0),
                _ => unreachable!(),
            }
            drop(media);
            let saved = flash.inner.bytes.borrow().clone();
            flash.arm(&[]);
            assert_eq!(
                unmounted(&flash).boot([0x4B; 16]),
                Err(Error::MemoryFatal),
                "{partition:?} {damage}"
            );
            assert_eq!(*flash.inner.bytes.borrow(), saved);
            assert!(flash.events().iter().all(|event| event.0 == Io::Read));
        }
    }
}

#[test]
fn an_entirely_closed_legacy_ring_cannot_be_auto_repaired_into_an_empty_store() {
    for partition in [MAIN, MAIN.end..MAIN.end + 128 * 1024] {
        let flash = provision_legacy();
        let word = FaultFlash::WRITE_SIZE.max(FaultFlash::READ_SIZE);
        for page in
            (partition.start as usize..partition.end as usize).step_by(FaultFlash::ERASE_SIZE)
        {
            let mut media = flash.inner.bytes.borrow_mut();
            media[page..page + word].fill(0);
            let end = page + FaultFlash::ERASE_SIZE;
            media[end - word..end].fill(0);
        }
        let saved = flash.inner.bytes.borrow().clone();
        flash.arm(&[]);
        assert_eq!(unmounted(&flash).boot([0x4B; 16]), Err(Error::MemoryFatal));
        assert_eq!(*flash.inner.bytes.borrow(), saved);
        assert!(flash.events().iter().all(|event| event.0 == Io::Read));
    }
}

#[test]
fn a_legacy_counter_ring_with_one_partial_page_and_no_erased_page_still_migrates() {
    let flash = provision_legacy();
    let word = FaultFlash::WRITE_SIZE.max(FaultFlash::READ_SIZE);
    let mut partial = 0;
    for page in (MAIN.end as usize..MAIN.end as usize + 128 * 1024).step_by(FaultFlash::ERASE_SIZE)
    {
        let mut media = flash.inner.bytes.borrow_mut();
        let end = page + FaultFlash::ERASE_SIZE;
        if media[page..page + word].iter().all(|&byte| byte == 0xFF) {
            media[page..page + word].fill(0);
            media[end - word..end].fill(0);
        } else if media[end - word..end].iter().all(|&byte| byte == 0xFF) {
            partial += 1;
        }
    }
    assert_eq!(partial, 1);
    let mut store = unmounted(&flash);
    store.boot([0x4B; 16]).unwrap();
    assert_imported(&mut store);
}

#[test]
fn activation_without_a_readable_manifest_reports_damage_before_legacy_fallback() {
    let flash = provision_legacy();
    let counters = flash.inner.bytes.borrow()[MAIN.end as usize..].to_vec();
    flash.arm(&[Rule {
        io: Io::Erase,
        skip: 0,
        effect: Effect::Refuse,
        latched: true,
    }]);
    assert!(unmounted(&flash).boot([0x4B; 16]).is_err());
    assert!(flash.hits()[0] > 0);
    assert_eq!(&flash.inner.bytes.borrow()[MAIN.end as usize..], counters);
    assert!(
        flash
            .inner
            .bytes
            .borrow()
            .windows(8)
            .any(|bytes| bytes == b"RSKACT02")
    );
    let manifests: Vec<_> = flash
        .inner
        .bytes
        .borrow()
        .windows(8)
        .enumerate()
        .filter_map(|(index, bytes)| (bytes == b"RSKIMP02").then_some(index))
        .collect();
    assert!(!manifests.is_empty());
    for position in manifests {
        flash.inner.bytes.borrow_mut()[position] ^= 0x80;
    }
    let damaged = flash.inner.bytes.borrow().clone();
    flash.arm(&[]);
    assert_eq!(unmounted(&flash).boot([0x5A; 16]), Err(Error::MemoryFatal));
    assert_eq!(*flash.inner.bytes.borrow(), damaged);
    assert!(flash.events().iter().all(|event| event.0 == Io::Read));
}

#[test]
fn the_sdk_e10_padding_in_an_unused_counter_page_does_not_block_legacy_upgrade() {
    let flash = provision_legacy();
    let end = MAIN.end as usize + 128 * 1024;
    flash.inner.bytes.borrow_mut()[end - 256..end].fill(0xEF);
    let mut store = unmounted(&flash);
    store.boot([0x4B; 16]).unwrap();
    assert_imported(&mut store);
}

#[test]
fn a_blank_device_with_only_sdk_e10_padding_initializes_automatically() {
    let flash = FaultFlash::new();
    let mut store = managed(&flash, source());
    let end = MAIN.end as usize + 128 * 1024;
    flash.inner.bytes.borrow_mut()[end - 256..end].fill(0xEF);
    store.boot([0x4B; 16]).unwrap();
    assert_eq!(store.state(), StorageState::Ready);
    assert_eq!(store.read(CRED, &mut []), None);
    assert!(!store.last_error());
}

#[test]
fn e10_padding_never_excuses_other_counter_page_data_or_a_partial_suffix() {
    for damaged in [1, 255, 256, 4095] {
        let flash = provision_legacy();
        let end = MAIN.end as usize + 128 * 1024;
        flash.inner.bytes.borrow_mut()[end - 256..end].fill(0xEF);
        flash.inner.bytes.borrow_mut()[end - damaged] = 0xEE;
        let saved = flash.inner.bytes.borrow().clone();
        flash.arm(&[]);
        assert_eq!(unmounted(&flash).boot([0x4B; 16]), Err(Error::MemoryFatal));
        assert_eq!(*flash.inner.bytes.borrow(), saved);
        assert!(flash.events().iter().all(|event| event.0 == Io::Read));
    }
}

#[test]
fn e10_padding_import_resumes_after_backup_and_recovery_cuts() {
    let flash = provision_legacy();
    let end = MAIN.end as usize + 128 * 1024;
    flash.inner.bytes.borrow_mut()[end - 256..end].fill(0xEF);
    let saved = flash.inner.bytes.borrow().clone();
    flash.arm(&[]);
    unmounted(&flash).boot([0x4B; 16]).unwrap();
    let trace = flash.events();
    for io in [Io::Program, Io::Erase] {
        let count = trace.iter().filter(|event| event.0 == io).count();
        assert!(count > 0);
        for skip in 0..count {
            *flash.inner.bytes.borrow_mut() = saved.clone();
            flash.arm(&[Rule {
                io,
                skip,
                effect: Effect::KeepTail,
                latched: true,
            }]);
            let _first = unmounted(&flash).boot([0x4B; 16]);
            assert!(flash.hits()[0] > 0);
            flash.arm(&[Rule {
                io: Io::Program,
                skip: 0,
                effect: Effect::KeepTail,
                latched: true,
            }]);
            let _second = unmounted(&flash).boot([0x5A; 16]);
            flash.arm(&[]);
            let mut reboot = unmounted(&flash);
            reboot
                .boot([0x6A; 16])
                .unwrap_or_else(|error| panic!("{io:?} {skip}: {error:?}"));
            assert_imported(&mut reboot);
        }
    }
}

#[test]
fn e10_padding_remains_the_open_buffer_page_of_an_otherwise_closed_counter_ring() {
    let flash = provision_legacy();
    let end = MAIN.end as usize + 128 * 1024;
    let word = FaultFlash::WRITE_SIZE.max(FaultFlash::READ_SIZE);
    flash.inner.bytes.borrow_mut()[end - 256..end].fill(0xEF);
    for page in (MAIN.end as usize..end - FaultFlash::ERASE_SIZE).step_by(FaultFlash::ERASE_SIZE) {
        let mut bytes = flash.inner.bytes.borrow_mut();
        bytes[page..page + word].fill(0);
        let tail = page + FaultFlash::ERASE_SIZE;
        bytes[tail - word..tail].fill(0);
    }
    let saved = flash.inner.bytes.borrow().clone();
    flash.arm(&[Rule {
        io: Io::Erase,
        skip: 0,
        effect: Effect::Refuse,
        latched: true,
    }]);
    assert!(unmounted(&flash).boot([0x4B; 16]).is_err());
    assert!(flash.hits()[0] > 0);
    flash.arm(&[]);
    let mut reboot = unmounted(&flash);
    reboot.boot([0x5A; 16]).unwrap();
    assert_imported(&mut reboot);
    *flash.inner.bytes.borrow_mut() = saved;
    flash.arm(&[]);
    let mut healthy = unmounted(&flash);
    healthy.boot([0x4B; 16]).unwrap();
    assert_imported(&mut healthy);
}

#[derive(Clone)]
struct WideReads(FaultFlash);
impl ErrorType for WideReads {
    type Error = <FaultFlash as ErrorType>::Error;
}
impl ReadNorFlash for WideReads {
    const READ_SIZE: usize = 4;
    async fn read(&mut self, at: u32, out: &mut [u8]) -> core::result::Result<(), Self::Error> {
        self.0.read(at, out).await
    }
    fn capacity(&self) -> usize {
        self.0.capacity()
    }
}
impl NorFlash for WideReads {
    const WRITE_SIZE: usize = FaultFlash::WRITE_SIZE;
    const ERASE_SIZE: usize = FaultFlash::ERASE_SIZE;
    async fn write(&mut self, at: u32, bytes: &[u8]) -> core::result::Result<(), Self::Error> {
        self.0.write(at, bytes).await
    }
    async fn erase(&mut self, from: u32, to: u32) -> core::result::Result<(), Self::Error> {
        self.0.erase(from, to).await
    }
}
impl MultiwriteNorFlash for WideReads {}

#[test]
fn e10_legacy_view_supports_wider_page_markers_during_import_and_resume() {
    let flash = provision_legacy();
    let end = MAIN.end as usize + 128 * 1024;
    flash.inner.bytes.borrow_mut()[end - 256..end].fill(0xEF);
    let word = FaultFlash::WRITE_SIZE;
    for page in (MAIN.end as usize..end - FaultFlash::ERASE_SIZE).step_by(FaultFlash::ERASE_SIZE) {
        let mut bytes = flash.inner.bytes.borrow_mut();
        bytes[page..page + word].fill(0);
        let tail = page + FaultFlash::ERASE_SIZE;
        bytes[tail - word..tail].fill(0);
    }
    let mount = || {
        Managed::new_unmounted(
            WideReads(flash.clone()),
            MAIN,
            MAIN.end..MAIN.end + 128 * 1024,
            source(),
            cache,
        )
    };
    let saved = flash.inner.bytes.borrow().clone();
    flash.arm(&[]);
    mount().boot([0x4B; 16]).unwrap();
    let programs = flash
        .events()
        .iter()
        .take_while(|event| event.0 != Io::Erase)
        .filter(|event| event.0 == Io::Program)
        .count();
    assert!(programs > 0);
    for skip in 0..programs {
        *flash.inner.bytes.borrow_mut() = saved.clone();
        flash.arm(&[Rule {
            io: Io::Program,
            skip,
            effect: Effect::KeepTail,
            latched: true,
        }]);
        let _cut = mount().boot([0x4B; 16]);
        assert!(flash.hits()[0] > 0);
        flash.arm(&[]);
        let mut reboot = mount();
        reboot
            .boot([0x5A; 16])
            .unwrap_or_else(|error| panic!("backup program {skip}: {error:?}"));
        assert_imported(&mut reboot);
    }
}

#[test]
fn automatic_import_survives_command_and_recovery_program_or_erase_cuts() {
    let flash = provision_legacy();
    let saved = flash.inner.bytes.borrow().clone();
    flash.arm(&[]);
    unmounted(&flash).boot([0x4B; 16]).unwrap();
    let trace = flash.events();
    for io in [Io::Program, Io::Erase] {
        let count = trace.iter().filter(|event| event.0 == io).count();
        assert!(count > 0);
        for skip in 0..count {
            for effect in [Effect::Refuse, Effect::Drop, Effect::KeepTail] {
                *flash.inner.bytes.borrow_mut() = saved.clone();
                flash.arm(&[Rule {
                    io,
                    skip,
                    effect,
                    latched: true,
                }]);
                let _cut = unmounted(&flash).boot([0x4B; 16]);
                assert!(flash.hits()[0] > 0, "first {io:?} {skip} {effect:?}");
                let interrupted = flash.inner.bytes.borrow().clone();
                flash.arm(&[]);
                let mut recovered = unmounted(&flash);
                recovered
                    .boot([0x5A; 16])
                    .unwrap_or_else(|error| panic!("first {io:?} {skip} {effect:?}: {error:?}"));
                assert_imported(&mut recovered);
                let recovery = flash.events();
                for second_io in [Io::Program, Io::Erase] {
                    let second_count = recovery.iter().filter(|event| event.0 == second_io).count();
                    if second_count == 0 {
                        continue;
                    }
                    for second_skip in [0, second_count - 1] {
                        *flash.inner.bytes.borrow_mut() = interrupted.clone();
                        flash.arm(&[Rule {
                            io: second_io,
                            skip: second_skip,
                            effect: Effect::KeepTail,
                            latched: true,
                        }]);
                        let _second_cut = unmounted(&flash).boot([0x5A; 16]);
                        assert!(flash.hits()[0] > 0, "second {second_io:?} {second_skip}");
                        flash.arm(&[]);
                        let mut final_boot = unmounted(&flash);
                        final_boot.boot([0x6A; 16]).unwrap_or_else(|error| panic!("{io:?} {skip} {effect:?}, second {second_io:?} {second_skip}: {error:?}"));
                        assert_imported(&mut final_boot);
                    }
                }
            }
        }
    }
}
