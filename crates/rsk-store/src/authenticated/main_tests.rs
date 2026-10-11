// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use sequential_storage::cache::{Cache, Uncached};
use sequential_storage::map::MapConfig;

const KEY: [u8; 32] = [0x35; 32];
const EPOCH: [u8; 16] = [0x4B; 16];
type UncachedMap = Cache<Uncached, Uncached, Uncached, u16>;

fn main() -> Main<impl MultiwriteNorFlash + Clone, UncachedMap> {
    main_on(crate::tests::flash_for_authenticated_tests())
}

fn main_on<F: MultiwriteNorFlash + Clone>(flash: F) -> Main<F, UncachedMap> {
    let range = 0..32768;
    let layout =
        super::super::Layout::new(range.end..range.end + super::super::storage::AUTHORITY_BYTES)
            .unwrap();
    Main::new(
        MapStorage::new(
            VerifiedFlash::new(flash.clone()),
            MapConfig::try_new(range).unwrap(),
            Cache::new_uncached(),
        ),
        layout.main.map(|range| {
            Journal::new(
                super::super::RawBank::new(flash.clone(), range).unwrap(),
                Partition::Main,
            )
        }),
        EPOCH,
        RootArm::PreOtp,
    )
}

#[test]
fn payload_read_refusals_are_errors_in_published_and_reserved_value_checks() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut main = main_on(flash.clone());
    main.initialize(&KEY, 0, &Directory::new()).unwrap();
    main.write(&KEY, 0xB000, Some(b"owner")).unwrap();
    let entry = main.directory.find(0xB000).unwrap();
    assert_eq!(main.published_value(&KEY, entry), Ok(5));
    let reserved = block_on(main.map.reserve_item(
        main.buffer.expose_mut(),
        &0xB000,
        &b"owner".as_slice(),
    ))
    .unwrap();
    block_on(main.map.append_reserved(
        main.buffer.expose_mut(),
        &0xB000,
        &b"owner".as_slice(),
        reserved,
    ))
    .unwrap();
    let prepared = Prepared {
        entry,
        address: reserved.address(),
    };
    assert_eq!(main.candidate_complete(&KEY, prepared), Ok(true));
    let before = flash.image();
    for candidate in [false, true] {
        main.map.invalidate_cache();
        flash.arm(&[crate::tests::Rule {
            io: crate::tests::Io::Read,
            skip: 0,
            effect: crate::tests::Effect::Refuse,
            latched: true,
        }]);
        if candidate {
            assert_eq!(
                main.candidate_complete(&KEY, prepared),
                Err(Error::MemoryFatal)
            );
        } else {
            assert_eq!(main.published_value(&KEY, entry), Err(Error::MemoryFatal));
        }
        assert!(flash.hits().first().is_some_and(|&hits| hits > 0));
        assert_eq!(flash.image(), before);
        flash.clear();
    }
    assert_eq!(main.candidate_complete(&KEY, prepared), Ok(true));
    assert_eq!(main.published_value(&KEY, entry), Ok(5));
}

#[test]
fn two_invalid_main_headers_are_neither_empty_nor_a_complete_authority() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut main = main_on(flash.clone());
    let layout =
        super::super::Layout::new(32768..32768 + super::super::storage::AUTHORITY_BYTES).unwrap();
    for range in layout.main {
        super::super::RawBank::new(flash.clone(), range)
            .unwrap()
            .program(0, b"invalid header")
            .unwrap();
    }
    let before = flash.image();
    assert_eq!(main.read(&KEY, 0xB000, &mut []), Err(Error::MemoryFatal));
    assert_eq!(flash.image(), before);
}

#[test]
fn dirty_authenticated_progress_above_a_complete_peer_cannot_roll_back() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut main = main_on(flash.clone());
    main.initialize(&KEY, 0, &Directory::new()).unwrap();
    let directory = Directory::<MAX_MAIN_ENTRIES>::new();
    let header = main.checkpoint(&KEY, 1).unwrap();
    main.journals[1]
        .write_snapshot(header, &KEY, &directory)
        .unwrap();
    let layout =
        super::super::Layout::new(32768..32768 + super::super::storage::AUTHORITY_BYTES).unwrap();
    let mut raw = super::super::RawBank::new(flash.clone(), layout.main[1].clone()).unwrap();
    raw.program(
        u32::try_from(super::super::CHECKPOINT_BYTES + DELTA_BYTES).unwrap(),
        b"dirty suffix",
    )
    .unwrap();
    let before = flash.image();
    assert_eq!(main.read(&KEY, 0xB000, &mut []), Err(Error::MemoryFatal));
    assert_eq!(flash.image(), before);
}

#[test]
fn equal_sequence_peers_cannot_recover_different_authenticated_candidates() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut main = main_on(flash.clone());
    main.initialize(&KEY, 0, &Directory::new()).unwrap();
    for (index, journal) in main.journals.iter_mut().enumerate() {
        let scan = journal
            .scan(&KEY, &mut Directory::<MAX_MAIN_ENTRIES>::new())
            .unwrap();
        let entry = Entry::live(
            Identity {
                partition: Partition::Main,
                epoch: EPOCH,
            },
            &KEY,
            0xB000 + u16::try_from(index).unwrap(),
            1,
            b"owner",
        )
        .unwrap();
        journal
            .append(
                scan.next,
                Delta {
                    kind: DeltaKind::Prepare,
                    partition: Partition::Main,
                    sequence: 1,
                    address: 4096,
                    entry,
                    previous: scan.state.unwrap().chain(),
                },
                &KEY,
            )
            .unwrap();
    }
    let before = flash.image();
    assert_eq!(main.read(&KEY, 0xB000, &mut []), Err(Error::MemoryFatal));
    assert_eq!(flash.image(), before);
}

#[test]
fn an_older_dirty_intent_does_not_prevent_aborting_a_newer_incomplete_candidate() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut main = main_on(flash.clone());
    main.initialize(&KEY, 0, &Directory::new()).unwrap();
    let identity = Identity {
        partition: Partition::Main,
        epoch: EPOCH,
    };
    let old_scan = main.journals[1]
        .scan(&KEY, &mut Directory::<MAX_MAIN_ENTRIES>::new())
        .unwrap();
    main.journals[1]
        .append(
            old_scan.next,
            Delta {
                kind: DeltaKind::Prepare,
                partition: Partition::Main,
                sequence: 1,
                address: 4,
                entry: Entry::live(identity, &KEY, 0xB001, 1, b"old").unwrap(),
                previous: old_scan.state.unwrap().chain(),
            },
            &KEY,
        )
        .unwrap();
    let layout =
        super::super::Layout::new(32768..32768 + super::super::storage::AUTHORITY_BYTES).unwrap();
    super::super::RawBank::new(flash.clone(), layout.main[1].clone())
        .unwrap()
        .program(
            old_scan.next + u32::try_from(DELTA_BYTES).unwrap(),
            b"dirty tail",
        )
        .unwrap();
    let header = main.checkpoint(&KEY, 1).unwrap();
    let scan = main.journals[0]
        .write_snapshot(header, &KEY, &Directory::<MAX_MAIN_ENTRIES>::new())
        .unwrap();
    let reserved = block_on(main.map.reserve_item(
        main.buffer.expose_mut(),
        &0xB000,
        &b"new".as_slice(),
    ))
    .unwrap();
    main.journals[0]
        .append(
            scan.next,
            Delta {
                kind: DeltaKind::Prepare,
                partition: Partition::Main,
                sequence: 2,
                address: reserved.address(),
                entry: Entry::live(identity, &KEY, 0xB000, 2, b"new").unwrap(),
                previous: scan.state.unwrap().chain(),
            },
            &KEY,
        )
        .unwrap();
    assert_eq!(main.read(&KEY, 0xB000, &mut [0; 3]), Ok(None));
    assert_eq!(main.read(&KEY, 0xB001, &mut [0; 3]), Ok(None));
    let recovered = main.journals[0]
        .scan(&KEY, &mut Directory::<MAX_MAIN_ENTRIES>::new())
        .unwrap();
    assert_eq!(recovered.state.unwrap().sequence(), 2);
    assert_eq!(recovered.state.unwrap().pending(), None);
}

#[test]
fn scrub_program_failure_is_reported_without_losing_an_acknowledged_owner() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut main = main_on(flash.clone());
    main.initialize(&KEY, 0, &Directory::new()).unwrap();
    main.write(&KEY, 0xB000, Some(b"owner")).unwrap();
    flash.arm(&[crate::tests::Rule {
        io: crate::tests::Io::Program,
        skip: 0,
        effect: crate::tests::Effect::Refuse,
        latched: true,
    }]);
    assert_eq!(main.compact(&KEY), Err(Error::MemoryFatal));
    assert!(flash.hits().first().is_some_and(|&hits| hits > 0));
    flash.clear();
    let mut fresh = main_on(flash);
    let mut value = [0; 5];
    assert_eq!(fresh.read(&KEY, 0xB000, &mut value), Ok(Some(5)));
    assert_eq!(&value, b"owner");
}

#[expect(
    clippy::indexing_slicing,
    reason = "A captured real NOR trace identifies the reserved candidate read after its verified append."
)]
#[test]
fn an_erased_candidate_after_verified_append_is_not_a_successful_write() {
    use embedded_storage_async::nor_flash::ReadNorFlash;
    let baseline = crate::tests::fault_flash_for_authenticated_tests();
    let mut healthy = main_on(baseline.clone());
    healthy.initialize(&KEY, 0, &Directory::new()).unwrap();
    let original = baseline.image();
    baseline.arm(&[]);
    healthy.write(&KEY, 0xB000, Some(b"owner")).unwrap();
    let trace = baseline.events();
    let last_program = trace
        .iter()
        .rposition(|(io, at, _)| *io == crate::tests::Io::Program && *at < 32768)
        .unwrap();
    let candidate = trace
        .iter()
        .find(|(io, at, _)| *io == crate::tests::Io::Program && *at > 0 && *at < 32768)
        .unwrap()
        .1;
    let read = trace
        .iter()
        .enumerate()
        .skip(last_program + 1)
        .find(|(_, (io, at, _))| *io == crate::tests::Io::Read && *at == candidate)
        .unwrap()
        .0;
    let skip = trace[..read]
        .iter()
        .filter(|(io, _, _)| *io == crate::tests::Io::Read)
        .count();
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    flash.replace_image_before_read(0, original);
    assert!(block_on(flash.clone().read(0, &mut [])).is_ok());
    let mut store = main_on(flash.clone());
    let mut missing = baseline.image();
    missing[..32768].fill(0xFF);
    flash.arm(&[]);
    flash.replace_image_before_read(skip, missing);
    assert_eq!(
        store.write(&KEY, 0xB000, Some(b"owner")),
        Err(Error::MemoryFatal)
    );
    assert!(
        flash
            .events()
            .iter()
            .any(|(io, at, _)| *io == crate::tests::Io::Program && *at < 32768)
    );
}

#[test]
fn a_main_partition_refuses_counter_writes_and_invalid_snapshot_source() {
    let mut main = main();
    main.initialize(&KEY, 0, &Directory::new()).unwrap();
    let counter = rsk_fs::counter::EF_COUNTER.get();
    assert_eq!(
        main.write(&KEY, counter, Some(b"counter")),
        Err(Error::MemoryFatal)
    );
    assert_eq!(main.write(&KEY, counter, None), Err(Error::MemoryFatal));
    assert!(main.snapshots(&KEY, 0, 2).is_err());
    assert_eq!(main.read(&KEY, 0xB000, &mut [0; 8]), Ok(None));
}

#[test]
fn deletion_at_a_full_journal_publishes_absence_without_losing_a_neighbor() {
    let mut main = main();
    main.initialize(&KEY, 0, &Directory::new()).unwrap();
    main.write(&KEY, 0xB001, Some(b"neighbor")).unwrap();
    loop {
        let scan = main.journals[0]
            .scan(&KEY, &mut Directory::<MAX_MAIN_ENTRIES>::new())
            .unwrap();
        if main.journals[0].capacity() - scan.next < u32::try_from(2 * DELTA_BYTES).unwrap() {
            break;
        }
        main.write(&KEY, 0xB000, Some(b"owner")).unwrap();
    }
    main.write(&KEY, 0xB000, None).unwrap();
    assert_eq!(main.read(&KEY, 0xB000, &mut [0; 8]), Ok(None));
    let mut neighbor = [0; 8];
    assert_eq!(main.read(&KEY, 0xB001, &mut neighbor), Ok(Some(8)));
    assert_eq!(&neighbor, b"neighbor");
}

#[test]
fn duplicate_unpublished_candidates_are_retired_without_touching_a_live_owner() {
    let mut main = main();
    main.initialize(&KEY, 0, &Directory::new()).unwrap();
    main.write(&KEY, 0xB001, Some(b"neighbor")).unwrap();
    for value in [&b"first"[..], &b"second"[..]] {
        let reserved = block_on(
            main.map
                .reserve_item(main.buffer.expose_mut(), &0xB000, &value),
        )
        .unwrap();
        block_on(
            main.map
                .append_reserved(main.buffer.expose_mut(), &0xB000, &value, reserved),
        )
        .unwrap();
    }
    main.retire_unpublished(&KEY).unwrap();
    assert!(
        block_on(
            main.map
                .fetch_item_unrepaired::<&[u8]>(main.buffer.expose_mut(), &0xB000)
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(main.read(&KEY, 0xB001, &mut [0; 8]), Ok(Some(8)));
}

#[test]
fn the_directory_ceiling_refuses_a_new_fid_and_still_allows_replacement() {
    const BASE: u16 = 0xB000;
    let mut main = main();
    let identity = Identity {
        partition: Partition::Main,
        epoch: EPOCH,
    };
    let mut directory = Directory::<MAX_MAIN_ENTRIES>::new();
    for fid in BASE..BASE + u16::try_from(MAX_MAIN_ENTRIES).unwrap() {
        block_on(
            main.map
                .store_item(main.buffer.expose_mut(), &fid, &b"".as_slice()),
        )
        .unwrap();
        directory
            .apply(Entry::live(identity, &KEY, fid, 0, &[]).unwrap())
            .unwrap();
    }
    main.initialize(&KEY, 0, &directory).unwrap();
    let next = BASE + u16::try_from(MAX_MAIN_ENTRIES).unwrap();
    assert_eq!(main.write(&KEY, next, Some(&[])), Err(Error::NoMemory));
    assert_eq!(main.read(&KEY, next, &mut []), Ok(None));
    main.write(&KEY, BASE, Some(b"replacement")).unwrap();
    let mut value = [0; 11];
    assert_eq!(main.read(&KEY, BASE, &mut value), Ok(Some(11)));
    assert_eq!(&value, b"replacement");
}
