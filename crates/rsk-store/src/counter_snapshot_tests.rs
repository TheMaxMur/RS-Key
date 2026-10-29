// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::api::Geometry;
use super::*;
use crate::authenticated::{CHECKPOINT_BYTES, ENTRY_BYTES};

const PAGE: usize = 256;

fn fixture() -> (Directory<MAX_COUNTER_ENTRIES>, Vec<Vec<u8>>) {
    let mut directory = Directory::new();
    let values = [1, 16, 17, 384, 255, 0, 1024]
        .into_iter()
        .enumerate()
        .map(|(i, length)| vec![u8::try_from(i + 1).unwrap(); length])
        .collect::<Vec<_>>();
    for (i, value) in values.iter().enumerate() {
        directory
            .apply(Entry::live(COUNTER_ID, &JOURNAL_KEY, 0xcd01 + i as u16, 7, value).unwrap())
            .unwrap();
    }
    (directory, values)
}

fn write(
    bank: &mut CounterBank<Geometry<1, PAGE, SECTOR>>,
    directory: &Directory<MAX_COUNTER_ENTRIES>,
    values: &[Vec<u8>],
) -> Result<()> {
    bank.write_snapshot(
        counter_checkpoint(directory, 7),
        &JOURNAL_KEY,
        directory,
        |entry, out| {
            out.copy_from_slice(&values[usize::from(entry.fid() - 0xcd01)]);
            Ok(())
        },
    )
}

#[test]
fn empty_counter_snapshot_programs_only_checkpoint_publication() {
    let flash = FaultFlash::new();
    let mut bank =
        CounterBank::new(RawBank::new(Geometry::<1, PAGE, SECTOR>(flash.clone()), MAIN).unwrap());
    let directory = Directory::new();
    let mut loaded = false;
    flash.arm(&[]);
    bank.write_snapshot(
        counter_checkpoint(&directory, 7),
        &JOURNAL_KEY,
        &directory,
        |_, _| {
            loaded = true;
            Ok(())
        },
    )
    .unwrap();
    assert!(!loaded);
    let programs: Vec<_> = flash
        .events()
        .into_iter()
        .filter(|event| event.0 == Io::Program)
        .collect();
    assert_eq!(programs, [(Io::Program, 0, PAGE); 2]);
    let mut recovered = Directory::new();
    let scan = bank.scan(&JOURNAL_KEY, &mut recovered).unwrap();
    assert_eq!(scan.status, JournalStatus::Complete);
    assert_eq!(scan.next as usize, CHECKPOINT_BYTES);
    assert!(recovered.entries().is_empty());
}

#[test]
fn counter_snapshot_packs_physical_pages_and_preserves_the_legacy_encoding() {
    let flash = FaultFlash::new();
    let mut bank =
        CounterBank::new(RawBank::new(Geometry::<1, PAGE, SECTOR>(flash.clone()), MAIN).unwrap());
    let (directory, values) = fixture();
    let mut expected = flash.image();
    expected[..CHECKPOINT_BYTES].copy_from_slice(
        &counter_checkpoint(&directory, 7)
            .encode(&JOURNAL_KEY)
            .unwrap(),
    );
    let mut end = CHECKPOINT_BYTES;
    for (entry, value) in directory.entries().iter().zip(&values) {
        expected[end..end + ENTRY_BYTES].copy_from_slice(&entry.encode().unwrap());
        end += ENTRY_BYTES;
        expected[end..end + value.len()].copy_from_slice(value);
        end += value.len().div_ceil(16) * 16;
    }
    flash.arm(&[]);
    write(&mut bank, &directory, &values).unwrap();
    assert_eq!(flash.image(), expected);
    let programs: Vec<_> = flash
        .events()
        .into_iter()
        .filter(|e| e.0 == Io::Program)
        .collect();
    assert_eq!(programs.len(), end.div_ceil(PAGE) + 2);
    assert_eq!(
        &programs[programs.len() - 2..],
        &[(Io::Program, 0, PAGE); 2]
    );
    let mut recovered = Directory::new();
    let scan = bank.scan(&JOURNAL_KEY, &mut recovered).unwrap();
    assert_eq!(scan.status, JournalStatus::Complete);
    assert_eq!(scan.next as usize, end);
    assert_eq!(recovered.entries(), directory.entries());
}

#[test]
fn every_counter_snapshot_program_byte_cut_refuses_unpublished_pages() {
    let seed = FaultFlash::new();
    let mut bank =
        CounterBank::new(RawBank::new(Geometry::<1, PAGE, SECTOR>(seed.clone()), MAIN).unwrap());
    let (directory, values) = fixture();
    seed.arm(&[]);
    write(&mut bank, &directory, &values).unwrap();
    let programmed: usize = seed
        .events()
        .iter()
        .filter(|e| e.0 == Io::Program)
        .map(|e| e.2)
        .sum();
    for cut in 0..=programmed {
        let flash = FaultFlash::new();
        let mut bank = CounterBank::new(
            RawBank::new(Geometry::<1, PAGE, SECTOR>(flash.clone()), MAIN).unwrap(),
        );
        flash.arm(&[Rule {
            io: Io::Program,
            skip: 0,
            effect: Effect::Shutoff(cut),
            latched: true,
        }]);
        let acknowledged = write(&mut bank, &directory, &values).is_ok();
        assert!(flash.hits()[0] > 0);
        flash.clear();
        let mut recovered = Directory::new();
        let scan = bank.scan(&JOURNAL_KEY, &mut recovered).unwrap();
        if cut < programmed - 2 * PAGE {
            assert_eq!(scan.checkpoint, None, "body cut={cut}");
            assert_eq!(scan.lower_bound, None, "body cut={cut}");
        }
        if scan.status == JournalStatus::Complete {
            assert_eq!(scan.sequence, Some(7), "cut={cut}");
            assert_eq!(recovered.entries(), directory.entries(), "cut={cut}");
            for (entry, expected) in directory.entries().iter().zip(&values) {
                let mut out = vec![0; expected.len()];
                assert_eq!(
                    bank.read_value(&scan, &JOURNAL_KEY, entry.fid(), &mut out),
                    Ok(Some(expected.len()))
                );
                assert_eq!(&out, expected, "cut={cut}");
            }
        } else {
            assert!(!acknowledged, "cut={cut}");
        }
    }
}
