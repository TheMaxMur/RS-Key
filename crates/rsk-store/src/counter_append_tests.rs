// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::api::Geometry;
use super::*;
use crate::authenticated::ENTRY_BYTES;

const PAGE: usize = 256;

fn empty(flash: &FaultFlash) -> CounterBank<Geometry<1, PAGE, SECTOR>> {
    let mut bank =
        CounterBank::new(RawBank::new(Geometry::<1, PAGE, SECTOR>(flash.clone()), MAIN).unwrap());
    let directory = Directory::new();
    bank.write_snapshot(
        counter_checkpoint(&directory, 0),
        &JOURNAL_KEY,
        &directory,
        |_, _| unreachable!(),
    )
    .unwrap();
    bank
}

#[test]
fn counter_append_coalesces_page_aligned_writes_without_changing_bytes() {
    for length in [0, 1, 16, 17, 384, rsk_fs::MAX_VALUE_BYTES] {
        let flash = FaultFlash::new();
        let mut bank = empty(&flash);
        let mut directory = Directory::new();
        let scan = bank.scan(&JOURNAL_KEY, &mut directory).unwrap();
        let value = vec![0x69; length];
        let entry = Entry::live(COUNTER_ID, &JOURNAL_KEY, CTR, 1, &value).unwrap();
        let start = usize::try_from(scan.next).unwrap();
        let end = start + ENTRY_BYTES + length.div_ceil(16) * 16;
        let mut expected = flash.image();
        expected[start..start + ENTRY_BYTES].copy_from_slice(&entry.encode().unwrap());
        expected[start + ENTRY_BYTES..start + ENTRY_BYTES + length].copy_from_slice(&value);
        flash.arm(&[]);
        bank.append(&scan, &JOURNAL_KEY, entry, &value).unwrap();
        let programs: Vec<_> = flash
            .events()
            .into_iter()
            .filter(|e| e.0 == Io::Program)
            .collect();
        assert_eq!(
            programs.len(),
            end.div_ceil(PAGE) - start / PAGE,
            "length={length}"
        );
        assert_eq!(flash.image(), expected, "length={length}");
        let recovered = bank.scan(&JOURNAL_KEY, &mut directory).unwrap();
        assert_eq!(recovered.status, JournalStatus::Complete);
        assert_eq!(recovered.sequence, Some(1));
        let mut output = vec![0; length];
        assert_eq!(
            bank.read_value(&recovered, &JOURNAL_KEY, CTR, &mut output),
            Ok(Some(length))
        );
        assert_eq!(output, value);
    }
}

#[test]
fn a_torn_combined_counter_record_never_authenticates_a_partial_payload() {
    let seed = FaultFlash::new();
    let mut bank = empty(&seed);
    let mut directory = Directory::new();
    let scan = bank.scan(&JOURNAL_KEY, &mut directory).unwrap();
    let value = [0x69; 384];
    let entry = Entry::live(COUNTER_ID, &JOURNAL_KEY, CTR, 1, &value).unwrap();
    let before = seed.image();
    seed.arm(&[]);
    bank.append(&scan, &JOURNAL_KEY, entry, &value).unwrap();
    let programmed: usize = seed
        .events()
        .iter()
        .filter(|e| e.0 == Io::Program)
        .map(|e| e.2)
        .sum();
    for cut in 0..=programmed {
        let flash = FaultFlash::new();
        *flash.inner.bytes.borrow_mut() = before.clone();
        let mut bank = CounterBank::new(
            RawBank::new(Geometry::<1, PAGE, SECTOR>(flash.clone()), MAIN).unwrap(),
        );
        let scan = bank.scan(&JOURNAL_KEY, &mut directory).unwrap();
        flash.arm(&[Rule {
            io: Io::Program,
            skip: 0,
            effect: Effect::Shutoff(cut),
            latched: true,
        }]);
        let acknowledged = bank.append(&scan, &JOURNAL_KEY, entry, &value).is_ok();
        assert!(flash.hits()[0] > 0, "cut={cut}");
        flash.clear();
        let recovered = bank.scan(&JOURNAL_KEY, &mut directory).unwrap();
        assert_eq!(recovered.lower_bound, recovered.sequence, "cut={cut}");
        match recovered.sequence {
            Some(0) => {
                assert!(!acknowledged, "cut={cut}");
                assert!(directory.entries().is_empty(), "cut={cut}");
            }
            Some(1) => {
                assert_eq!(recovered.status, JournalStatus::Complete, "cut={cut}");
                let mut output = [0; 384];
                assert_eq!(
                    bank.read_value(&recovered, &JOURNAL_KEY, CTR, &mut output),
                    Ok(Some(value.len()))
                );
                assert_eq!(output, value, "cut={cut}");
            }
            other => panic!("unexpected sequence {other:?} at cut={cut}"),
        }
    }
}
