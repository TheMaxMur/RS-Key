// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::authenticated::CHECKPOINT_BYTES;

#[derive(Clone)]
pub(super) struct Geometry<const READ: usize, const WRITE: usize, const ERASE: usize>(
    pub(super) FaultFlash,
);

impl<const R: usize, const W: usize, const E: usize> ErrorType for Geometry<R, W, E> {
    type Error = FlashFault;
}
impl<const R: usize, const W: usize, const E: usize> ReadNorFlash for Geometry<R, W, E> {
    const READ_SIZE: usize = R;
    async fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result2<()> {
        self.0.read(offset, bytes).await
    }
    fn capacity(&self) -> usize {
        self.0.capacity()
    }
}
impl<const R: usize, const W: usize, const E: usize> NorFlash for Geometry<R, W, E> {
    const WRITE_SIZE: usize = W;
    const ERASE_SIZE: usize = E;
    async fn write(&mut self, offset: u32, bytes: &[u8]) -> Result2<()> {
        self.0.write(offset, bytes).await
    }
    async fn erase(&mut self, from: u32, to: u32) -> Result2<()> {
        self.0.erase(from, to).await
    }
}
impl<const R: usize, const W: usize, const E: usize> MultiwriteNorFlash for Geometry<R, W, E> {}

#[test]
fn unsupported_raw_bank_geometry_refuses_before_io() {
    let flash = FaultFlash::new();
    macro_rules! refuse {
        ($r:expr, $w:expr, $e:expr) => {
            assert!(RawBank::new(Geometry::<{ $r }, { $w }, { $e }>(flash.clone()), MAIN).is_err());
        };
    }
    refuse!(1, 4, 0);
    refuse!(3, 4, SECTOR);
    refuse!(1, 0, SECTOR);
    refuse!(1, 512, SECTOR);
    refuse!(1, 3, SECTOR);
    refuse!(4, 4, 6);
    refuse!(1, 8, 4);
    #[cfg(target_pointer_width = "64")]
    refuse!(1, 4, usize::MAX);
    assert!(flash.events().is_empty());
    let mut admitted = RawBank::new(Geometry::<4, 4, SECTOR>(flash.clone()), MAIN).unwrap();
    admitted.program(3, b"bounded").unwrap();
    let mut value = [0; 7];
    admitted.read(3, &mut value).unwrap();
    assert_eq!(&value, b"bounded");
}

#[test]
fn an_unaligned_bank_read_crosses_scratch_windows_without_growing_them() {
    let flash = FaultFlash::new();
    let mut bank = RawBank::new(Geometry::<4, 4, SECTOR>(flash), MAIN).unwrap();
    let mut data = [0; 520];
    for (index, byte) in data.iter_mut().enumerate() {
        *byte = u8::try_from(index % 251).unwrap();
    }
    bank.program(0, &data).unwrap();
    let mut output = [0; 516];
    bank.read(3, &mut output).unwrap();
    assert_eq!(output, data[3..519]);
}

#[test]
fn an_unaligned_bank_program_crosses_scratch_windows_without_growing_them() {
    let flash = FaultFlash::new();
    let mut bank = RawBank::new(Geometry::<4, 4, SECTOR>(flash.clone()), MAIN).unwrap();
    let neighbor = flash.inner.snapshot(COUNTER);
    let data = [0x5A; 520];
    bank.program(3, &data).unwrap();
    let mut output = [0; 528];
    bank.read(0, &mut output).unwrap();
    assert_eq!(output[..3], [0xFF; 3]);
    assert_eq!(output[3..523], data);
    assert_eq!(output[523..], [0xFF; 5]);
    assert_eq!(flash.inner.snapshot(COUNTER), neighbor);
}

#[test]
fn byte_writable_flash_programs_each_physical_page_once_per_record() {
    let flash = FaultFlash::new();
    let mut bank = RawBank::new(Geometry::<1, 1, SECTOR>(flash.clone()), MAIN).unwrap();
    let data = [0x5A; 416];
    bank.program(96, &data).unwrap();
    let writes: Vec<_> = flash
        .events()
        .into_iter()
        .filter(|(io, _, _)| *io == Io::Program)
        .map(|(_, address, len)| (address - MAIN.start, len))
        .collect();
    assert_eq!(writes, [(96, 160), (256, 256)]);
    let mut output = [0; 516];
    bank.read(0, &mut output).unwrap();
    assert_eq!(output[..96], [0xFF; 96]);
    assert_eq!(output[96..512], data);
    assert_eq!(output[512..], [0xFF; 4]);
}

#[test]
fn bank_program_parts_cross_pages_without_intermediate_value_copies() {
    let flash = FaultFlash::new();
    let mut bank = RawBank::new(flash.clone(), MAIN).unwrap();
    let header = [0xA5; 17];
    let value = [0x5A; 384];
    let tail = [0x69; 16];
    bank.program_parts(95, &[&[], &header, &value, &[], &tail])
        .unwrap();
    let writes: Vec<_> = flash
        .events()
        .into_iter()
        .filter(|(io, _, _)| *io == Io::Program)
        .map(|(_, address, len)| (address - MAIN.start, len))
        .collect();
    assert_eq!(writes, [(92, 164), (256, 256)]);
    let mut expected = vec![0xFF; 95];
    expected.extend_from_slice(&header);
    expected.extend_from_slice(&value);
    expected.extend_from_slice(&tail);
    expected.extend_from_slice(&[0xFF; 4]);
    let mut output = vec![0; expected.len()];
    bank.read(0, &mut output).unwrap();
    assert_eq!(output, expected);
}

#[test]
fn invalid_parts_refuse_before_programming_any_part_of_the_page() {
    let flash = FaultFlash::new();
    let mut bank = RawBank::new(flash.clone(), MAIN).unwrap();
    bank.program(96, &[0; 64]).unwrap();
    let before = flash.image();
    flash.arm(&[]);
    assert_eq!(
        bank.program_parts(96, &[&[0; 16], &[1; 48]]),
        Err(Error::MemoryFatal)
    );
    assert!(flash.events().iter().all(|event| event.0 == Io::Read));
    assert_eq!(flash.image(), before);
    flash.arm(&[]);
    assert_eq!(
        bank.program_parts(bank.capacity() - 4, &[&[1; 4], &[2; 4]]),
        Err(Error::MemoryFatal)
    );
    assert_eq!(bank.program_parts(bank.capacity(), &[&[], &[]]), Ok(()));
    assert!(flash.events().is_empty());
    assert_eq!(flash.image(), before);
}

#[test]
#[expect(
    clippy::reversed_empty_ranges,
    reason = "An inverted bank window must be refused before any flash access."
)]
fn invalid_bank_ranges_and_erased_probe_offsets_refuse_without_mutation() {
    let flash = FaultFlash::new();
    let capacity = u32::try_from(flash.capacity()).unwrap();
    for range in [0..0, 4096..0, 1..4096, 0..4095, 0..capacity + 4096] {
        assert!(RawBank::new(flash.clone(), range).is_err());
    }
    assert!(flash.events().is_empty());
    let mut bank = RawBank::new(flash.clone(), MAIN).unwrap();
    assert_eq!(bank.range(), MAIN);
    let before = flash.inner.bytes.borrow().clone();
    assert_eq!(
        bank.read_erased(bank.capacity() + 1),
        Err(Error::MemoryFatal)
    );
    assert_eq!(bank.read(bank.capacity(), &mut []), Ok(()));
    assert_eq!(bank.program(bank.capacity(), &[]), Ok(()));
    assert_eq!(*flash.inner.bytes.borrow(), before);
}

#[test]
fn verified_flash_error_kinds_preserve_backend_failure_and_readback_mismatch() {
    use crate::verified_flash::VerifyError;
    #[derive(Debug)]
    struct AlignmentFault;
    impl NorFlashError for AlignmentFault {
        fn kind(&self) -> NorFlashErrorKind {
            NorFlashErrorKind::NotAligned
        }
    }
    assert_eq!(VerifyError::Flash(FlashFault).kind(), FlashFault.kind());
    assert_eq!(
        VerifyError::Flash(AlignmentFault).kind(),
        NorFlashErrorKind::NotAligned
    );
    assert_eq!(
        VerifyError::<FlashFault>::Mismatch.kind(),
        NorFlashErrorKind::Other
    );
}

#[test]
fn short_bank_suffixes_are_complete_only_when_erased() {
    let flash = FaultFlash::new();
    let range = 0..u32::try_from(CHECKPOINT_BYTES + 4).unwrap();
    for partition in [Partition::Main, Partition::Counter] {
        for dirty in [false, true] {
            flash.inner.bytes.borrow_mut().fill(0xFF);
            let directory = Directory::<MAX_COUNTER_ENTRIES>::new();
            let identity = Identity {
                partition,
                ..COUNTER_ID
            };
            let header = Checkpoint {
                identity,
                arm: RootArm::PreOtp,
                sequence: 0,
                entries: 0,
                digest: directory.digest(identity, &JOURNAL_KEY, 0).unwrap(),
            };
            let mut raw = RawBank::new(Geometry::<1, 4, 4>(flash.clone()), range.clone()).unwrap();
            raw.program(0, &header.encode(&JOURNAL_KEY).unwrap())
                .unwrap();
            if dirty {
                raw.program(u32::try_from(CHECKPOINT_BYTES).unwrap(), &[0])
                    .unwrap();
            }
            let wanted = if dirty {
                JournalStatus::Dirty
            } else {
                JournalStatus::Complete
            };
            if partition == Partition::Main {
                assert_eq!(
                    Journal::new(raw, partition)
                        .scan(&JOURNAL_KEY, &mut Directory::<2>::new())
                        .unwrap()
                        .status,
                    wanted
                );
            } else {
                assert_eq!(
                    CounterBank::new(raw)
                        .scan(&JOURNAL_KEY, &mut Directory::new())
                        .unwrap()
                        .status,
                    wanted
                );
            }
        }
    }
}

#[test]
fn snapshot_capacity_refusals_precede_erase_and_value_loading() {
    let flash = FaultFlash::new();
    let raw = RawBank::new(flash.clone(), 0..u32::try_from(SECTOR).unwrap()).unwrap();
    let mut bank = CounterBank::new(raw);
    let mut directory = Directory::<MAX_COUNTER_ENTRIES>::new();
    directory
        .apply(
            Entry::live(
                COUNTER_ID,
                &JOURNAL_KEY,
                CTR,
                0,
                &[0; rsk_fs::MAX_VALUE_BYTES],
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        bank.write_snapshot(
            counter_checkpoint(&directory, 0),
            &JOURNAL_KEY,
            &directory,
            |_, _| unreachable!()
        ),
        Err(Error::NoMemory)
    );
    let tiny = RawBank::new(
        Geometry::<1, 4, 4>(flash.clone()),
        0..u32::try_from(CHECKPOINT_BYTES).unwrap(),
    )
    .unwrap();
    let mut journal = Journal::new(tiny, Partition::Main);
    let empty = Directory::<2>::new();
    assert_eq!(
        journal.write_snapshot(checkpoint(&empty, 0), &JOURNAL_KEY, &empty),
        Err(Error::NoMemory)
    );
    assert!(flash.events().is_empty());
}
