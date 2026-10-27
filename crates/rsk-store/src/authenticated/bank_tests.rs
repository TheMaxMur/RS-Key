// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[expect(
    clippy::unwrap_used,
    reason = "An admitted window precedes invalid span arguments without allocating giant buffers."
)]
#[test]
fn span_rejects_integer_overflow_and_retains_exact_empty_and_full_bounds() {
    let bank = RawBank::new(crate::tests::flash_for_authenticated_tests(), 4096..8192).unwrap();
    assert_eq!(bank.span(0, 0), Ok(4096..4096));
    assert_eq!(bank.span(0, 4096), Ok(4096..8192));
    assert_eq!(bank.span(u32::MAX, 0), Err(Error::MemoryFatal));
    assert_eq!(
        bank.span(0, usize::try_from(u32::MAX).unwrap()),
        Err(Error::MemoryFatal)
    );
    #[cfg(target_pointer_width = "64")]
    assert_eq!(
        bank.span(0, usize::try_from(u32::MAX).unwrap() + 1),
        Err(Error::MemoryFatal)
    );
}

#[test]
#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Fixed fixture bounds exercise raw flash alignment and digest boundaries."
)]
fn reads_preserve_unaligned_edges_and_chunk_boundaries() {
    let mut bank = RawBank::new(crate::tests::flash_for_authenticated_tests(), 4096..8192).unwrap();
    let mut input = FlashBuf::<1024>::new();
    for (index, byte) in input.iter_mut().enumerate() {
        *byte = u8::try_from(index % 251).unwrap();
    }
    bank.program(0, &input).unwrap();
    for offset in [0, 1, 2, 3, 255, 256, 257] {
        for length in [0, 1, 3, 4, 255, 256, 257, 511] {
            for padding in 0..4 {
                let mut out = FlashBuf::<516>::new();
                out.fill(0xA5);
                bank.read(
                    u32::try_from(offset).unwrap(),
                    &mut out[padding..padding + length],
                )
                .unwrap();
                assert_eq!(
                    &out[padding..padding + length],
                    &input[offset..offset + length]
                );
                assert!(out[..padding].iter().all(|&byte| byte == 0xA5));
                assert!(out[padding + length..].iter().all(|&byte| byte == 0xA5));
            }
        }
    }
}

#[test]
#[expect(
    clippy::unwrap_used,
    reason = "Each admitted fixture plants one byte inside its bank."
)]
fn erased_tail_checks_every_byte_and_rejects_unreadable_tail() {
    use crate::tests::{Effect, FaultFlash, Io, Rule};
    for offset in [0, 1, 2, 3, 255, 256, 257, 4093, 4094, 4095] {
        for dirty in offset..4096 {
            let mut bank = RawBank::new(FaultFlash::new(), 4096..8192).unwrap();
            bank.program(dirty, &[0xFE]).unwrap();
            assert_eq!(
                bank.read_erased(offset),
                Ok(false),
                "offset={offset} dirty={dirty}"
            );
        }
        let flash = FaultFlash::new();
        let mut bank = RawBank::new(flash.clone(), 4096..8192).unwrap();
        assert_eq!(bank.read_erased(offset), Ok(true));
        flash.arm(&[Rule {
            io: Io::Read,
            skip: 0,
            effect: Effect::Refuse,
            latched: true,
        }]);
        assert_eq!(bank.read_erased(offset), Err(Error::MemoryFatal));
    }
}

#[derive(Clone)]
struct AlignedFlash(crate::tests::FaultFlash);

impl embedded_storage_async::nor_flash::ErrorType for AlignedFlash {
    type Error = crate::tests::FlashFault;
}
impl ReadNorFlash for AlignedFlash {
    const READ_SIZE: usize = 4;
    async fn read(&mut self, offset: u32, out: &mut [u8]) -> core::result::Result<(), Self::Error> {
        assert!(offset.is_multiple_of(4));
        assert!(out.len().is_multiple_of(4));
        assert!(out.as_ptr().addr().is_multiple_of(4));
        self.0.read(offset, out).await
    }
    fn capacity(&self) -> usize {
        self.0.capacity()
    }
}
impl NorFlash for AlignedFlash {
    const WRITE_SIZE: usize = <crate::tests::FaultFlash as NorFlash>::WRITE_SIZE;
    const ERASE_SIZE: usize = <crate::tests::FaultFlash as NorFlash>::ERASE_SIZE;
    async fn write(&mut self, offset: u32, bytes: &[u8]) -> core::result::Result<(), Self::Error> {
        self.0.write(offset, bytes).await
    }
    async fn erase(&mut self, start: u32, end: u32) -> core::result::Result<(), Self::Error> {
        self.0.erase(start, end).await
    }
}
impl MultiwriteNorFlash for AlignedFlash {}

#[test]
#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Fixed fixture bounds exercise raw flash alignment and digest boundaries."
)]
fn word_flash_preserves_alignment_empty_bounds_and_transfer_errors() {
    use crate::tests::{Effect, FaultFlash, Io, Rule};
    let flash = FaultFlash::new();
    let mut bank = RawBank::new(AlignedFlash(flash.clone()), 4096..8192).unwrap();
    let mut expected = FlashBuf::<1024>::new();
    for (index, byte) in expected.iter_mut().enumerate() {
        *byte = u8::try_from(index % 251).unwrap();
    }
    bank.program(0, &expected).unwrap();
    for (offset, padding, count) in [
        (0, 0, 512),
        (1, 0, 511),
        (0, 1, 512),
        (3, 3, 257),
        (255, 2, 513),
    ] {
        let mut out = FlashBuf::<520>::new();
        bank.read(offset, &mut out[padding..padding + count])
            .unwrap();
        assert_eq!(
            &out[padding..padding + count],
            &expected[offset as usize..offset as usize + count]
        );
    }
    flash.arm(&[]);
    assert_eq!(bank.read(4096, &mut []), Ok(()));
    assert_eq!(bank.read(4097, &mut []), Err(Error::MemoryFatal));
    assert!(flash.events().is_empty());
    let mut out = FlashBuf::<516>::new();
    bank.read(0, &mut out[..512]).unwrap();
    assert_eq!(flash.events(), [(Io::Read, 4096, 512)]);
    for (offset, padding, count) in [(0, 0, 512), (1, 1, 512)] {
        flash.arm(&[]);
        bank.read(offset, &mut out[padding..padding + count])
            .unwrap();
        let transfers = flash.events().len();
        for skip in 0..transfers {
            flash.arm(&[Rule {
                io: Io::Read,
                skip,
                effect: Effect::Refuse,
                latched: false,
            }]);
            assert_eq!(
                bank.read(offset, &mut out[padding..padding + count]),
                Err(Error::MemoryFatal)
            );
            assert_eq!(flash.hits(), [1]);
            assert!(flash.events().iter().all(|event| event.0 == Io::Read));
        }
    }
}

#[test]
#[expect(
    clippy::unwrap_used,
    reason = "Fixed fixture bounds exercise raw flash alignment and digest boundaries."
)]
fn bank_digest_matches_software_hash_and_checks_full_suffix_before_acceleration() {
    use crate::tests::FaultFlash;
    fn accelerated(
        flash: &mut FaultFlash,
        range: Range<u32>,
        end: u32,
        prefix: &[u8],
    ) -> Result<Option<[u8; 32]>> {
        RawBank::new(flash.clone(), range)?.digest_if_erased_tail(end, prefix)
    }
    for end in [0u32, 1, 13, 55, 56, 63, 64, 65, 255, 256, 257, 4096] {
        let flash = FaultFlash::new();
        let mut bank = RawBank::new(flash.clone(), 4096..8192).unwrap();
        let data: std::vec::Vec<_> = (0..end).map(|i| u8::try_from(i % 251).unwrap()).collect();
        bank.program(0, &data).unwrap();
        let prefix = b"public-domain";
        let mut input = prefix.to_vec();
        input.extend_from_slice(&data);
        input.extend_from_slice(&end.to_le_bytes());
        let expected = rsk_crypto::sha256(&input);
        assert_eq!(bank.digest(end, prefix), Ok(expected));
        bank.digest = Some(accelerated);
        assert_eq!(bank.digest(end, prefix), Ok(expected));
        if end < 4096 {
            bank.program(4095, &[0]).unwrap();
            assert_eq!(bank.digest(end, prefix), Err(Error::MemoryFatal));
            assert_eq!(bank.digest_if_erased_tail(end, prefix), Ok(None));
        }
    }
}

#[test]
#[expect(
    clippy::indexing_slicing,
    reason = "Fixed fixture offsets flip every byte of each admitted slice."
)]
fn erased_predicate_checks_all_unrolled_word_lanes_and_short_remainders() {
    let mut data = [0xFF; 523];
    for offset in 0..4 {
        for length in 0..520 {
            let bytes = &mut data[offset..offset + length];
            assert!(all_erased(bytes));
            for index in 0..length {
                bytes[index] = 0xFE;
                assert!(
                    !all_erased(bytes),
                    "offset={offset} length={length} index={index}"
                );
                bytes[index] = 0xFF;
            }
        }
    }
}
