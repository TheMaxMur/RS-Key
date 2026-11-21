// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use embassy_futures::block_on;
use embedded_storage_async::nor_flash::{NorFlashError, NorFlashErrorKind};

#[derive(Debug)]
struct Bounds;
impl NorFlashError for Bounds {
    fn kind(&self) -> NorFlashErrorKind {
        NorFlashErrorKind::OutOfBounds
    }
}
#[derive(Clone)]
struct Flash<const SECTOR: usize = 4096>([u8; 8192]);
impl<const SECTOR: usize> ErrorType for Flash<SECTOR> {
    type Error = Bounds;
}
impl<const SECTOR: usize> ReadNorFlash for Flash<SECTOR> {
    const READ_SIZE: usize = 4;
    async fn read(&mut self, at: u32, out: &mut [u8]) -> core::result::Result<(), Bounds> {
        let start = usize::try_from(at).unwrap();
        out.copy_from_slice(self.0.get(start..start + out.len()).ok_or(Bounds)?);
        Ok(())
    }
    fn capacity(&self) -> usize {
        self.0.len()
    }
}
impl<const SECTOR: usize> NorFlash for Flash<SECTOR> {
    const WRITE_SIZE: usize = 4;
    const ERASE_SIZE: usize = SECTOR;
    async fn write(&mut self, at: u32, data: &[u8]) -> core::result::Result<(), Bounds> {
        let start = usize::try_from(at).unwrap();
        self.0
            .get_mut(start..start + data.len())
            .ok_or(Bounds)?
            .copy_from_slice(data);
        Ok(())
    }
    async fn erase(&mut self, start: u32, end: u32) -> core::result::Result<(), Bounds> {
        self.0
            .get_mut(usize::try_from(start).unwrap()..usize::try_from(end).unwrap())
            .ok_or(Bounds)?
            .fill(0xFF);
        Ok(())
    }
}
impl<const SECTOR: usize> MultiwriteNorFlash for Flash<SECTOR> {}

#[test]
fn legacy_view_masks_only_its_padding_and_refuses_all_mutations() {
    let mut flash = Flash::<4096>([0xFF; 8192]);
    block_on(flash.write(0, &[0x5A; 1024])).unwrap();
    let mut view = CounterFlash::new(flash, Some(256..512));
    assert_eq!(view.capacity(), 8192);
    let mut bytes = [0; 288];
    block_on(view.read(240, &mut bytes)).unwrap();
    assert_eq!(&bytes[..16], &[0x5A; 16]);
    assert_eq!(&bytes[16..272], &[0xFF; 256]);
    assert_eq!(&bytes[272..], &[0x5A; 16]);
    assert!(block_on(view.write(0, &[0; 4])).is_err());
    assert!(block_on(view.erase(0, 4096)).is_err());
    block_on(view.read(0, &mut bytes[..4])).unwrap();
    assert_eq!(&bytes[..4], &[0x5A; 4]);
    assert!(block_on(view.read(8192, &mut bytes[..4])).is_err());
}

#[test]
fn absent_padding_keeps_the_entire_read_visible() {
    let mut flash = Flash::<4096>([0xFF; 8192]);
    block_on(flash.write(256, &[0xEF; 256])).unwrap();
    let mut view = CounterFlash::new(flash, None);
    let mut bytes = [0; 256];
    block_on(view.read(256, &mut bytes)).unwrap();
    assert_eq!(bytes, [0xEF; 256]);
}

#[test]
fn e10_padding_must_fit_entirely_inside_one_erase_sector() {
    let mut small = Flash::<128>([0xFF; 8192]);
    small.0.get_mut(8192 - E10_BYTES..).unwrap().fill(E10_BYTE);
    assert_eq!(read_e10_padding(small, 0..8192).unwrap(), None);
    let mut exact = Flash::<256>([0xFF; 8192]);
    exact.0.get_mut(8192 - E10_BYTES..).unwrap().fill(E10_BYTE);
    assert_eq!(read_e10_padding(exact, 0..8192).unwrap(), Some(7936..8192));
}

#[test]
fn e10_prefix_read_stops_at_the_suffix_even_with_a_short_final_chunk() {
    let mut flash = Flash::<384>([0xFF; 8192]);
    flash.0.get_mut(1280..1536).unwrap().fill(E10_BYTE);
    assert_eq!(read_e10_padding(flash, 0..1536).unwrap(), Some(1280..1536));
}

#[test]
fn e10_padding_can_be_checked_in_a_single_sector_window() {
    let mut flash = Flash::<4096>([0xFF; 8192]);
    flash
        .0
        .get_mut(4096 - E10_BYTES..4096)
        .unwrap()
        .fill(E10_BYTE);
    assert_eq!(read_e10_padding(flash, 0..4096).unwrap(), Some(3840..4096));
}
