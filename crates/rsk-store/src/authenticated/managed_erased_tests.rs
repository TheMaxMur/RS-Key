// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![expect(
    clippy::unwrap_used,
    reason = "The fixture establishes valid authority before refusing the board read callback."
)]

use super::*;
use crate::tests::FaultFlash;
use embedded_storage_async::nor_flash::ReadNorFlash;

std::thread_local! {
    static MODE: core::cell::Cell<u8> = const { core::cell::Cell::new(0) };
    static CALLS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

fn erased(flash: &mut FaultFlash, range: Range<u32>) -> Result<bool> {
    CALLS.with(|value| value.set(value.get() + 1));
    match MODE.with(core::cell::Cell::get) {
        1 => return Ok(false),
        2 => return Err(Error::MemoryFatal),
        _ => {}
    }
    let mut bytes = vec![0; usize::try_from(range.end - range.start).unwrap()];
    embassy_futures::block_on(flash.read(range.start, &mut bytes))
        .map_err(|_| Error::MemoryFatal)?;
    Ok(super::super::super::all_erased(&bytes))
}

#[test]
fn counter_writes_use_the_board_tail_check_and_never_hide_its_refusals() {
    for mode in [1, 2] {
        MODE.with(|value| value.set(0));
        let flash = crate::tests::fault_flash_for_authenticated_tests();
        let source = KeySource::new([0x43; 32], |_| super::super::super::RootRead::Blank, false);
        let mut store = Managed::new_unmounted_with_reads(
            flash,
            0..32768,
            32768..32768 + super::super::super::storage::AUTHORITY_BYTES,
            source,
            Cache::<Uncached, Uncached, Uncached, u16>::new_uncached,
            None,
            Some(erased),
        );
        store
            .administer(StorageAction::Initialize, [0x4B; 16])
            .unwrap();
        store
            .write(rsk_fs::counter::PIV_RETRIES, &[3, 1, 3, 2])
            .unwrap();
        for _ in 0..2 {
            store.mount().unwrap();
            CALLS.with(|value| value.set(0));
            assert_eq!(store.read(rsk_fs::counter::PIV_RETRIES, &mut []), Some(4));
            store
                .write(rsk_fs::counter::PIV_RETRIES, &[3, 1, 3, 2])
                .unwrap();
            assert!(CALLS.with(core::cell::Cell::get) >= 2);
        }
        MODE.with(|value| value.set(mode));
        assert_eq!(
            store.write(rsk_fs::counter::PIV_RETRIES, &[3, 0, 3, 2]),
            Err(Error::MemoryFatal)
        );
        let mut out = [0xA5; 4];
        assert_eq!(store.read(rsk_fs::counter::PIV_RETRIES, &mut out), None);
        assert!(store.last_error());
        assert_eq!(out, [0xA5; 4]);
    }
}
