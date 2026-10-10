// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use sequential_storage::map::ReservedItem;

fn unrepaired(store: &mut TestStore, fid: u16) -> Option<Vec<u8>> {
    block_on(
        store
            .main
            .fetch_item_unrepaired::<&[u8]>(&mut store.buf, &fid),
    )
    .unwrap()
    .map(<[u8]>::to_vec)
}

#[test]
fn an_equal_older_value_does_not_prove_the_reserved_candidate_was_programmed() {
    const FID: u16 = 0xCF00;
    const VALUE: &[u8] = b"same value in a different physical record";
    let flash = SharedMock::new();
    let mut store = mount(&flash);
    store.write(FID, VALUE).unwrap();
    let reserved = block_on(
        store
            .main
            .reserve_item::<&[u8]>(&mut store.buf, &FID, &VALUE),
    )
    .unwrap();
    assert_eq!(
        block_on(
            store
                .main
                .fetch_matching_item(&mut store.buf, &FID, |data| data == VALUE)
        )
        .unwrap(),
        Some(VALUE)
    );
    assert_eq!(
        block_on(store.main.read_reserved(&mut store.buf, &FID, reserved)).unwrap(),
        None
    );
    block_on(
        store
            .main
            .append_reserved(&mut store.buf, &FID, &VALUE, reserved),
    )
    .unwrap();
    assert_eq!(
        block_on(store.main.read_reserved(&mut store.buf, &FID, reserved)).unwrap(),
        Some(VALUE)
    );
    block_on(store.main.discard_reserved(reserved)).unwrap();
    assert_eq!(
        block_on(store.main.read_reserved(&mut store.buf, &FID, reserved)).unwrap(),
        None
    );
    assert_eq!(unrepaired(&mut store, FID).as_deref(), Some(VALUE));
}

#[test]
fn a_crc_valid_short_cached_item_is_refused_without_a_parser_panic() {
    type ByteCache = Cache<
        ArrayPageStates<{ MAIN_PAGES as usize }>,
        ArrayPagePointers<{ MAIN_PAGES as usize }>,
        ArrayKeyPointers<u8, 1>,
        u8,
    >;
    let flash = SharedMock::new();
    let mut store = mount(&flash);
    store.write(0xCF00, b"owner").unwrap();
    assert_eq!(
        unrepaired(&mut store, 0xCF00).as_deref(),
        Some(&b"owner"[..])
    );
    let short = SharedMock::new();
    let mut byte_map = MapStorage::new(
        VerifiedFlash::new(short.clone()),
        MapConfig::new(MAIN),
        ByteCache::new(
            ArrayPageStates::new(),
            ArrayPagePointers::new(),
            ArrayKeyPointers::new(),
        ),
    );
    block_on(byte_map.store_item::<&[u8]>(&mut [0; 32], &0x5Au8, &&[][..])).unwrap();
    let span = WORD..WORD + 12;
    flash.bytes.borrow_mut()[span.clone()].copy_from_slice(&short.bytes.borrow()[span]);
    let before = flash.bytes.borrow().clone();
    assert!(
        block_on(
            store
                .main
                .fetch_item_unrepaired::<&[u8]>(&mut store.buf, &0xCF00)
        )
        .is_err()
    );
    assert_eq!(
        *flash.bytes.borrow(),
        before,
        "an unrepaired lookup must not mutate flash"
    );
}

#[test]
fn a_reserved_append_keeps_the_published_old_value_until_authority_moves() {
    const FID: u16 = 0xCF00;
    const OLD: &[u8] = b"published owner value";
    const NEW: &[u8] = b"unpublished owner value";
    let flash = SharedMock::new();
    let mut store = mount(&flash);
    store.write(FID, OLD).unwrap();
    store.write(0xCF01, b"neighbor").unwrap();
    let reserved = block_on(store.main.reserve_item::<&[u8]>(&mut store.buf, &FID, &NEW)).unwrap();
    assert_eq!(unrepaired(&mut store, FID).as_deref(), Some(OLD));
    let before = flash.programs.borrow().len();
    block_on(
        store
            .main
            .append_reserved(&mut store.buf, &FID, &NEW, reserved),
    )
    .unwrap();
    assert!(
        flash.programs.borrow()[before..]
            .iter()
            .all(|&at| { at >= reserved.address() && at < reserved.address() + SECTOR as u32 })
    );
    assert_eq!(unrepaired(&mut store, FID).as_deref(), Some(NEW));
    assert_eq!(
        block_on(
            store
                .main
                .fetch_matching_item(&mut store.buf, &FID, |bytes| bytes == OLD)
        )
        .unwrap(),
        Some(OLD)
    );
    block_on(store.main.discard_reserved(reserved)).unwrap();
    assert_eq!(unrepaired(&mut store, FID).as_deref(), Some(OLD));
    assert_eq!(
        unrepaired(&mut store, 0xCF01).as_deref(),
        Some(&b"neighbor"[..])
    );
}

#[test]
fn every_torn_candidate_header_can_be_cancelled_without_erasing_its_owner() {
    const FID: u16 = 0xCF00;
    const OLD: &[u8] = b"published owner value";
    const NEW: &[u8] = b"unpublished owner value";
    for cut in 0..=8 {
        let flash = SharedMock::new();
        let mut store = mount(&flash);
        store.write(FID, OLD).unwrap();
        store.write(0xCF01, b"neighbor").unwrap();
        let reserved =
            block_on(store.main.reserve_item::<&[u8]>(&mut store.buf, &FID, &NEW)).unwrap();
        let before = flash.bytes.borrow().clone();
        block_on(
            store
                .main
                .append_reserved(&mut store.buf, &FID, &NEW, reserved),
        )
        .unwrap();
        let complete = flash.bytes.borrow().clone();
        *flash.bytes.borrow_mut() = before;
        let start = reserved.address() as usize;
        flash.bytes.borrow_mut()[start..start + cut].copy_from_slice(&complete[start..start + cut]);
        let mut reboot = mount(&flash);
        block_on(
            reboot
                .main
                .discard_reserved(ReservedItem::resume(reserved.address(), reserved.length())),
        )
        .unwrap();
        assert_eq!(
            unrepaired(&mut reboot, FID).as_deref(),
            Some(OLD),
            "header cut {cut}"
        );
        assert_eq!(
            unrepaired(&mut reboot, 0xCF01).as_deref(),
            Some(&b"neighbor"[..])
        );
        let unchanged = flash.snapshot(MAIN);
        block_on(reboot.main.discard_reserved(reserved)).unwrap();
        assert_eq!(
            flash.snapshot(MAIN),
            unchanged,
            "cancellation must be idempotent"
        );
    }
}

#[test]
fn recovery_reservations_cannot_cross_a_page_or_partition_boundary() {
    let flash = SharedMock::new();
    let mut store = mount(&flash);
    let before = flash.bytes.borrow().clone();
    for (address, length) in [
        (0, 8),
        (1, 8),
        (MAIN.end, 8),
        (MAIN.end - 4, 8),
        (u32::MAX, u16::MAX),
    ] {
        assert!(
            block_on(
                store
                    .main
                    .discard_reserved(ReservedItem::resume(address, length))
            )
            .is_err()
        );
        assert_eq!(*flash.bytes.borrow(), before);
    }
}

#[test]
fn six_counter_pages_support_four_maximum_values_and_a_staged_replacement() {
    const PAGES: usize = 6;
    type CounterSix =
        Cache<ArrayPageStates<PAGES>, ArrayPagePointers<PAGES>, ArrayKeyPointers<u16, 4>, u16>;
    let flash = SharedMock::new();
    let range = COUNTER.start..COUNTER.start + u32::try_from(PAGES * SECTOR).unwrap();
    flash.bytes.borrow_mut().resize(range.end as usize, 0xFF);
    let mut map = MapStorage::new(
        VerifiedFlash::new(flash.clone()),
        MapConfig::new(range),
        CounterSix::new(
            ArrayPageStates::new(),
            ArrayPagePointers::new(),
            ArrayKeyPointers::new(),
        ),
    );
    let mut buffer = [0; KV_BUF];
    let fids = rsk_fs::counter::COUNTER_FIDS;
    let mut owners = Vec::new();
    for (index, fid) in fids.iter().enumerate() {
        let payload = vec![u8::try_from(index + 1).unwrap(); rsk_fs::MAX_VALUE_BYTES];
        block_on(map.store_item::<&[u8]>(&mut buffer, &fid.get(), &payload.as_slice())).unwrap();
        owners.push(payload);
    }
    for generation in 0..32 {
        let index = generation % fids.len();
        let fid = fids[index].get();
        let replacement = vec![u8::try_from(generation + 5).unwrap(); rsk_fs::MAX_VALUE_BYTES];
        let reserved =
            block_on(map.reserve_item::<&[u8]>(&mut buffer, &fid, &replacement.as_slice()))
                .unwrap();
        for (other, expected) in fids.iter().zip(&owners) {
            assert_eq!(
                block_on(
                    map.fetch_matching_item(&mut buffer, &other.get(), |data| data == expected)
                )
                .unwrap(),
                Some(expected.as_slice())
            );
        }
        block_on(map.append_reserved(&mut buffer, &fid, &replacement.as_slice(), reserved))
            .unwrap();
        assert_eq!(
            block_on(map.fetch_matching_item(&mut buffer, &fid, |data| data == owners[index]))
                .unwrap(),
            Some(owners[index].as_slice())
        );
        owners[index] = replacement;
    }
    for (fid, expected) in fids.iter().zip(&owners) {
        assert_eq!(
            block_on(map.fetch_item::<&[u8]>(&mut buffer, &fid.get())).unwrap(),
            Some(expected.as_slice())
        );
    }
}
