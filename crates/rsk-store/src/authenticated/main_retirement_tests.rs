// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::{Effect, FaultFlash, Io, Rule};

#[path = "main_prefix_read_tests.rs"]
mod prefix_read;

fn provision(flash: &FaultFlash) -> Main<FaultFlash, UncachedMap> {
    let mut main = main_on(flash.clone());
    main.initialize(&KEY, 0, &Directory::new()).unwrap();
    for value in 0..6u8 {
        main.write(&KEY, 0xB001, Some(&[value; 1024])).unwrap();
    }
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
    main
}

#[test]
fn retirement_reads_less_without_changing_any_erasure_or_retained_owner() {
    let measure = |filtered: bool| {
        let flash = crate::tests::fault_flash_for_authenticated_tests();
        let mut main = provision(&flash);
        flash.arm(&[]);
        if filtered {
            main.retire_unpublished(&KEY).unwrap();
        } else {
            main.validate_values(&KEY).unwrap();
            let mut retired = Vec::new();
            let mut iter = block_on(main.map.fetch_all_items(main.buffer.expose_mut())).unwrap();
            while let Some((fid, _)) =
                block_on(iter.next::<&[u8]>(main.buffer.expose_mut())).unwrap()
            {
                if main.directory.find(fid).is_none() && !retired.contains(&fid) {
                    retired.push(fid);
                }
            }
            for fid in retired {
                block_on(main.map.remove_item(main.buffer.expose_mut(), &fid)).unwrap();
            }
            main.validate_values(&KEY).unwrap();
        }
        let events = flash.events();
        assert_eq!(main.read(&KEY, 0xB001, &mut [0; 1024]), Ok(Some(1024)));
        assert!(
            block_on(
                main.map
                    .fetch_item_unrepaired::<&[u8]>(main.buffer.expose_mut(), &0xB000)
            )
            .unwrap()
            .is_none()
        );
        (flash.image(), events)
    };
    let (filtered_image, filtered) = measure(true);
    let (full_image, full) = measure(false);
    assert_eq!(filtered_image, full_image);
    assert_eq!(
        filtered
            .iter()
            .filter(|e| e.0 != Io::Read)
            .collect::<Vec<_>>(),
        full.iter().filter(|e| e.0 != Io::Read).collect::<Vec<_>>()
    );
    let bytes = |events: &[(Io, u32, usize)]| {
        events
            .iter()
            .filter(|e| e.0 == Io::Read)
            .map(|e| e.2)
            .sum::<usize>()
    };
    assert!(bytes(&filtered) < bytes(&full));
}

#[test]
fn retirement_still_refuses_a_damaged_published_value_before_deletion() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut main = provision(&flash);
    let mut changed = flash.image();
    let at = changed
        .windows(1024)
        .position(|bytes| bytes == [5; 1024])
        .unwrap();
    *changed.get_mut(at).unwrap() ^= 1;
    flash.arm(&[]);
    flash.replace_image_before_read(0, changed.clone());
    assert_eq!(main.retire_unpublished(&KEY), Err(Error::MemoryFatal));
    assert_eq!(flash.image(), changed);
    assert!(flash.events().iter().all(|e| e.0 == Io::Read));
}

#[test]
fn every_retirement_read_refusal_is_reported_instead_of_hiding_an_orphan() {
    let trace = crate::tests::fault_flash_for_authenticated_tests();
    let mut healthy = provision(&trace);
    trace.arm(&[]);
    healthy.retire_unpublished(&KEY).unwrap();
    let reads = trace.events().iter().filter(|e| e.0 == Io::Read).count();
    for skip in 0..reads {
        let flash = crate::tests::fault_flash_for_authenticated_tests();
        let mut main = provision(&flash);
        flash.arm(&[Rule {
            io: Io::Read,
            skip,
            effect: Effect::Refuse,
            latched: false,
        }]);
        assert_eq!(
            main.retire_unpublished(&KEY),
            Err(Error::MemoryFatal),
            "read {skip}"
        );
        assert_eq!(flash.hits(), [1]);
    }
}

#[path = "main_read_geometry_tests.rs"]
mod read_geometry;
