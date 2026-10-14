// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn partition(regions: &[Region]) {
    assert_eq!(regions.first().unwrap().start, SRAM_START);
    assert_eq!(regions.last().unwrap().end, SRAM_END);
    for region in regions {
        assert!(region.start < region.end);
        assert_eq!(region.start % ALIGNMENT, 0);
        assert_eq!(region.end % ALIGNMENT, 0);
    }
    for pair in regions.windows(2) {
        assert_eq!(pair[0].end, pair[1].start);
    }
}

#[test]
fn ram_has_one_immutable_code_window_and_data_everywhere_else() {
    let code = RamCode::new(0x2002_0000, 0x2002_1000).unwrap();
    let regions = code.regions();
    partition(&regions);
    assert_eq!(
        regions
            .iter()
            .filter(|r| r.permission == Permission::Code)
            .count(),
        1
    );
    assert_eq!(
        regions
            .iter()
            .filter(|r| r.permission == Permission::FlashStackCode)
            .count(),
        0
    );
}

#[test]
fn flash_stack_windows_on_either_side_keep_the_code_island_and_never_overlap() {
    let code = RamCode::new(0x2002_0000, 0x2002_1000).unwrap();
    for stack in (0x2001_8000..0x2001_8020).chain(0x2002_8000..0x2002_8020) {
        let regions = code.flash_stack_regions(stack).unwrap();
        partition(&regions);
        let flash = regions
            .iter()
            .find(|r| r.permission == Permission::FlashStackCode)
            .unwrap();
        assert!(flash.start <= stack - FLASH_STACK_BYTES);
        assert!(flash.end >= stack);
        assert!(flash.end - stack < ALIGNMENT);
        assert!(flash.end - flash.start <= FLASH_STACK_BYTES + ALIGNMENT);
        assert_eq!(
            regions
                .iter()
                .filter(|r| r.permission == Permission::Code)
                .count(),
            1
        );
        assert_eq!(
            regions
                .iter()
                .filter(|r| r.permission == Permission::FlashStackCode)
                .count(),
            1
        );
        assert!(flash.end < code.start || flash.start > code.end);
        let immutable = regions
            .iter()
            .find(|r| r.permission == Permission::Code)
            .unwrap();
        assert_eq!((immutable.start, immutable.end), (code.start, code.end));
    }
}

#[test]
fn bad_linker_ranges_fail_instead_of_creating_an_executable_data_region() {
    for (start, end) in [
        (SRAM_START, SRAM_START + ALIGNMENT),
        (SRAM_END - ALIGNMENT, SRAM_END),
        (0x2002_0001, 0x2002_1000),
        (0x2002_0000, 0x2002_1001),
        (0x2002_1000, 0x2002_0000),
        (0x2002_0000, 0x2002_0000),
    ] {
        assert!(RamCode::new(start, end).is_none());
    }
}

#[test]
fn an_overflow_or_stack_window_touching_ram_code_is_refused() {
    let code = RamCode::new(0x2002_0000, 0x2002_1000).unwrap();
    for stack in [
        0,
        u32::MAX,
        SRAM_START + FLASH_STACK_BYTES,
        SRAM_END,
        code.start,
        code.end,
        code.end + FLASH_STACK_BYTES,
    ] {
        assert!(code.flash_stack_regions(stack).is_none());
    }
}
