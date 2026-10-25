// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

const SCRATCH_START: u32 = MAIN_SRAM_END + 256;

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
fn ram_has_two_immutable_code_windows_and_data_everywhere_else() {
    let code = RamCode::new(0x2002_0000, 0x2002_1000, SCRATCH_START).unwrap();
    let regions = code.regions();
    partition(&regions);
    assert_eq!(
        regions
            .iter()
            .filter(|r| r.permission == Permission::Code)
            .count(),
        2
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
    let code = RamCode::new(0x2002_0000, 0x2002_1000, SCRATCH_START).unwrap();
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
            2
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
        assert_eq!(regions[5], code.scratch_region());
        assert!(flash.end < code.scratch_start);
        assert_eq!(regions.len() + 2, 8);
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
        assert!(RamCode::new(start, end, SCRATCH_START).is_none());
    }
}

#[test]
fn an_overflow_or_stack_window_touching_ram_code_is_refused() {
    let code = RamCode::new(0x2002_0000, 0x2002_1000, SCRATCH_START).unwrap();
    for stack in [
        0,
        u32::MAX,
        SRAM_START + FLASH_STACK_BYTES,
        MAIN_SRAM_END,
        SCRATCH_START,
        SRAM_END,
        code.start,
        code.end,
        code.end + FLASH_STACK_BYTES,
    ] {
        assert!(code.flash_stack_regions(stack).is_none());
    }
}

#[test]
fn scratch_bounds_cannot_make_shared_ram_executable() {
    for scratch in [
        0,
        MAIN_SRAM_END - ALIGNMENT,
        SCRATCH_START + 1,
        SRAM_END,
        u32::MAX,
    ] {
        assert!(RamCode::new(0x2002_0000, 0x2002_1000, scratch).is_none());
    }
    for scratch in [MAIN_SRAM_END, SCRATCH_START, SRAM_END - ALIGNMENT] {
        let code = RamCode::new(0x2002_0000, 0x2002_1000, scratch).unwrap();
        partition(&code.regions());
        assert_eq!(
            code.regions()[3],
            Region {
                start: scratch,
                end: SRAM_END,
                permission: Permission::Code,
            }
        );
    }
    assert!(RamCode::new(MAIN_SRAM_END - ALIGNMENT, MAIN_SRAM_END, SCRATCH_START).is_none());
}

#[test]
fn residue_prefix_is_data_and_both_code_windows_remain_read_only() {
    let code = RamCode::new(0x2002_0000, 0x2002_1000, SCRATCH_START).unwrap();
    for regions in [
        code.regions().to_vec(),
        code.flash_stack_regions(0x2001_8000).unwrap().to_vec(),
        code.flash_stack_regions(0x2002_8000).unwrap().to_vec(),
    ] {
        let prefix = regions
            .iter()
            .find(|r| r.start <= MAIN_SRAM_END && r.end >= SCRATCH_START)
            .unwrap();
        assert_eq!(prefix.permission, Permission::Data);
        let code_regions: Vec<_> = regions
            .iter()
            .filter(|r| r.permission == Permission::Code)
            .copied()
            .collect();
        assert_eq!(
            code_regions,
            [
                Region {
                    start: code.start,
                    end: code.end,
                    permission: Permission::Code
                },
                code.scratch_region()
            ]
        );
    }
}
