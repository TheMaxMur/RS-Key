// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[kani::proof]
fn flash_permissions_partition_ram_without_overlapping_immutable_code() {
    let Some(code) = RamCode::new(kani::any(), kani::any(), kani::any()) else {
        return;
    };
    let Some(regions) = code.flash_stack_regions(kani::any()) else {
        return;
    };
    assert_eq!(regions[0].start, SRAM_START);
    assert_eq!(regions[5].end, SRAM_END);
    let mut immutable = 0;
    let mut flash = 0;
    for region in regions {
        assert!(region.start < region.end);
        assert!(region.start.is_multiple_of(ALIGNMENT));
        assert!(region.end.is_multiple_of(ALIGNMENT));
        match region.permission {
            Permission::Code => {
                immutable += 1;
                assert!(
                    (region.start == code.start && region.end == code.end)
                        || (region.start == code.scratch_start && region.end == SRAM_END)
                );
            }
            Permission::FlashStackCode => {
                flash += 1;
                assert!(region.end < code.start || region.start > code.end);
                assert!(region.end < code.scratch_start);
                assert!(region.end - region.start <= FLASH_STACK_BYTES + ALIGNMENT);
            }
            Permission::Data => {}
        }
    }
    for pair in regions.windows(2) {
        assert_eq!(pair[0].end, pair[1].start);
    }
    assert_eq!(immutable, 2);
    assert_eq!(flash, 1);
    kani::cover!(regions[1].permission == Permission::FlashStackCode);
    kani::cover!(regions[3].permission == Permission::FlashStackCode);
}
