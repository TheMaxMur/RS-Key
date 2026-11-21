// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[kani::proof]
#[kani::unwind(5)]
fn staged_dek_requires_its_owner_format_and_body() {
    let bytes: [u8; 4] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    let target: u16 = kani::any();
    kani::assume([EF_DEK_PW1.get(), EF_DEK_PW3.get(), EF_DEK_RC.get()].contains(&target));
    let fid = KeyFid::new(target);
    let input = &bytes[..len];
    let accepted = staged_is_for(input, fid);
    let owner = bytes[0] == target as u8;
    let format = bytes[1] == DEK_FORMAT_V3;

    kani::cover!(accepted, "a valid stage header reaches authentication");
    kani::cover!(
        (len >= 3) & !owner & format,
        "the owner independently refuses a stage"
    );
    kani::cover!(
        (len >= 3) & owner & !format,
        "the format independently refuses a stage"
    );
    kani::cover!(
        (len == 2) & owner & format,
        "the absent body independently refuses a stage"
    );

    if accepted {
        assert!(
            len >= 3,
            "a staged DEK needs a byte beyond its owner and format"
        );
        assert!(
            owner,
            "a stage for another reference cannot replace this DEK"
        );
        assert!(
            format,
            "an unsupported staged format cannot replace this DEK"
        );
    }
    if len >= 3 && owner && format {
        assert!(
            accepted,
            "a valid stage header must reach the authenticated reader"
        );
    }
}
