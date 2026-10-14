// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn share_titles_name_both_numbers() {
    let mut buf = [0u8; 18];
    assert_eq!(fmt_share_title(1, 3, &mut buf), "Share 1/3");
    assert_eq!(fmt_share_title(2, 12, &mut buf), "Share 2/12");
    assert_eq!(fmt_share_title(65535, 65535, &mut buf), "Share 65535/65535");
}
