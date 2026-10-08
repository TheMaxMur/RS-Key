// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn vector_rows_preserve_comments_and_empty_fields() {
    let rows: Vec<_> = cases::<3>("# header\n2048 - comment with spaces").collect();
    assert_eq!(rows, [["2048", "", "comment with spaces"]]);
}

#[test]
#[should_panic(expected = "1 of 2 fields: incomplete")]
fn a_short_vector_row_is_refused() {
    let _ = cases::<2>("incomplete").next();
}
