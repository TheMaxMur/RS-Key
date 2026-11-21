// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

// These map shapes never carry subparameters or skipped values. The stubs
// assert their unreachability without unfolding minicbor's nested-value walker.
fn unexpected_skip(_: &mut Decoder<'_>) -> Result<(), CtapError> {
    assert!(false, "a scalar two-field map reached the skip walker");
    Err(CtapError::Other)
}

fn unexpected_subpara<'a>(
    _: &'a [u8],
    _: &mut Decoder<'a>,
    _: &mut Req<'a>,
) -> Result<(), CtapError> {
    assert!(false, "a scalar two-field map reached subparameters");
    Err(CtapError::Other)
}

#[kani::proof]
#[kani::unwind(3)]
#[kani::stub(crate::cbordec::skip_value, unexpected_skip)]
#[kani::stub(parse_subpara, unexpected_subpara)]
fn two_field_maps_require_the_subcommand_before_a_protocol_or_duplicate() {
    let first: u8 = kani::any();
    let duplicate: bool = kani::any();
    let subcommand: u8 = kani::any();
    kani::assume(first < 24 && subcommand < 24);
    let second = if duplicate { 1 } else { 3 };
    let data = [0xA2, first, subcommand, second, 0];
    // Pure operands avoid short-circuit MIR copies of the same source cover.
    kani::cover!(
        (first == 1) & (second == 3),
        "ordered protocol field accepted"
    );
    kani::cover!((first == 1) & (second == 1), "duplicate subcommand refused");
    kani::cover!(first != 1, "missing first subcommand refused");
    let result = parse(&data);
    if first != 1 {
        assert!(matches!(result, Err(CtapError::MissingParameter)));
    } else if duplicate {
        assert!(matches!(result, Err(CtapError::InvalidCbor)));
    } else {
        assert!(
            result.is_ok_and(
                |req| req.subcommand == u64::from(subcommand) && req.raw_subpara.is_empty()
            )
        );
    }
}
