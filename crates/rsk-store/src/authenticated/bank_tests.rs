// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[expect(
    clippy::unwrap_used,
    reason = "An admitted window precedes invalid span arguments without allocating giant buffers."
)]
#[test]
fn span_rejects_integer_overflow_and_retains_exact_empty_and_full_bounds() {
    let bank = RawBank::new(crate::tests::flash_for_authenticated_tests(), 4096..8192).unwrap();
    assert_eq!(bank.span(0, 0), Ok(4096..4096));
    assert_eq!(bank.span(0, 4096), Ok(4096..8192));
    assert_eq!(bank.span(u32::MAX, 0), Err(Error::MemoryFatal));
    assert_eq!(
        bank.span(0, usize::try_from(u32::MAX).unwrap()),
        Err(Error::MemoryFatal)
    );
    #[cfg(target_pointer_width = "64")]
    assert_eq!(
        bank.span(0, usize::try_from(u32::MAX).unwrap() + 1),
        Err(Error::MemoryFatal)
    );
}
