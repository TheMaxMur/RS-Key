// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn new_and_default_expose_complete_aligned_zeroed_windows() {
    for buffer in [FlashBuf::<64>::new(), FlashBuf::<64>::default()] {
        assert_eq!(buffer.len(), 64);
        assert_eq!(&*buffer, &[0; 64]);
        assert_eq!(buffer.as_ptr() as usize % 4, 0);
    }
}

#[test]
fn the_mutable_window_changes_the_same_readable_bytes() {
    let mut buffer = FlashBuf::<64>::new();
    buffer.copy_from_slice(&[0x5a; 64]);
    assert_eq!(&*buffer, &[0x5a; 64]);
}

#[test]
fn a_secret_wipe_scrubs_the_live_flash_staging_buffer() {
    let mut buffer = rsk_secret::Secret::new(FlashBuf::<64>::new());
    buffer.expose_mut().fill(0xa5);
    assert_eq!(&**buffer.expose(), &[0xa5; 64]);
    buffer.wipe();
    assert_eq!(&**buffer.expose(), &[0; 64]);
}
