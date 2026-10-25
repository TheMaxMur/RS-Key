// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

/// Wipe a complete initialized SRAM buffer without rounding past its edges.
#[inline(never)]
pub fn wipe_bytes(bytes: &mut [u8]) {
    const WORDS_PER_PASS: usize = 8;
    // SAFETY: all u32 bit patterns are valid. The exclusive initialized slice
    // splits into disjoint byte edges and an aligned word span, with no padding.
    let (head, words, tail) = unsafe { bytes.align_to_mut::<u32>() };
    for byte in head.iter_mut().chain(tail) {
        // SAFETY: this exclusive byte belongs to the supplied SRAM slice.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    let zero = |word: &mut u32| {
        // SAFETY: align_to_mut supplied this initialized, aligned exclusive word.
        unsafe { core::ptr::write_volatile(word, 0) };
    };
    let (blocks, rest) = words.as_chunks_mut::<WORDS_PER_PASS>();
    for block in blocks {
        zero(&mut block[0]);
        zero(&mut block[1]);
        zero(&mut block[2]);
        zero(&mut block[3]);
        zero(&mut block[4]);
        zero(&mut block[5]);
        zero(&mut block[6]);
        zero(&mut block[7]);
    }
    for word in rest {
        zero(word);
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
