// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Constant-time PKCS#1 v1.5 encryption unpadding (RFC 8017 §7.2.2), the
//! decryption-side counterpart to `keys::rsa_sign_em`. It exists so PSO:DECIPHER
//! can run its private operation on the asm CRT core ([`crate::rsa_crt`]) instead
//! of the `rsa` crate, which carries RUSTSEC-2023-0071 with no fixed release.
//!
//! Every structural test below is a mask, never a branch: which of the four ways
//! an EM can be malformed must not be timeable, or the status word's padding
//! oracle gains a finer-grained sibling.

use rsk_sdk::Sw;

/// `0xFF` when `a == b`, `0x00` otherwise.
fn ct_eq(a: u8, b: u8) -> u8 {
    let x = a ^ b;
    // `x | -x` has its top bit set for every non-zero `x`, and is 0 for `x == 0`.
    let nonzero = (x | x.wrapping_neg()) >> 7;
    (nonzero ^ 1).wrapping_neg()
}

/// Widen a `0x00`/`0xFF` flag to an all-ones / all-zeroes `usize` mask.
fn ct_mask(flag: u8) -> usize {
    ((flag & 1) as usize).wrapping_neg()
}

/// `0xFF` when `v >= bound`, for values far below `usize::MAX / 2`.
fn ct_ge(v: usize, bound: usize) -> u8 {
    let below = (v.wrapping_sub(bound) >> (usize::BITS - 1)) as u8 & 1;
    (below ^ 1).wrapping_neg()
}

/// Strip `0x00 ‖ 0x02 ‖ PS ‖ 0x00` from a modulus-width `em`, writing the message
/// to `out` and returning its length. `PS` is at least 8 non-zero bytes, so an
/// `em` shorter than 11 has no valid form at all.
///
/// The message is rejected as a whole — a caller learns "this ciphertext did not
/// decrypt", never which byte betrayed it.
pub fn unpad_encrypt(em: &[u8], out: &mut [u8]) -> Result<usize, Sw> {
    if em.len() < 11 {
        return Err(Sw::WRONG_DATA);
    }
    let mut good = ct_eq(em[0], 0x00) & ct_eq(em[1], 0x02);

    // One pass over the whole block. `seen` latches at the first zero byte, so
    // `start` records the offset just past it — the message's first byte. Bytes
    // of PS are non-zero by construction: an earlier zero would have been this
    // separator instead.
    let mut seen = 0u8;
    let mut start = 0usize;
    for (i, &b) in em.iter().enumerate().skip(2) {
        let is_zero = ct_eq(b, 0x00);
        let first = is_zero & !seen;
        start |= (i + 1) & ct_mask(first);
        seen |= is_zero;
    }
    // |PS| = start − 3 must be at least 8, so the message starts at 11 or later.
    // A block with no separator never latched and leaves `start` at 0, which the
    // same floor rejects — so this one test covers both malformations.
    good &= ct_ge(start, 11);

    if good != 0xFF {
        return Err(Sw::WRONG_DATA);
    }
    let msg = &em[start..];
    if msg.len() > out.len() {
        return Err(Sw::WRONG_LENGTH);
    }
    out[..msg.len()].copy_from_slice(msg);
    Ok(msg.len())
}

#[cfg(test)]
#[path = "pkcs1v15_tests.rs"]
mod tests;
