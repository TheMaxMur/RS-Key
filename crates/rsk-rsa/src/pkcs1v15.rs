// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! PKCS#1 v1.5 (RFC 8017): the signer on the asm CRT core ([`crate::crt`]) over
//! the bytes a host sends, the decryption both DECIPHER arms end in, and the
//! constant-time unpadding they read the block back with.
//!
//! Every structural test in that unpad is a mask, never a branch: which of the
//! four ways an EM can be malformed must not be timeable, or the status word's
//! padding oracle gains a finer-grained sibling.

use rsk_secret::Secret;

use crate::{MAX_RSA_BYTES, Rng, RsaError, RsaKey};

/// PKCS#1 v1.5's framing: `00 01|02`, at least eight bytes of padding and the `00`
/// separator, so a block of `k` bytes carries at most `k − 11` (RFC 8017 §9.2).
pub const PKCS1_V15_OVERHEAD: usize = 11;

/// Write the EMSA-PKCS1-v1_5 block `00 01 PS 00 ‖ di` for an `mlen`-byte modulus
/// into the pre-zeroed `em` (RFC 8017 §9.2). `PS` is `0xFF`·(mlen−dlen−3), and
/// the width check is what holds it to the mandatory eight bytes.
fn emsa_block(di: &[u8], mlen: usize, em: &mut [u8]) -> Result<(), RsaError> {
    if mlen < di.len() + PKCS1_V15_OVERHEAD {
        return Err(RsaError::BadWidth);
    }
    let ps_end = mlen - di.len() - 1;
    em[1] = 0x01;
    em[2..ps_end].fill(0xff);
    em[ps_end + 1..mlen].copy_from_slice(di);
    Ok(())
}

/// PKCS#1 v1.5 over `data` exactly as given, with the cached CRT params on the
/// UMAAL asm: `00 01 FF… 00 ‖ data` through the blinded, Bellcore-fault-checked
/// private op ([`crate::crt::private_op`]). This is how a YubiKey 5.8.0 signs for
/// OpenPGP: a DigestInfo is what a conformant host sends, a bare hash is not
/// wrapped in one, and nothing is signed raw. `BadWidth` past `mlen − 11` bytes.
pub fn rsa_sign_crt(
    crt: &crate::crt::RsaCrt,
    data: &[u8],
    rng: &mut dyn Rng,
    out: &mut [u8],
) -> Result<usize, RsaError> {
    let mlen = crt.modulus_len();
    let mut em = [0u8; MAX_RSA_BYTES];
    emsa_block(data, mlen, &mut em)?;
    crate::crt::private_op(crt, &em[..mlen], rng, out)
}

/// PKCS#1 v1.5 decryption with a full [`RsaKey`], on the software private op —
/// the arm PSO:DECIPHER falls back to for a legacy `P‖Q` key whose prime width
/// the asm CRT core cannot take. Same blinded, Bellcore-fault-checked operation
/// and the same constant-time [`unpad_encrypt`] as the asm arm.
pub fn rsa_decrypt(
    key: &RsaKey,
    ct: &[u8],
    rng: &mut dyn Rng,
    out: &mut [u8],
) -> Result<usize, RsaError> {
    let mlen = key.size();
    if mlen > MAX_RSA_BYTES {
        return Err(RsaError::BadWidth);
    }
    let mut em = Secret::<[u8; MAX_RSA_BYTES]>::zeroed();
    let res = key
        .private_op(ct, rng, &mut em.expose_mut()[..mlen])
        .and_then(|_| unpad_encrypt(&em.expose()[..mlen], out));
    em.wipe();
    res
}

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
pub fn unpad_encrypt(em: &[u8], out: &mut [u8]) -> Result<usize, RsaError> {
    if em.len() < 11 {
        return Err(RsaError::BadBlock);
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
        return Err(RsaError::BadBlock);
    }
    let msg = &em[start..];
    if msg.len() > out.len() {
        return Err(RsaError::BadWidth);
    }
    out[..msg.len()].copy_from_slice(msg);
    Ok(msg.len())
}

#[cfg(test)]
#[path = "pkcs1v15_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "pkcs1v15_wycheproof_tests.rs"]
mod wycheproof_tests;
