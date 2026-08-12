// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! BIP-39 mnemonic encoding for a 256-bit seed, on-device.
//!
//! The trusted display shows the recovery phrase as 24 English words derived **on the
//! device** from its master seed, so the seed never crosses USB. This is the encode
//! direction only (entropy → words): the host keeps the decode/restore path (its
//! `mnemonic` library). The two must agree bit-for-bit, which a host-vector test pins.
//!
//! `no_std`, no alloc, no secret intermediate buffer kept: [`entropy_to_indices`] reads
//! the 264 bits (256 entropy + 8 checksum) straight out of the inputs. The 24 returned
//! indices encode the seed, so the **caller zeroizes them** after rendering.

#![no_std]

mod wordlist;
pub use wordlist::WORDS;

/// Words a 256-bit (32-byte) entropy encodes: `(256 + 8 checksum) / 11 = 24`.
pub const WORD_COUNT: usize = 24;

/// The 24 BIP-39 word indices (`0..2048`) for a 32-byte seed, in order. Each is an
/// 11-bit value, so it always indexes [`WORDS`] in bounds (proven by `indices_in_range`).
///
/// The checksum is the first 8 bits of `SHA-256(entropy)`, appended to the 256 entropy
/// bits; the 264-bit string is then read big-endian in 11-bit groups. The returned array
/// is secret (it reconstructs the seed) — zeroize it once the phrase is shown.
pub fn entropy_to_indices(entropy: &[u8; 32]) -> [u16; WORD_COUNT] {
    pack_indices(entropy, rsk_crypto::sha256(entropy)[0])
}

/// The packing half of [`entropy_to_indices`], with the checksum byte passed in.
/// Split out so `indices_in_range` proves the real loop over a symbolic checksum
/// instead of dragging SHA-256 into the solver for no added assurance.
fn pack_indices(entropy: &[u8; 32], checksum: u8) -> [u16; WORD_COUNT] {
    // Bit `b` of the 264-bit string: the first 256 come from `entropy` (MSB-first per
    // byte), the last 8 from `checksum`. No copy of the seed is made.
    let bit = |b: usize| -> u16 {
        let byte = if b < 256 { entropy[b / 8] } else { checksum };
        ((byte >> (7 - (b % 8))) & 1) as u16
    };
    let mut idx = [0u16; WORD_COUNT];
    let mut i = 0;
    while i < WORD_COUNT {
        let mut v = 0u16;
        let mut j = 0;
        while j < 11 {
            v = (v << 1) | bit(i * 11 + j);
            j += 1;
        }
        idx[i] = v;
        i += 1;
    }
    idx
}

/// The BIP-39 word for `index` (`0..2048`). Indices from [`entropy_to_indices`] are
/// always in range; an out-of-range index panics (a programming error).
pub fn word(index: u16) -> &'static str {
    WORDS[index as usize]
}

#[cfg(kani)]
#[path = "kani.rs"]
mod proofs;

#[cfg(test)]
mod tests;
