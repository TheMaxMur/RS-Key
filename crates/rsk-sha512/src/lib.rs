// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![cfg_attr(not(test), no_std)]

//! Fast SHA-512 and SHA-384 for the Cortex-M33, byte-identical to `sha2`.
//! Exposes [`Sha512`] and [`Sha384`] digest types that are drop-in for `sha2`'s,
//! so `hmac::Hmac<Sha512>` and `hkdf::Hkdf<Sha512>` compose over them byte-for-
//! byte — only the block-compression code differs. Why it exists: the RustCrypto
//! soft backend fully unrolls SHA-512 into a ~28 KB straight-line body that
//! overflows the RP2350's XIP cache and re-fetches over QSPI flash on every block
//! (~2 ms/block, ~191 ms for the FIDO key-derivation ratchet); this crate keeps
//! the compression a compact rolled loop (~0.9 KB) that fits the cache — measured
//! ~4× faster end-to-end on a getAssertion, with the identical hash. SHA-384 is
//! the same SHA-512 compression with a different IV and a 48-byte truncation.
//!
//! Only the compression (`block::compress`) is new; the SHA finalization, HMAC
//! and HKDF constructions above it are the unchanged generic RustCrypto code, so
//! byte-identity reduces to "does this compression equal FIPS 180-4", gated by a
//! randomized differential against `sha2`/`hmac`/`hkdf` plus NIST/RFC KATs.
//! SHA-512 is big-endian; the chaining state is a native `[u64; 8]`.

use core::fmt;

use digest::{
    HashMarker, Output, Reset,
    block_buffer::{BlockBuffer, Eager},
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, UpdateCore,
    },
    generic_array::GenericArray,
    typenum::{U48, U64, U128},
};

mod block;
use block::{H512_384, H512_512};

/// Fold each 128-byte big-endian message block of `blocks` into `state`. Kept a
/// compact rolled loop (see [`block::compress`]) so the whole routine fits the
/// RP2350 XIP cache — the reason it beats the unrolled `sha2` soft backend.
fn sha512_compress(state: &mut [u64; 8], blocks: &[GenericArray<u8, U128>]) {
    for b in blocks {
        // GenericArray<u8, U128> has the layout of [u8; 128]; the conversion is
        // a checked reborrow, so no unsafe is needed.
        let b: &[u8; 128] = b.as_slice().try_into().expect("SHA-512 block is 128 bytes");
        block::compress(state, b);
    }
}

// The SHA-512 and SHA-384 cores differ only in IV, output length and name; the
// update/finalize logic — the byte-identity-critical part — lives once here and
// both cores delegate to it. A 128-byte block, `Eager` buffer, `[u64; 8]` state.
type Sha512Buffer = BlockBuffer<U128, Eager>;

#[inline]
fn core_update(state: &mut [u64; 8], block_len: &mut u128, blocks: &[GenericArray<u8, U128>]) {
    *block_len += blocks.len() as u128;
    sha512_compress(state, blocks);
}

/// Pad (0x80, zeros, 128-bit big-endian bit length), run the final block(s), and
/// write the state big-endian into `out`. `out.len()` selects the digest width:
/// 64 for SHA-512 (all 8 words), 48 for SHA-384 (the leading 6). This mirrors
/// `sha2`'s finalization exactly.
#[inline]
fn core_finalize(state: &mut [u64; 8], block_len: u128, buffer: &mut Sha512Buffer, out: &mut [u8]) {
    let bit_len = 8 * (buffer.get_pos() as u128 + 128 * block_len);
    buffer.len128_padding_be(bit_len, |b| {
        sha512_compress(state, core::slice::from_ref(b))
    });
    for (chunk, word) in out.chunks_exact_mut(8).zip(state.iter()) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
}

/// Core block-level SHA-512 hasher (512-bit output).
#[derive(Clone)]
pub struct Sha512Core {
    state: [u64; 8],
    block_len: u128,
}

impl Default for Sha512Core {
    #[inline]
    fn default() -> Self {
        Self {
            state: H512_512,
            block_len: 0,
        }
    }
}

impl HashMarker for Sha512Core {}
impl BlockSizeUser for Sha512Core {
    type BlockSize = U128;
}
impl BufferKindUser for Sha512Core {
    type BufferKind = Eager;
}
impl OutputSizeUser for Sha512Core {
    type OutputSize = U64;
}
impl UpdateCore for Sha512Core {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        core_update(&mut self.state, &mut self.block_len, blocks);
    }
}
impl FixedOutputCore for Sha512Core {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        core_finalize(&mut self.state, self.block_len, buffer, out);
    }
}
impl Reset for Sha512Core {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}
impl AlgorithmName for Sha512Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha512")
    }
}
impl fmt::Debug for Sha512Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha512Core { ... }")
    }
}

/// Core block-level SHA-384 hasher (384-bit output, SHA-512 compression with the
/// SHA-384 IV and the leading 48 bytes of state).
#[derive(Clone)]
pub struct Sha384Core {
    state: [u64; 8],
    block_len: u128,
}

impl Default for Sha384Core {
    #[inline]
    fn default() -> Self {
        Self {
            state: H512_384,
            block_len: 0,
        }
    }
}

impl HashMarker for Sha384Core {}
impl BlockSizeUser for Sha384Core {
    type BlockSize = U128;
}
impl BufferKindUser for Sha384Core {
    type BufferKind = Eager;
}
impl OutputSizeUser for Sha384Core {
    type OutputSize = U48;
}
impl UpdateCore for Sha384Core {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        core_update(&mut self.state, &mut self.block_len, blocks);
    }
}
impl FixedOutputCore for Sha384Core {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        core_finalize(&mut self.state, self.block_len, buffer, out);
    }
}
impl Reset for Sha384Core {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}
impl AlgorithmName for Sha384Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha384")
    }
}
impl fmt::Debug for Sha384Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha384Core { ... }")
    }
}

/// SHA-512 hasher — drop-in for `sha2::Sha512`.
pub type Sha512 = CoreWrapper<Sha512Core>;
/// SHA-384 hasher — drop-in for `sha2::Sha384`.
pub type Sha384 = CoreWrapper<Sha384Core>;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
