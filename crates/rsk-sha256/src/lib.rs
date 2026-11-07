// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! SHA-256 with unrolled register rotation, retaining RustCrypto's digest API.

#![cfg_attr(not(test), no_std)]

use core::fmt;
use rsk_secret::Secret;
use sha2::digest::{
    HashMarker, Output, Reset,
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, UpdateCore,
    },
    typenum::{U32, U64},
};

#[used]
static INITIAL: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const ROUND: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// Keep unoptimized frames bounded while preserving literal-index release rounds.
#[inline]
fn schedule_word(a: u32, x: u32, b: u32, y: u32) -> u32 {
    a.wrapping_add(x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3))
        .wrapping_add(b)
        .wrapping_add(y.rotate_right(17) ^ y.rotate_right(19) ^ (y >> 10))
}

#[inline]
fn round_first(e: u32, f: u32, g: u32, h: u32, constant: u32, word: u32) -> u32 {
    h.wrapping_add(e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25))
        .wrapping_add(g ^ (e & (f ^ g)))
        .wrapping_add(constant)
        .wrapping_add(word)
}

#[inline]
fn round_second(a: u32, b: u32, c: u32) -> u32 {
    (a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22))
        .wrapping_add((a & b) | (c & (a | b)))
}

// Eight-word groups keep literal indices without retaining every temporary.
#[inline]
fn expand8<const START: usize>(w: &mut [u32; 64]) {
    macro_rules! expand {
        ($i:expr) => {{
            w[$i] = schedule_word(w[$i - 16], w[$i - 15], w[$i - 7], w[$i - 2]);
        }};
    }
    expand!(START);
    expand!(START + 1);
    expand!(START + 2);
    expand!(START + 3);
    expand!(START + 4);
    expand!(START + 5);
    expand!(START + 6);
    expand!(START + 7);
}

#[inline]
fn rounds8<const START: usize>(working: &mut [u32; 8], w: &[u32; 64]) {
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *working;
    macro_rules! round {
        ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident, $i:expr) => {{
            let t1 = round_first($e, $f, $g, $h, ROUND[$i], w[$i]);
            let t2 = round_second($a, $b, $c);
            $d = $d.wrapping_add(t1);
            $h = t1.wrapping_add(t2);
        }};
    }
    round!(a, b, c, d, e, f, g, h, START);
    round!(h, a, b, c, d, e, f, g, START + 1);
    round!(g, h, a, b, c, d, e, f, START + 2);
    round!(f, g, h, a, b, c, d, e, START + 3);
    round!(e, f, g, h, a, b, c, d, START + 4);
    round!(d, e, f, g, h, a, b, c, START + 5);
    round!(c, d, e, f, g, h, a, b, START + 6);
    round!(b, c, d, e, f, g, h, a, START + 7);
    *working = [a, b, c, d, e, f, g, h];
}

fn compress(state: &mut [u32; 8], block: &Block<Sha256Core>) {
    let mut schedule = Secret::new([0u32; 64]);
    let w = schedule.expose_mut();
    for (word, bytes) in w.iter_mut().zip(block.as_chunks::<4>().0.iter()) {
        *word = u32::from_be_bytes(*bytes);
    }
    expand8::<16>(w);
    expand8::<24>(w);
    expand8::<32>(w);
    expand8::<40>(w);
    expand8::<48>(w);
    expand8::<56>(w);
    // Avoid rematerializing the schedule solely for its final wipe.
    let w = core::hint::black_box(w);
    let mut working = Secret::new([0u32; 8]);
    working.expose_mut().copy_from_slice(state);
    rounds8::<0>(working.expose_mut(), w);
    rounds8::<8>(working.expose_mut(), w);
    rounds8::<16>(working.expose_mut(), w);
    rounds8::<24>(working.expose_mut(), w);
    rounds8::<32>(working.expose_mut(), w);
    rounds8::<40>(working.expose_mut(), w);
    rounds8::<48>(working.expose_mut(), w);
    rounds8::<56>(working.expose_mut(), w);
    for (word, value) in state.iter_mut().zip(working.expose()) {
        *word = word.wrapping_add(*value);
    }
}

pub struct Sha256Core {
    state: Secret<[u32; 8]>,
    blocks: u64,
}
impl Default for Sha256Core {
    fn default() -> Self {
        Self {
            state: Secret::new(INITIAL),
            blocks: 0,
        }
    }
}
impl Clone for Sha256Core {
    fn clone(&self) -> Self {
        let mut cloned = Self::default();
        cloned
            .state
            .expose_mut()
            .copy_from_slice(self.state.expose());
        cloned.blocks = self.blocks;
        cloned
    }
}
impl HashMarker for Sha256Core {}
impl BlockSizeUser for Sha256Core {
    type BlockSize = U64;
}
impl BufferKindUser for Sha256Core {
    type BufferKind = Eager;
}
impl OutputSizeUser for Sha256Core {
    type OutputSize = U32;
}
impl UpdateCore for Sha256Core {
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.blocks += blocks.len() as u64;
        for block in blocks {
            compress(self.state.expose_mut(), block);
        }
    }
}
impl FixedOutputCore for Sha256Core {
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bits = 8 * (buffer.get_pos() as u64 + 64 * self.blocks);
        buffer.len64_padding_be(bits, |block| compress(self.state.expose_mut(), block));
        for (bytes, word) in out
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(self.state.expose())
        {
            bytes.copy_from_slice(&word.to_be_bytes());
        }
    }
}
impl Reset for Sha256Core {
    fn reset(&mut self) {
        *self = Self::default();
    }
}
impl AlgorithmName for Sha256Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha256")
    }
}
impl fmt::Debug for Sha256Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha256Core { ... }")
    }
}
pub type Sha256 = CoreWrapper<Sha256Core>;

/// Hash a suffix after one public 64-byte block whose chaining state is known.
/// The prefix has not been padded; its length still counts in the final digest.
pub fn digest_after_public_block(state: [u32; 8], suffix: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hash = Sha256::from_core(Sha256Core {
        state: Secret::new(state),
        blocks: 1,
    });
    Digest::update(&mut hash, suffix);
    hash.finalize().into()
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
