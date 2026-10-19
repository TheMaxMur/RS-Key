// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! SHA-256 with eight-round register rotation, retaining RustCrypto's digest API.

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

const INITIAL: [u32; 8] = [
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

fn compress(state: &mut [u32; 8], block: &Block<Sha256Core>) {
    let mut schedule = Secret::new([0u32; 64]);
    let w = schedule.expose_mut();
    for (word, bytes) in w.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes(bytes.try_into().expect("SHA-256 word is four bytes"));
    }
    for i in 16..64 {
        let x = w[i - 15];
        let y = w[i - 2];
        w[i] = w[i - 16]
            .wrapping_add(x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3))
            .wrapping_add(w[i - 7])
            .wrapping_add(y.rotate_right(17) ^ y.rotate_right(19) ^ (y >> 10));
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    // Rotating the register roles saves the seven state moves in each round.
    macro_rules! round {
        ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident, $i:expr) => {{
            let t1 = $h
                .wrapping_add($e.rotate_right(6) ^ $e.rotate_right(11) ^ $e.rotate_right(25))
                .wrapping_add($g ^ ($e & ($f ^ $g)))
                .wrapping_add(ROUND[$i])
                .wrapping_add(w[$i]);
            let t2 = ($a.rotate_right(2) ^ $a.rotate_right(13) ^ $a.rotate_right(22))
                .wrapping_add(($a & $b) | ($c & ($a | $b)));
            $d = $d.wrapping_add(t1);
            $h = t1.wrapping_add(t2);
        }};
    }
    for i in (0..64).step_by(8) {
        round!(a, b, c, d, e, f, g, h, i);
        round!(h, a, b, c, d, e, f, g, i + 1);
        round!(g, h, a, b, c, d, e, f, i + 2);
        round!(f, g, h, a, b, c, d, e, i + 3);
        round!(e, f, g, h, a, b, c, d, i + 4);
        round!(d, e, f, g, h, a, b, c, i + 5);
        round!(c, d, e, f, g, h, a, b, i + 6);
        round!(b, c, d, e, f, g, h, a, i + 7);
    }
    for (word, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *word = word.wrapping_add(value);
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
        for (bytes, word) in out.chunks_exact_mut(4).zip(self.state.expose()) {
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

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
