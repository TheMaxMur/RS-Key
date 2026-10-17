// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

/// Board compression over one padded SHA-256 message block.
pub trait Sha256Compression {
    fn compress(&mut self, block: &[u8; 64]) -> bool;
}

/// SHA-256 framing for a board-owned compression engine over public metadata.
/// Each emitted block includes standard SHA-256 padding once `finish` runs.
pub struct Sha256Blocks {
    block: [u8; 64],
    used: usize,
    length: u64,
}

impl Default for Sha256Blocks {
    fn default() -> Self {
        Self {
            block: [0; 64],
            used: 0,
            length: 0,
        }
    }
}

impl Sha256Blocks {
    /// A refused block invalidates this message; discard the state on `false`.
    #[inline(always)]
    #[must_use]
    pub fn update(&mut self, mut bytes: &[u8], sink: &mut impl Sha256Compression) -> bool {
        self.length = self.length.wrapping_add(bytes.len() as u64);
        if self.used != 0 {
            let count = bytes.len().min(self.block.len() - self.used);
            self.block[self.used..self.used + count].copy_from_slice(&bytes[..count]);
            self.used += count;
            bytes = &bytes[count..];
            if self.used == self.block.len() {
                self.used = 0;
                if !sink.compress(&self.block) {
                    return false;
                }
            }
        }
        let (blocks, rest) = bytes.as_chunks::<64>();
        for block in blocks {
            if !sink.compress(block) {
                return false;
            }
        }
        self.block[..rest.len()].copy_from_slice(rest);
        self.used += rest.len();
        true
    }

    #[inline(always)]
    #[must_use]
    pub fn finish(mut self, sink: &mut impl Sha256Compression) -> bool {
        self.block[self.used] = 0x80;
        self.block[self.used + 1..].fill(0);
        if self.used >= 56 {
            if !sink.compress(&self.block) {
                return false;
            }
            self.block.fill(0);
        }
        self.block[56..].copy_from_slice(&self.length.wrapping_mul(8).to_be_bytes());
        sink.compress(&self.block)
    }
}

#[cfg(test)]
#[path = "sha256_blocks_tests.rs"]
mod tests;
