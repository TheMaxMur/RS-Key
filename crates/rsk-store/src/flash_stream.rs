// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Checked CPU reads from the RP2350 XIP stream's two-word FIFO.

pub const WORD_BYTES: usize = 4;
pub const FIFO_WORDS: usize = 2;
const MAX_WORDS: usize = 0x003f_ffff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unaligned,
    OutOfBounds,
    Transfer,
}

/// Exclusive CPU ownership must cover this interface through the final stop.
pub trait Stream {
    fn stop(&mut self);
    fn available(&mut self) -> usize;
    fn start(&mut self, offset: u32, words: u32);
    fn read_word(&mut self) -> u32;
    fn remaining(&mut self) -> u32;
    /// The internal flash-relative address, with CPU alias bits removed.
    fn address(&mut self) -> u32;
    fn expired(&mut self) -> bool;
}

struct Active<'a, S: Stream>(&'a mut S);
impl<S: Stream> Drop for Active<'_, S> {
    #[inline(always)]
    fn drop(&mut self) {
        self.0.stop();
    }
}

/// Read complete words freshly; abort on a stall or inconsistent final progress.
#[inline(always)]
pub fn read(
    stream: &mut impl Stream,
    capacity: usize,
    offset: u32,
    bytes: &mut [u8],
) -> Result<(), Error> {
    if !offset.is_multiple_of(4)
        || !bytes.len().is_multiple_of(WORD_BYTES)
        || bytes.len() / WORD_BYTES > MAX_WORDS
    {
        return Err(Error::Unaligned);
    }
    let end = usize::try_from(offset)
        .map_err(|_| Error::OutOfBounds)?
        .checked_add(bytes.len())
        .filter(|end| *end <= capacity)
        .ok_or(Error::OutOfBounds)?;
    let end = u32::try_from(end).map_err(|_| Error::OutOfBounds)?;
    if bytes.is_empty() {
        return Ok(());
    }
    stream.stop();
    let active = Active(stream);
    for _ in 0..FIFO_WORDS {
        if active.0.available() == 0 {
            break;
        }
        active.0.read_word();
    }
    if active.0.available() != 0 {
        return Err(Error::Transfer);
    }
    active.0.start(
        offset,
        u32::try_from(bytes.len() / WORD_BYTES).map_err(|_| Error::OutOfBounds)?,
    );
    let mut words = bytes.as_chunks_mut::<WORD_BYTES>().0.iter_mut();
    while words.len() != 0 {
        let count = active.0.available();
        if count > FIFO_WORDS || (count == 0 && active.0.expired()) {
            return Err(Error::Transfer);
        }
        for _ in 0..count.min(words.len()) {
            let word = words.next().ok_or(Error::Transfer)?;
            word.copy_from_slice(&active.0.read_word().to_le_bytes());
        }
    }
    if active.0.remaining() != 0 || active.0.address() != end || active.0.available() != 0 {
        return Err(Error::Transfer);
    }
    Ok(())
}

#[cfg(test)]
#[path = "flash_stream_tests.rs"]
mod tests;
