// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Checked CPU reads from RP2350 XIP and its two-word stream FIFO.

pub const WORD_BYTES: usize = 4;
pub const FIFO_WORDS: usize = 2;
const MAX_WORDS: usize = 0x003f_ffff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unaligned,
    OutOfBounds,
    Transfer,
}

/// Decode a captured FIFO status; simultaneous empty and full is inconsistent.
#[inline(always)]
pub fn fifo_readable(empty: bool, full: bool) -> Result<bool, Error> {
    if empty && full {
        Err(Error::Transfer)
    } else {
        Ok(!empty)
    }
}

/// Exclusive CPU ownership must cover this interface through the final stop.
pub trait Stream {
    fn stop(&mut self);
    fn readable(&mut self) -> Result<bool, Error>;
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

/// Read one byte only after proving the hardware callback's offset is in bounds.
#[inline(always)]
pub fn read_byte(capacity: usize, offset: u32, read: impl FnOnce(u32) -> u8) -> Result<u8, Error> {
    if usize::try_from(offset).map_err(|_| Error::OutOfBounds)? >= capacity {
        return Err(Error::OutOfBounds);
    }
    Ok(read(offset))
}

/// Read adjacent bytes only after proving both callback offsets are in bounds.
#[inline(always)]
pub fn read_pair(
    capacity: usize,
    offset: u32,
    mut read: impl FnMut(u32) -> u8,
) -> Result<[u8; 2], Error> {
    let next = offset.checked_add(1).ok_or(Error::OutOfBounds)?;
    if usize::try_from(next).map_err(|_| Error::OutOfBounds)? >= capacity {
        return Err(Error::OutOfBounds);
    }
    Ok([read(offset), read(next)])
}

/// Read complete words freshly; abort on a stall or inconsistent final progress.
#[inline(always)]
pub fn read(
    stream: &mut impl Stream,
    capacity: usize,
    offset: u32,
    bytes: &mut [u8],
) -> Result<(), Error> {
    let length = bytes.len();
    let mut words = bytes.as_chunks_mut::<WORD_BYTES>().0.iter_mut();
    transfer(stream, capacity, offset, length, |value| {
        words
            .next()
            .ok_or(Error::Transfer)?
            .copy_from_slice(&value.to_le_bytes());
        Ok(())
    })
}

/// Check freshly streamed words without copying an erased tail into SRAM.
#[inline(always)]
pub fn read_erased(
    stream: &mut impl Stream,
    capacity: usize,
    offset: u32,
    length: usize,
) -> Result<bool, Error> {
    let mut erased = u32::MAX;
    transfer(stream, capacity, offset, length, |word| {
        erased &= word;
        Ok(())
    })?;
    Ok(erased == u32::MAX)
}

/// Read complete words freshly; abort on a stall or inconsistent final progress.
#[inline(always)]
fn transfer(
    stream: &mut impl Stream,
    capacity: usize,
    offset: u32,
    length: usize,
    mut consume: impl FnMut(u32) -> Result<(), Error>,
) -> Result<(), Error> {
    if !offset.is_multiple_of(4)
        || !length.is_multiple_of(WORD_BYTES)
        || length / WORD_BYTES > MAX_WORDS
    {
        return Err(Error::Unaligned);
    }
    let end = usize::try_from(offset)
        .map_err(|_| Error::OutOfBounds)?
        .checked_add(length)
        .filter(|end| *end <= capacity)
        .ok_or(Error::OutOfBounds)?;
    let end = u32::try_from(end).map_err(|_| Error::OutOfBounds)?;
    if length == 0 {
        return Ok(());
    }
    stream.stop();
    let active = Active(stream);
    for _ in 0..FIFO_WORDS {
        if !active.0.readable()? {
            break;
        }
        active.0.read_word();
    }
    if active.0.readable()? {
        return Err(Error::Transfer);
    }
    active.0.start(
        offset,
        u32::try_from(length / WORD_BYTES).map_err(|_| Error::OutOfBounds)?,
    );
    for _ in 0..length / WORD_BYTES {
        loop {
            if active.0.readable()? {
                break;
            }
            if active.0.expired() {
                return Err(Error::Transfer);
            }
        }
        consume(active.0.read_word())?;
    }
    if active.0.remaining() != 0 || active.0.address() != end || active.0.readable()? {
        return Err(Error::Transfer);
    }
    Ok(())
}

#[cfg(test)]
#[path = "flash_stream_tests.rs"]
mod tests;
