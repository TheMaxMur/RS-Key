// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::authenticated::bank::IO_CHUNK;

// The checkpoint MAC stays unpublished until every body page has read back.
#[inline(never)]
pub(super) fn write_entries<F: NorFlash + MultiwriteNorFlash>(
    bank: &mut CounterBank<F>,
    checkpoint: Checkpoint,
    key: &[u8; 32],
    directory: &Directory<MAX_COUNTER_ENTRIES>,
    mut load: impl FnMut(Entry, &mut [u8]) -> Result<()>,
) -> Result<()> {
    let mut scratch = Secret::<[u8; VALUE_BUFFER]>::zeroed();
    let mut page = Secret::new([0xff; IO_CHUNK]);
    let mut filled = CHECKPOINT_BYTES;
    let mut at = 0;
    for entry in directory.entries() {
        let length = entry.length().ok_or(Error::MemoryFatal)?;
        let padded = CounterBank::<F>::padded_length(*entry)?;
        scratch.expose_mut().fill(0xff);
        let value = scratch
            .expose_mut()
            .get_mut(..length)
            .ok_or(Error::MemoryFatal)?;
        load(*entry, value)?;
        entry.verify(checkpoint.identity, key, value)?;
        for mut bytes in [
            entry.encode()?.as_slice(),
            scratch.expose().get(..padded).ok_or(Error::MemoryFatal)?,
        ] {
            while !bytes.is_empty() {
                let count = bytes.len().min(IO_CHUNK - filled);
                page.expose_mut()
                    .get_mut(filled..filled + count)
                    .ok_or(Error::MemoryFatal)?
                    .copy_from_slice(bytes.get(..count).ok_or(Error::MemoryFatal)?);
                bytes = bytes.get(count..).ok_or(Error::MemoryFatal)?;
                filled += count;
                if filled == IO_CHUNK {
                    bank.bank.program(at, page.expose())?;
                    at = at
                        .checked_add(u32::try_from(IO_CHUNK).map_err(|_| Error::MemoryFatal)?)
                        .ok_or(Error::MemoryFatal)?;
                    filled = 0;
                    page.expose_mut().fill(0xff);
                }
            }
        }
    }
    if filled != 0 && !directory.entries().is_empty() {
        bank.bank
            .program(at, page.expose().get(..filled).ok_or(Error::MemoryFatal)?)?;
    }
    Ok(())
}
