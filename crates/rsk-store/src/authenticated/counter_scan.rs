// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

pub(super) fn counter_index(fid: u16) -> Result<usize> {
    rsk_fs::counter::COUNTER_FIDS
        .iter()
        .position(|counter| counter.get() == fid)
        .ok_or(Error::MemoryFatal)
}

pub(super) fn padded_length(entry: Entry) -> Result<usize> {
    let length = entry.length().unwrap_or(0);
    if length > rsk_fs::MAX_VALUE_BYTES {
        return Err(Error::MemoryFatal);
    }
    Ok(length.div_ceil(VALUE_ALIGNMENT) * VALUE_ALIGNMENT)
}

fn read_payload<'a, F: NorFlash + MultiwriteNorFlash>(
    reader: &mut RawBank<F>,
    entry: Entry,
    offset: u32,
    buffer: &'a mut [u8; VALUE_BUFFER],
) -> Result<Option<(usize, &'a [u8])>> {
    let padded = padded_length(entry)?;
    let length = entry.length().unwrap_or(0);
    let bytes = buffer.get_mut(..padded).ok_or(Error::MemoryFatal)?;
    reader.read(offset, bytes)?;
    if !bytes
        .get(length..)
        .ok_or(Error::MemoryFatal)?
        .iter()
        .all(|&byte| byte == 0xFF)
    {
        return Ok(None);
    }
    Ok(Some((
        padded,
        bytes.get(..length).ok_or(Error::MemoryFatal)?,
    )))
}

pub(super) fn read_entry_value<F: NorFlash + MultiwriteNorFlash>(
    reader: &mut RawBank<F>,
    entry: Entry,
    offset: u32,
    checkpoint: Checkpoint,
    key: &[u8; 32],
    buffer: &mut [u8; VALUE_BUFFER],
) -> Result<Option<usize>> {
    let Some((padded, value)) = read_payload(reader, entry, offset, buffer)? else {
        return Ok(None);
    };
    if entry.verify(checkpoint.identity, key, value).is_err() {
        return Ok(None);
    }
    Ok(Some(padded))
}

fn read_scan_value<F: NorFlash + MultiwriteNorFlash>(
    reader: &mut RawBank<F>,
    entry: Entry,
    offset: u32,
    checkpoint: Checkpoint,
    buffer: &mut [u8; VALUE_BUFFER],
    mac: &rsk_crypto::mac::HmacSha256,
    fingerprint: &mut Sha256State,
) -> Result<Option<usize>> {
    let Some((padded, value)) = read_payload(reader, entry, offset, buffer)? else {
        return Ok(None);
    };
    if entry
        .verify_with_mac(checkpoint.identity, mac, value)
        .is_err()
    {
        return Ok(None);
    }
    fingerprint.update(buffer.get(..padded).ok_or(Error::MemoryFatal)?);
    Ok(Some(padded))
}

pub(super) fn scan<F: NorFlash + MultiwriteNorFlash>(
    reader: &mut RawBank<F>,
    key: &[u8; 32],
    directory: &mut Directory<MAX_COUNTER_ENTRIES>,
) -> Result<CounterScan> {
    reader.append_proof = None;
    directory.clear();
    let mut header = [0; CHECKPOINT_BYTES];
    reader.read(0, &mut header)?;
    let mut fingerprint = Sha256State::new();
    fingerprint.update(RAW_DOMAIN);
    fingerprint.update(&reader.capacity().to_le_bytes());
    fingerprint.update(&header);
    let mut scan = CounterScan {
        status: JournalStatus::Dirty,
        checkpoint: None,
        sequence: None,
        lower_bound: None,
        next: 0,
        locations: [None; MAX_COUNTER_ENTRIES],
        fingerprint: None,
    };
    if header.iter().all(|&byte| byte == 0xFF) {
        if reader.read_erased(0)? {
            scan.status = JournalStatus::Empty;
        }
        return Ok(scan);
    }
    let Ok(checkpoint) = Checkpoint::verify(&header, key) else {
        return Ok(scan);
    };
    if checkpoint.identity.partition != Partition::Counter {
        return Ok(scan);
    }
    scan.checkpoint = Some(checkpoint);
    scan.lower_bound = Some(checkpoint.sequence);
    let mut scratch = Secret::<[u8; VALUE_BUFFER]>::zeroed();
    let mac = rsk_crypto::mac::HmacSha256::new(key);
    let mut at = u32::try_from(CHECKPOINT_BYTES).map_err(|_| Error::MemoryFatal)?;
    for _ in 0..checkpoint.entries {
        let mut encoded = [0; ENTRY_BYTES];
        reader.read(at, &mut encoded)?;
        fingerprint.update(&encoded);
        let Ok(entry) = Entry::decode(&encoded) else {
            return Ok(scan);
        };
        let Ok(index) = counter_index(entry.fid()) else {
            return Ok(scan);
        };
        if entry.length().is_none() || directory.push_snapshot(entry, checkpoint.sequence).is_err()
        {
            return Ok(scan);
        }
        let value_at = at
            .checked_add(u32::try_from(ENTRY_BYTES).map_err(|_| Error::MemoryFatal)?)
            .ok_or(Error::MemoryFatal)?;
        let Some(padded) = read_scan_value(
            reader,
            entry,
            value_at,
            checkpoint,
            scratch.expose_mut(),
            &mac,
            &mut fingerprint,
        )?
        else {
            return Ok(scan);
        };
        *scan.locations.get_mut(index).ok_or(Error::MemoryFatal)? = Some(CounterLocation {
            entry,
            value_offset: value_at,
        });
        at = value_at
            .checked_add(u32::try_from(padded).map_err(|_| Error::MemoryFatal)?)
            .ok_or(Error::MemoryFatal)?;
    }
    if !ct_eq(
        &directory.digest(checkpoint.identity, key, checkpoint.sequence)?,
        &checkpoint.digest,
    ) {
        return Ok(scan);
    }
    scan.sequence = Some(checkpoint.sequence);
    scan.next = at;
    while at < reader.capacity() {
        if reader.capacity() - at < u32::try_from(ENTRY_BYTES).map_err(|_| Error::MemoryFatal)? {
            return finish_scan(reader, key, fingerprint, scan, at);
        }
        let mut encoded = [0; ENTRY_BYTES];
        reader.read(at, &mut encoded)?;
        if encoded.iter().all(|&byte| byte == 0xFF) {
            return finish_scan(reader, key, fingerprint, scan, at);
        }
        fingerprint.update(&encoded);
        let Ok(entry) = Entry::decode(&encoded) else {
            return Ok(scan);
        };
        let Ok(index) = counter_index(entry.fid()) else {
            return Ok(scan);
        };
        let sequence = scan
            .sequence
            .ok_or(Error::MemoryFatal)?
            .checked_add(1)
            .ok_or(Error::MemoryFatal)?;
        if entry.generation() != sequence {
            return Ok(scan);
        }
        let value_at = at
            .checked_add(u32::try_from(ENTRY_BYTES).map_err(|_| Error::MemoryFatal)?)
            .ok_or(Error::MemoryFatal)?;
        let Some(padded) = read_scan_value(
            reader,
            entry,
            value_at,
            checkpoint,
            scratch.expose_mut(),
            &mac,
            &mut fingerprint,
        )?
        else {
            return Ok(scan);
        };
        if directory.apply(entry).is_err() {
            return Ok(scan);
        }
        *scan.locations.get_mut(index).ok_or(Error::MemoryFatal)? =
            entry.length().map(|_| CounterLocation {
                entry,
                value_offset: value_at,
            });
        at = value_at
            .checked_add(u32::try_from(padded).map_err(|_| Error::MemoryFatal)?)
            .ok_or(Error::MemoryFatal)?;
        scan.sequence = Some(sequence);
        scan.lower_bound = Some(sequence);
        scan.next = at;
    }
    scratch.wipe();
    finish_scan(reader, key, fingerprint, scan, at)
}

fn finish_scan<F: NorFlash + MultiwriteNorFlash>(
    reader: &mut RawBank<F>,
    key: &[u8; 32],
    fingerprint: Sha256State,
    mut scan: CounterScan,
    at: u32,
) -> Result<CounterScan> {
    if !reader.read_erased(at)? {
        return Ok(scan);
    }
    scan.fingerprint = Some(reader.remember_prefix(fingerprint, at, key));
    scan.status = JournalStatus::Complete;
    Ok(scan)
}
