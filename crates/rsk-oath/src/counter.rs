// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use rsk_crypto::{Device, aes256gcm_encrypt};
use rsk_fs::{Fs, KeyFid, Sealed, Storage};
use rsk_sdk::error::{Error, Result};
use rsk_secret::Secret;

use crate::{OATH_TYPE_HOTP, OATH_TYPE_MASK, Rng, TAG_IMF, TAG_KEY, find_tag_range, seal};

const COUNTER_BYTES: usize = 8;
const SEALED_BYTES: usize = seal::NONCE_LEN + COUNTER_BYTES + seal::TAG_LEN;

/// A detached value is usable only through the backend's authenticated owner binding.
pub(crate) fn apply<S: Storage, const N: usize>(
    dev: &Device,
    fs: &mut Fs<S>,
    fid: KeyFid,
    plain: &mut Secret<[u8; N]>,
    length: usize,
) -> Result<()> {
    // Access-code bytes are an arbitrary HMAC key, not credential TLVs.
    if fid == crate::EF_OATH_CODE {
        return Ok(());
    }
    let blob = plain.expose().get(..length).ok_or(Error::MemoryFatal)?;
    let hotp = find_tag_range(blob, TAG_KEY)
        .and_then(|range| blob.get(range))
        .and_then(|key| key.first())
        .is_some_and(|ty| ty & OATH_TYPE_MASK == OATH_TYPE_HOTP);
    if !hotp {
        return Ok(());
    }
    let mut sealed = Secret::<[u8; SEALED_BYTES]>::zeroed();
    let Some(n) = fs.read_bound_counter(fid, sealed.expose_mut())? else {
        return Ok(());
    };
    let mut counter = Secret::<[u8; COUNTER_BYTES]>::zeroed();
    if n != SEALED_BYTES || seal::open(dev, sealed.expose(), &mut counter) != Some(COUNTER_BYTES) {
        return Err(Error::MemoryFatal);
    }
    let range = find_tag_range(blob, TAG_IMF).ok_or(Error::MemoryFatal)?;
    plain
        .expose_mut()
        .get_mut(range)
        .and_then(|v| v.first_chunk_mut::<COUNTER_BYTES>())
        .ok_or(Error::MemoryFatal)?
        .copy_from_slice(counter.expose());
    Ok(())
}

pub(crate) fn publish<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    fid: KeyFid,
    counter: &[u8; COUNTER_BYTES],
) -> Result<bool> {
    let mut nonce = [0; seal::NONCE_LEN];
    rng.fill(&mut nonce);
    let mut sealed = Secret::<[u8; SEALED_BYTES]>::zeroed();
    let (iv, rest) = sealed.expose_mut().split_at_mut(seal::NONCE_LEN);
    iv.copy_from_slice(&nonce);
    let (ciphertext, tag) = rest.split_at_mut(COUNTER_BYTES);
    ciphertext.copy_from_slice(counter);
    let key = seal::kenc(dev);
    tag.copy_from_slice(&aes256gcm_encrypt(
        key.expose(),
        &nonce,
        dev.serial_hash,
        ciphertext,
    ));
    fs.write_bound_counter(fid, Sealed::wrap(sealed.expose()))
}
