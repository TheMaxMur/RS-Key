// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use core::ops::Range;

use embassy_futures::block_on;
use embedded_storage_async::nor_flash::ReadNorFlash;
use rsk_crypto::sha256_blocks::{Sha256Blocks, Sha256Compression};
use rsk_sdk::error::{Error, Result};
use rsk_secret::Secret;
use rsk_store::FlashBuf;

use super::SharedFlash;

// Embassy has no SHA peripheral token; the board's StaticCell owns this one.
pub(super) struct Engine {
    available: bool,
}

impl Engine {
    pub(super) fn new() -> Self {
        rp_pac::RESETS
            .reset()
            .modify(|value| value.set_sha256(false));
        for _ in 0..READY_POLLS {
            if rp_pac::RESETS.reset_done().read().sha256() {
                return Self { available: true };
            }
        }
        Self { available: false }
    }
}

const READY_POLLS: usize = 1024;
const CHUNK: usize = 4096;

#[inline(always)]
fn ready() -> bool {
    for _ in 0..READY_POLLS {
        let status = rp_pac::SHA256.csr().read();
        if status.err_wdata_not_rdy() {
            return false;
        }
        if status.wdata_rdy() && status.sum_vld() {
            return true;
        }
    }
    false
}

impl Sha256Compression for Engine {
    #[inline(always)]
    fn compress(&mut self, bytes: &[u8; 64]) -> bool {
        if !ready() {
            return false;
        }
        let [
            w0,
            w1,
            w2,
            w3,
            w4,
            w5,
            w6,
            w7,
            w8,
            w9,
            w10,
            w11,
            w12,
            w13,
            w14,
            w15,
        ] = bytes.as_chunks::<4>().0
        else {
            return false;
        };
        macro_rules! write_words {
            ($($word:ident),+) => { $(
                rp_pac::SHA256.wdata().write_value(u32::from_le_bytes(*$word));
            )+ };
        }
        write_words!(
            w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15
        );
        ready()
    }
}

// SAFETY: startup initializes .data.ram_func before use; the existing Secure
// linker/MPU places it in read-only executable SRAM, separate from mutable data.
#[unsafe(link_section = ".data.ram_func")]
#[inline(never)]
pub(super) fn digest(
    flash: &mut SharedFlash,
    range: Range<u32>,
    end: u32,
    prefix: &[u8],
) -> Result<[u8; 32]> {
    let owner = flash.sha256;
    let mut exclusive = owner.try_borrow_mut().map_err(|_| Error::MemoryFatal)?;
    if !exclusive.available {
        return Err(Error::MemoryFatal);
    }
    rp_pac::SHA256.csr().write(|value| {
        value.set_start(true);
        value.set_bswap(true);
        value.set_dma_size(rp_pac::sha256::vals::DmaSize::_32bit);
        value.set_err_wdata_not_rdy(true);
    });
    if !ready() {
        return Err(Error::MemoryFatal);
    }
    let mut hash = Sha256Blocks::default();
    if !hash.update(prefix, &mut *exclusive) {
        return Err(Error::MemoryFatal);
    }
    let mut scratch = Secret::new(FlashBuf::<CHUNK>::new());
    let boundary = range.start.checked_add(end).ok_or(Error::MemoryFatal)?;
    if boundary > range.end {
        return Err(Error::MemoryFatal);
    }
    let mut at = range.start;
    while at < range.end {
        // Keep mode checks and wait bounds at the existing chunk boundaries.
        if at >= boundary && at.is_multiple_of(4) && (range.end - at).is_multiple_of(4) {
            flash.quad.borrow_mut().ensure_mode();
            let _owner = flash.inner.borrow_mut();
            let count = usize::try_from(range.end - at)
                .map_err(|_| Error::MemoryFatal)?
                .min(CHUNK);
            if !super::stream::read_erased(at, count).map_err(|_| Error::MemoryFatal)? {
                return Err(Error::MemoryFatal);
            }
            at += u32::try_from(count).map_err(|_| Error::MemoryFatal)?;
            continue;
        }
        let limit = if at < boundary { boundary } else { range.end };
        let count = usize::try_from(limit - at)
            .map_err(|_| Error::MemoryFatal)?
            .min(CHUNK);
        let bytes = scratch
            .expose_mut()
            .get_mut(..count)
            .ok_or(Error::MemoryFatal)?;
        block_on(flash.read(at, bytes)).map_err(|_| Error::MemoryFatal)?;
        if at < boundary {
            if !hash.update(bytes, &mut *exclusive) {
                return Err(Error::MemoryFatal);
            }
        } else if !rsk_store::authenticated::all_erased(bytes) {
            return Err(Error::MemoryFatal);
        }
        at += u32::try_from(count).map_err(|_| Error::MemoryFatal)?;
    }
    if !hash.update(&end.to_le_bytes(), &mut *exclusive)
        || !hash.finish(&mut *exclusive)
        || !ready()
    {
        return Err(Error::MemoryFatal);
    }
    let sha = rp_pac::SHA256;
    let mut out = [0; 32];
    for (bytes, register) in out.chunks_exact_mut(4).zip([
        sha.sum0(),
        sha.sum1(),
        sha.sum2(),
        sha.sum3(),
        sha.sum4(),
        sha.sum5(),
        sha.sum6(),
        sha.sum7(),
    ]) {
        bytes.copy_from_slice(&register.read().to_be_bytes());
    }
    Ok(out)
}
