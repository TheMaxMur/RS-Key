// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn ctx() -> MmioCtx<'static> {
    MmioCtx::default()
}

/// The bootrom's sweet-b path: START with BSWAP, bytes via `strb`,
/// padding to 56, the bit length as two `rev`ed words, sums `rev`ed.
fn rom_style_digest(msg: &[u8]) -> [u8; 32] {
    let mut s = Sha256::new();
    let c = &mut ctx();
    s.write(CSR, 0x1206 | CSR_BSWAP | CSR_START, 4, 0, c);
    for &b in msg {
        s.write(WDATA, b as u32, 1, 0, c);
    }
    let total = msg.len() as u64;
    s.write(WDATA, 0x80, 1, 0, c);
    let mut n = total + 1;
    while n % 64 != 56 {
        s.write(WDATA, 0, 1, 0, c);
        n += 1;
    }
    s.write(WDATA, ((total >> 29) as u32).swap_bytes(), 4, 0, c);
    s.write(WDATA, ((total << 3) as u32).swap_bytes(), 4, 0, c);
    assert_ne!(s.read(CSR, 4, c) & CSR_SUM_VLD, 0);
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&s.read(SUM0 + 4 * i as u32, 4, c).to_be_bytes());
    }
    out
}

#[test]
fn rom_byte_stream_matches_sha256() {
    use sha2::{Digest, Sha256 as Ref};
    for len in [0usize, 1, 55, 56, 63, 64, 65, 200] {
        let msg: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
        let want: [u8; 32] = Ref::digest(&msg).into();
        assert_eq!(rom_style_digest(&msg), want, "len {len}");
    }
}

#[test]
fn word_writes_with_bswap_hash_memory_order() {
    use sha2::{Digest, Sha256 as Ref};
    // 64 bytes of message as little-endian words from memory, then a
    // second, padding-only block.
    let msg: Vec<u8> = (0..64u32).map(|i| i as u8).collect();
    let mut s = Sha256::new();
    let c = &mut ctx();
    s.write(CSR, 0x1206 | CSR_START, 4, 0, c);
    for w in msg.chunks(4) {
        s.write(WDATA, u32::from_le_bytes(w.try_into().unwrap()), 4, 0, c);
    }
    s.write(WDATA, 0x80, 4, 0, c);
    for _ in 0..13 {
        s.write(WDATA, 0, 4, 0, c);
    }
    s.write(WDATA, 0, 4, 0, c);
    s.write(WDATA, (512u32).swap_bytes(), 4, 0, c);
    let want: [u8; 32] = Ref::digest(&msg).into();
    let mut got = [0u8; 32];
    for i in 0..8 {
        got[i * 4..i * 4 + 4].copy_from_slice(&s.read(SUM0 + 4 * i as u32, 4, c).to_be_bytes());
    }
    assert_eq!(got, want);
}
