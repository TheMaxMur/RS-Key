// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Hand-encoded seed literals mirroring the `rs-key-fs-ops-*` records that
//! `fs_ops_sequences()` in `scripts/external_corpus.py` generates. They are
//! re-encoded here from that generator's source, not imported from Python, so the
//! Miri replay builds the same non-empty state the corpus does before exercising
//! the read-clamp, delete, `META_MAX` NoMemory and reboot paths.
//!
//! The opcode byte is `(fid_index << 3) | verb` (`fuzz_targets/fs_ops.rs`);
//! `verb` is 0=put, 1=read, 2=delete, 3=meta_add, 4=meta_find, 5=meta_delete,
//! 6=reboot and 7=query. put / read / meta_add each consume one extra byte.

/// Put 40 bytes, then read through views shorter than, equal to and longer than
/// the file — the copy clamps to the view while the returned length does not.
const PUT_READ_CLAMP: &[u8] = &[
    0x00, 40, 0x01, 0, 0x01, 16, 0x01, 39, 0x01, 40, 0x01, 255, 0x07,
];

/// Two puts, a read, a delete and the read-after-delete, then a second fid put
/// and deleted.
const PUT_DELETE: &[u8] = &[
    0x00, 10, 0x00, 200, 0x01, 255, 0x02, 0x01, 8, 0x07, 0x08, 1, 0x0A,
];

/// `meta_add` replace, `meta_find`, `meta_delete` and `meta_find` on the same fid.
const META_ADD_REPLACE_FIND_DELETE: &[u8] = &[0x03, 8, 0x03, 20, 0x04, 0x05, 0x04, 0x07];

/// Four 255-byte meta values: the first three fit `META_MAX`, the fourth must
/// answer NoMemory and leave the store untouched; a delete then makes room for a
/// 250-byte value.
const META_NOMEMORY_BOUNDARY: &[u8] = &[
    0x03, 255, 0x0B, 255, 0x13, 255, 0x1B, 255, 0x1C, 0x14, 0x15, 0x1B, 250, 0x1C, 0x07,
];

/// Put and `meta_add`, reboot (`into_storage`→`scan`), then read both back.
const REBOOT_READ: &[u8] = &[0x00, 50, 0x03, 6, 6, 0x01, 64, 0x04, 0x07];

/// `meta_add` then `meta_delete`, reboot, query: the empty metadata side-store
/// must not leave `EF_META` behind.
const REBOOT_CLEARS_META: &[u8] = &[0x03, 4, 0x05, 6, 0x07, 0x04];

/// Every seed, in the order `fs_ops_sequences()` yields them.
pub(crate) const SEEDS: [&[u8]; 6] = [
    PUT_READ_CLAMP,
    PUT_DELETE,
    META_ADD_REPLACE_FIND_DELETE,
    META_NOMEMORY_BOUNDARY,
    REBOOT_READ,
    REBOOT_CLEARS_META,
];
