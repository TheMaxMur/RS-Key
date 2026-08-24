// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Verification-only projection of `RSKeyTransport`'s variables onto the real
//! `Reassembler`, excluded from production builds.
//!
//! The model's four variables are the reassembler's own scalars — which channel
//! owns the transaction, the seq byte the next continuation must carry, how much
//! is assembled and how much was declared. What the model counts in CHUNKS the
//! code counts in BYTES, and that is the whole abstraction: `Cap` chunks is
//! `INIT_DATA + Cap * CONT_DATA` bytes here.

use super::{CTAP_MAX_MESSAGE, HID_RPT_SIZE, Reassembler};

/// `RSKeyTransport`'s state, read from the real fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxView {
    /// `owner`: the channel whose transaction is in progress, or none.
    pub owner: Option<u32>,
    /// `seq`: what the next continuation must carry.
    pub seq: u8,
    /// `got`, in bytes rather than chunks.
    pub got: usize,
    /// `need`, in bytes rather than chunks.
    pub need: usize,
}

impl Reassembler {
    /// The model's state, read from the real fields.
    pub fn tx_view(&self) -> TxView {
        TxView {
            owner: if self.in_tx { Some(self.cid) } else { None },
            seq: self.seq,
            got: self.cur,
            need: self.bcnt,
        }
    }

    /// A reassembler mid-transaction, as a harness poses one. The buffer stays
    /// concrete: none of the three properties reads a payload byte, and a
    /// symbolic 7609-byte array would only give CBMC unrelated state to unwind.
    pub fn mid_transaction(cid: u32, seq: u8, cur: usize, bcnt: usize) -> Self {
        let mut r = Self::new();
        r.cid = cid;
        r.seq = seq;
        r.cur = cur;
        r.bcnt = bcnt;
        r.in_tx = true;
        r
    }

    /// A copy of the state a probe can fork, so one pre-state can be driven by
    /// several frames without rebuilding it. Verification-only: `Reassembler` is
    /// deliberately not `Clone` in production — a duplicated transaction is a
    /// second owner for one channel.
    pub fn clone_for_probe(&self) -> Self {
        Self {
            msg: self.msg,
            cid: self.cid,
            cmd: self.cmd,
            bcnt: self.bcnt,
            cur: self.cur,
            seq: self.seq,
            in_tx: self.in_tx,
        }
    }

    /// `NoBufferOverrun` as a state predicate over the real fields: the assembled
    /// length never passes the declared one, and neither passes the buffer.
    pub fn within_the_buffer(&self) -> bool {
        self.cur <= self.bcnt && self.bcnt <= CTAP_MAX_MESSAGE && self.cur <= self.msg.len()
    }
}

/// The largest declared length a posed pre-state carries — the whole buffer,
/// which under `cfg(kani)` is an INIT plus two continuations. `Cap` is 2 in
/// `Transport.cfg`, recorded in `formal/scopes.txt` as the measured minimum, so
/// the posed space is at the model's own bound rather than below it.
pub const PROBE_MAX: usize = CTAP_MAX_MESSAGE;

/// An INIT frame for `cid` declaring `bcnt` bytes.
pub fn init_frame(cid: u32, cmd: u8, bcnt: u16) -> [u8; HID_RPT_SIZE] {
    let mut f = [0u8; HID_RPT_SIZE];
    f[..4].copy_from_slice(&cid.to_le_bytes());
    f[4] = cmd;
    f[5] = (bcnt >> 8) as u8;
    f[6] = bcnt as u8;
    f
}

/// A continuation frame for `cid` carrying sequence byte `seq`.
pub fn cont_frame(cid: u32, seq: u8) -> [u8; HID_RPT_SIZE] {
    let mut f = [0u8; HID_RPT_SIZE];
    f[..4].copy_from_slice(&cid.to_le_bytes());
    f[4] = seq & 0x7F;
    f
}
