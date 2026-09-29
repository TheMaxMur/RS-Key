// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Verification-only projection of `RSKeyTransport`'s variables onto the real
//! `Reassembler`, excluded from production builds.
//!
//! The model's four variables are the reassembler's own scalars — which channel
//! owns the transaction, the seq byte the next continuation must carry, how much
//! is assembled and how much was declared. What the model counts in CHUNKS the
//! code counts in BYTES, and that is the whole abstraction: `Cap` chunks is
//! `INIT_DATA + Cap * CONT_DATA` bytes here. [`PROBE_CHUNKS`] is that relation as
//! an obligation the compiler discharges rather than the sentence you just read.

use super::{CONT_DATA, CTAP_MAX_MESSAGE, HID_RPT_SIZE, INIT_DATA, Reassembler};

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
    /// The model's state, read from the real fields
    /// (`crates/rsk-usb/src/ctaphid.rs:359-367`).
    pub fn tx_view(&self) -> TxView {
        TxView {
            owner: if self.in_tx { Some(self.cid) } else { None },
            seq: self.seq,
            got: self.cur,
            need: self.bcnt,
        }
    }

    /// A reassembler mid-transaction, as a harness poses one — the pre-state
    /// `crates/rsk-usb/src/ctaphid.rs:441-519` decides a frame against. The
    /// buffer stays concrete: none of the three properties reads a payload byte,
    /// and a symbolic 7609-byte array gives CBMC unrelated state to unwind.
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
    /// second owner for one channel, and `IsClone` below is what holds that.
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
    /// length never passes the declared one, and neither passes the buffer. The
    /// state the copy at `crates/rsk-usb/src/ctaphid.rs:502-508` indexes through.
    pub fn within_the_buffer(&self) -> bool {
        self.cur <= self.bcnt && self.bcnt <= CTAP_MAX_MESSAGE && self.cur <= self.msg.len()
    }
}

/// The buffer in CONTINUATION frames — the model's `Cap`. Written out rather
/// than divided out of [`PROBE_MAX`], so a width that moves on one side and not
/// the other stops the build instead of quietly posing a different space.
#[cfg(kani)]
pub const PROBE_CHUNKS: usize = 2;
#[cfg(not(kani))]
pub const PROBE_CHUNKS: usize = 128;

/// The largest declared length a posed pre-state carries — the whole buffer,
/// which under `cfg(kani)` is an INIT plus two continuations. `formal/Transport
/// .cfg` runs `Cap = 3` and `formal/scopes.txt` records 2 as the FLOOR, so the
/// harnesses pose the floor — one chunk UNDER the configuration TLC walks.
/// Rust can read neither file: `scripts/transport_bridge_gate.py` is what holds
/// those two numbers to these, and it is a `check.sh` row.
pub const PROBE_MAX: usize = CTAP_MAX_MESSAGE;

/// The chunk-to-byte bridge `RSKeyTransport` is read through, as an obligation
/// the compiler discharges rather than the sentence at the top of this file.
const _: () = assert!(PROBE_MAX == INIT_DATA + PROBE_CHUNKS * CONT_DATA);
/// `Cap >= 2` is the module's own precondition: at one chunk a continuation has
/// no second transaction to be spliced into, and all three mutants go green.
const _: () = assert!(PROBE_CHUNKS >= 2);
/// And the ceiling must be expressible in the INIT frame's 16-bit `bcnt`, or the
/// refusal is one no host can provoke and `SEC-TRANS-003`'s INIT arm is
/// discharged by an unreachable branch. Held at the SHIPPED width under `test`.
const _: () = assert!(CTAP_MAX_MESSAGE <= u16::MAX as usize);

/// Whether `T` is `Clone`, which stable Rust has no `T: !Clone` bound to ask.
/// Resolution order answers instead: an inherent associated const wins over a
/// trait one, and the inherent block below applies only when `T: Clone`.
struct IsClone<T>(core::marker::PhantomData<T>);

impl<T: Clone> IsClone<T> {
    const YES: bool = true;
}

/// The answer for every other `T`, reached only where the inherent one is not.
trait NotClone {
    const YES: bool = false;
}

impl<T> NotClone for IsClone<T> {}

/// The probe still reads a `Clone` type as one, so the `false` below is an
/// answer and not a constant: if resolution ever stops reaching the inherent
/// `YES`, every `!IsClone` assertion goes vacuously green and this one red.
const _: () = assert!(IsClone::<TxView>::YES, "IsClone stopped detecting Clone");
/// And `Reassembler` is not `Clone`: one channel, one owner. A duplicate is a
/// second owner mid-transaction, which is the state `NoCrossChannelSplice` is
/// stated over — `clone_for_probe` is how a harness forks one instead.
const _: () = assert!(!IsClone::<Reassembler>::YES, "Reassembler became Clone");

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
