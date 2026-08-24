// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `RSKeyTransport`'s three properties, checked against `Reassembler::feed` at
//! every reachable pre-state rather than at the ones a test happens to pose.
//!
//! The reassembler is already unit-tested and fuzzed, and every one of those
//! exercises a single `feed` or a random stream checked for "no panic". These are
//! about what a *pre-state* plus one frame can do: whether a stranger's frame can
//! reach the owner's buffer, whether a frame out of order can fill a gap, and
//! whether a declared length can walk the copy past the array.

use super::transport_assurance::{PROBE_MAX, cont_frame, init_frame};
use super::{CTAPHID_INIT, Outcome, Reassembler};

/// A live transaction as the model can reach one: some channel owns it, some
/// sequence byte is expected, and part of a declared message is assembled.
fn posed() -> Reassembler {
    let cid: u32 = kani::any();
    let seq: u8 = kani::any();
    let cur: usize = kani::any();
    let bcnt: usize = kani::any();
    kani::assume(cid != 0 && cid != u32::MAX);
    kani::assume(bcnt <= PROBE_MAX && cur < bcnt);
    let r = Reassembler::mid_transaction(cid, seq, cur, bcnt);
    assert!(
        r.within_the_buffer(),
        "the posed pre-state is already out of bounds"
    );
    r
}

/// `NoCrossChannelSplice`: a stranger's continuation is refused and changes
/// nothing the owner's transaction depends on.
#[kani::proof]
fn no_cross_channel_splice_from_a_continuation() {
    let mut r = posed();
    let before = r.tx_view();
    let other: u32 = kani::any();
    kani::assume(other != 0 && other != before.owner.unwrap());
    let seq: u8 = kani::any();

    let out = r.feed(&cont_frame(other, seq));

    assert!(
        matches!(out, Outcome::Error(..)),
        "a stranger's frame was accepted"
    );
    assert!(
        r.tx_view() == before,
        "a stranger's frame moved the owner's transaction"
    );
    kani::cover!(true, "the stranger arm is reachable");
}

/// `NoCrossChannelSplice`, the init-type half: a stranger's non-`CTAPHID_INIT`
/// frame mid-transaction is BUSY, and the owner's transaction survives it.
#[kani::proof]
fn no_cross_channel_splice_from_an_init_type_frame() {
    let mut r = posed();
    let before = r.tx_view();
    let other: u32 = kani::any();
    let cmd: u8 = kani::any();
    kani::assume(other != 0 && other != u32::MAX && other != before.owner.unwrap());
    kani::assume(cmd & 0x80 != 0 && cmd != CTAPHID_INIT);
    let bcnt: u16 = kani::any();

    let out = r.feed(&init_frame(other, cmd, bcnt));

    assert!(matches!(out, Outcome::Error(..)));
    assert!(
        r.tx_view() == before,
        "a stranger's init-type frame moved the owner's transaction"
    );
}

/// `NoSequenceGap`: a continuation carrying the wrong sequence byte aborts the
/// transaction instead of filling the gap. What must NOT happen is an append.
#[kani::proof]
fn no_sequence_gap_fills_a_hole() {
    let mut r = posed();
    let before = r.tx_view();
    let seq: u8 = kani::any();
    kani::assume(seq & 0x80 == 0 && seq != before.seq);

    let out = r.feed(&cont_frame(before.owner.unwrap(), seq));

    assert!(
        matches!(out, Outcome::Error(..)),
        "an out-of-order frame was accepted"
    );
    let after = r.tx_view();
    assert!(
        after.got == before.got,
        "an out-of-order frame was appended"
    );
    assert!(
        after.owner.is_none(),
        "an out-of-order frame left the transaction open"
    );
}

/// `NoBufferOverrun`: whatever one frame does, the assembled length stays inside
/// the declared one and the declared one inside the buffer — the state the copy
/// at `msg[cur..cur + n]` indexes through.
#[kani::proof]
fn no_buffer_overrun_after_any_single_frame() {
    let mut r = posed();
    let raw: [u8; 7] = kani::any();
    let mut f = [0u8; super::HID_RPT_SIZE];
    f[..7].copy_from_slice(&raw);

    let _ = r.feed(&f);

    assert!(r.within_the_buffer(), "one frame walked the buffer");
    kani::cover!(
        r.tx_view().owner.is_none(),
        "a frame that closes the transaction"
    );
    kani::cover!(r.tx_view().owner.is_some(), "a frame that leaves it open");
}

/// The declared length is refused before it is trusted, at any value a frame can
/// carry — the arm that needs no bound on the pre-state, since nothing indexes.
#[kani::proof]
fn an_over_length_init_is_refused_before_it_is_stored() {
    let mut r = Reassembler::new();
    let cid: u32 = kani::any();
    let bcnt: u16 = kani::any();
    kani::assume(cid != 0 && cid != u32::MAX);
    kani::assume(bcnt as usize > super::CTAP_MAX_MESSAGE);

    let out = r.feed(&init_frame(cid, CTAPHID_INIT, bcnt));

    assert!(
        matches!(out, Outcome::Error(..)),
        "an over-length INIT was accepted"
    );
    assert!(
        r.tx_view()
            == super::transport_assurance::TxView {
                owner: None,
                seq: 0,
                got: 0,
                need: 0,
            },
        "a refused INIT still moved the state"
    );
}
