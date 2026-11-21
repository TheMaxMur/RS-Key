// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The probe's own framing, pinned: the harnesses read `bcnt` back out of the
//! frames `init_frame` builds, so a frame builder that loses a length lane poses
//! a different pre-state than the sentence on the test says.

use super::init_frame;
use crate::ctaphid::{CTAPHID_PING, Outcome, Reassembler};

/// `bcnt` is big-endian in the INIT frame (`bcnt_hi` then `bcnt_lo`), so a
/// declaration above one byte uses both lanes. With the high lane shifted the
/// wrong way it is always zero and a 300-byte declaration reads as 44 — which
/// `Reassembler::feed` then completes from the INIT frame alone, posing a
/// transaction that is not open.
#[test]
fn a_declared_length_above_one_byte_uses_both_bcnt_lanes() {
    const CID: u32 = 0x1122_3344;
    let frame = init_frame(CID, CTAPHID_PING, 300);
    assert_eq!(frame[5], 1, "bcnt_hi");
    assert_eq!(frame[6], 44, "bcnt_lo");

    let mut asm = Reassembler::new();
    assert_eq!(
        asm.feed(&frame),
        Outcome::None,
        "the 300-byte declaration was read as complete"
    );
    assert!(asm.in_progress());
    assert_eq!(asm.current_cid(), CID);
}
