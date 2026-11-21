// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
#[allow(
    clippy::unwrap_used,
    reason = "a test's fixture is its own bound, and a panic is its failure report"
)]
fn certificate_slot_labels_use_uppercase_hex_without_a_leading_zero() {
    for (slot, suffix) in [
        (0, "0"),
        (0x0f, "F"),
        (0x10, "10"),
        (SLOT_ATTESTATION, "F9"),
    ] {
        for (attestation, kind) in [(false, "Slot"), (true, "Attestation")] {
            let (bytes, n) = slot_label(attestation, slot);
            assert_eq!(
                core::str::from_utf8(bytes.get(..n).unwrap()).unwrap(),
                alloc::format!("RS-Key PIV {kind} {suffix}")
            );
        }
    }
}
