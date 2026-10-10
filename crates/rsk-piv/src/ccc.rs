// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Default CCC (Card Capability Container, PIV object `5FC107`) — a **mandatory**
//! PIV object (SP 800-73-4 pt1 §3.1.1) this card previously held only if a host
//! had written one. Serving a default mirrors the CHUID path, so the object a
//! Windows key-container open reads is present on a freshly flashed card. Shape
//! is Table 8 in table order: mandatory elements only, `F0`/`F1`/`F2`
//! zero-length (§3.1.1 allows it and defines no PIV values for them), `F5`
//! carrying the data model number `0x10` (Appendix A), unused optional elements
//! absent. A host `PUT DATA` still overrides it — `get_data` reads flash first.

/// The nine wire bytes; see the module docs for each element's Table 8 origin.
pub(crate) const CCC: [u8; 9] = [0xF0, 0x00, 0xF1, 0x00, 0xF2, 0x00, 0xF5, 0x01, 0x10];

#[cfg(test)]
#[path = "ccc_tests.rs"]
mod tests;
