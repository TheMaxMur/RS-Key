// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! ISO-7816 APDU parsing.

// Host bytes: a panic here is a board that answers nothing until unplugged.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use crate::error::{Error, Result};

/// ISO 7816-4: Ne when Le is absent or encoded as 0 (short form).
pub const NE_SHORT_MAX: usize = 256;
/// ISO 7816-4: Ne when extended Le is encoded as 0.
pub const NE_EXT_MAX: usize = 65536;
/// ISO 7816-4 §7.6.1 GET RESPONSE, which the dispatcher serves while a tail is owed.
pub const INS_GET_RESPONSE: u8 = 0xC0;
/// ISO 7816-4 §5.4.1: b4b3 of a first-interindustry class byte carry the
/// secure-messaging indication (`01` proprietary, `10`/`11` per §6).
const CLA_SM_MASK: u8 = 0x0C;
/// ISO 7816-4 §5.4.1: b4b3 = `01`, the proprietary secure-messaging indication.
const CLA_SM_PROPRIETARY: u8 = 0x04;
/// ISO 7816-4 §5.4.1: b8 of the class byte set marks the proprietary class.
pub const CLA_PROPRIETARY: u8 = 0x80;

/// A parsed command APDU. `data` borrows the command buffer (the `Nc` bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Apdu<'a> {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    /// Length of the command data field (`Nc`).
    pub nc: usize,
    /// Expected length of the response (`Ne` / Le), already normalised
    /// (0 → 256 short, 0 → 65536 extended).
    pub ne: usize,
    pub data: &'a [u8],
    /// Whether the command used the extended length encoding. An absent `Le` leaves
    /// `ne` 0 in both encodings, and [`Self::frame_cap`] is where they differ.
    pub extended: bool,
}

impl<'a> Apdu<'a> {
    /// Parse a raw command buffer. Handles ISO-7816 cases 1–4, short and
    /// extended length.
    pub fn parse(buf: &'a [u8]) -> Result<Self> {
        // No slice patterns: Kani's codegen refuses them behind a reference, and the
        // harnesses in `apdu_kani.rs` drive this parser.
        let (Some(&[cla, ins, p1, p2]), Some(rest)) = (buf.first_chunk::<4>(), buf.get(4..)) else {
            return Err(Error::WrongLength);
        };
        let mut nc = 0usize;
        let mut ne = 0usize;
        let mut data: &[u8] = &[];
        let mut extended = false;

        if rest.is_empty() {
            // Case 1 (Ne still defaults to 256).
            ne = NE_SHORT_MAX;
        } else if rest.len() == 1
            && let Some(&le) = rest.first()
        {
            // Case 2 short.
            ne = match le {
                0 => NE_SHORT_MAX,
                n => n as usize,
            };
        } else if let (Some(&[0, hi, lo]), Some(tail)) = (rest.first_chunk::<3>(), rest.get(3..)) {
            // Extended length (leading 0 marker).
            extended = true;
            if tail.is_empty() {
                ne = match u16::from_be_bytes([hi, lo]) {
                    0 => NE_EXT_MAX,
                    n => n as usize,
                };
            } else {
                // The whole 16-bit Lc, never its low byte. A YubiKey 5.7.4 stores
                // `Lc mod 256` here and answers `9000` — 300 bytes of PUT DATA
                // become 44 — which is the one parity that loses a user's data.
                nc = u16::from_be_bytes([hi, lo]) as usize;
                let (Some(body), Some(after)) = (tail.get(..nc), tail.get(nc..)) else {
                    return Err(Error::WrongLength);
                };
                data = body;
                if after.len() == 2
                    && let Some(&le) = after.first_chunk::<2>()
                {
                    ne = match u16::from_be_bytes(le) {
                        0 => NE_EXT_MAX,
                        n => n as usize,
                    };
                }
            }
        } else if let Some((&lc, tail)) = rest.split_first() {
            // Short Lc (cases 3 and 4).
            nc = lc as usize;
            let (Some(body), Some(after)) = (tail.get(..nc), tail.get(nc..)) else {
                return Err(Error::WrongLength);
            };
            data = body;
            if after.len() == 1
                && let Some(&le) = after.first()
            {
                ne = match le {
                    0 => NE_SHORT_MAX,
                    n => n as usize,
                };
            }
        }

        Ok(Apdu {
            cla,
            ins,
            p1,
            p2,
            nc,
            ne,
            data,
            extended,
        })
    }

    /// True when this is a command-chaining segment (CLA bit 0x10 set).
    #[inline]
    pub fn is_chaining(&self) -> bool {
        self.cla & 0x10 != 0
    }

    /// True when the class byte asks for secure messaging, which this card does
    /// not implement — OpenPGP Extended Capabilities announces SM off, and PIV
    /// has no SM key. The caller answers `6E00`; see [`crate::Dispatcher`].
    #[inline]
    pub fn is_secure_messaging(&self) -> bool {
        self.cla & CLA_SM_MASK != 0
    }

    /// Whether a YubiKey 5.8.0's CCID layer hands this class on at all: `00`, `04`,
    /// `80`, `84`, or any class with the chaining bit, taken as a segment first.
    /// It answers every other class with an empty data block.
    #[inline]
    pub fn is_served_over_ccid(&self) -> bool {
        self.is_chaining() || self.cla & !(CLA_PROPRIETARY | CLA_SM_PROPRIETARY) == 0
    }

    /// Class `00` or `80`: the basic channel with no other bit set, interindustry
    /// or proprietary. A YubiKey 5.8.0 serves OATH, management and OTP under both.
    #[inline]
    pub fn is_basic_class(&self) -> bool {
        self.cla & !CLA_PROPRIETARY == 0
    }

    /// The most one response frame may carry for this command, as a YubiKey 5.8.0
    /// cuts it: its `Ne`, where a short command with no `Le` still means 256 and an
    /// extended one means no cap below the transport's buffer.
    pub fn frame_cap(&self) -> usize {
        match (self.ne, self.extended) {
            (0, false) => NE_SHORT_MAX,
            (0, true) => usize::MAX,
            (ne, _) => ne,
        }
    }
}

/// Kani proof harnesses (`cargo kani -p rsk-sdk`).
#[cfg(kani)]
#[path = "apdu_kani.rs"]
mod proofs;

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    reason = "a test's fixture is its own bound, and a panic is its failure report"
)]
#[path = "apdu_tests.rs"]
mod tests;
