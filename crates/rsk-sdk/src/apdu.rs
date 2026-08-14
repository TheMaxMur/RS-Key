// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! ISO-7816 APDU parsing.

use crate::error::{Error, Result};

/// ISO 7816-4: Ne when Le is absent or encoded as 0 (short form).
pub const NE_SHORT_MAX: usize = 256;
/// ISO 7816-4: Ne when extended Le is encoded as 0.
pub const NE_EXT_MAX: usize = 65536;
/// ISO 7816-4 §5.4.1: b4b3 of a first-interindustry class byte carry the
/// secure-messaging indication (`01` proprietary, `10`/`11` per §6).
const CLA_SM_MASK: u8 = 0x0C;

#[inline]
fn be16(b: &[u8]) -> u16 {
    ((b[0] as u16) << 8) | b[1] as u16
}

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
}

impl<'a> Apdu<'a> {
    /// Parse a raw command buffer. Handles ISO-7816 cases 1–4, short and
    /// extended length.
    pub fn parse(buf: &'a [u8]) -> Result<Self> {
        if buf.len() < 4 {
            return Err(Error::WrongLength);
        }
        let size = buf.len();
        let (cla, ins, p1, p2) = (buf[0], buf[1], buf[2], buf[3]);
        let mut nc = 0usize;
        let mut ne = 0usize;
        let mut data: &[u8] = &[];

        if size == 4 {
            // Case 1 (Ne still defaults to 256).
            ne = NE_SHORT_MAX;
        } else if size == 5 {
            // Case 2 short.
            ne = match buf[4] {
                0 => NE_SHORT_MAX,
                n => n as usize,
            };
        } else if buf[4] == 0 && size >= 7 {
            // Extended length (leading 0 marker).
            if size == 7 {
                ne = match be16(&buf[5..7]) {
                    0 => NE_EXT_MAX,
                    n => n as usize,
                };
            } else {
                // The whole 16-bit Lc, never its low byte. A YubiKey 5.7.4 stores
                // `Lc mod 256` here and answers `9000` — 300 bytes of PUT DATA
                // become 44 — which is the one parity that loses a user's data.
                nc = be16(&buf[5..7]) as usize;
                let start = 7;
                if start + nc > size {
                    return Err(Error::WrongLength);
                }
                data = &buf[start..start + nc];
                if nc + 7 + 2 == size {
                    ne = match be16(&buf[size - 2..]) {
                        0 => NE_EXT_MAX,
                        n => n as usize,
                    };
                }
            }
        } else {
            // Short Lc (cases 3 and 4).
            nc = buf[4] as usize;
            let start = 5;
            if start + nc > size {
                return Err(Error::WrongLength);
            }
            data = &buf[start..start + nc];
            if nc + 5 + 1 == size {
                ne = match buf[size - 1] {
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
}

/// Kani proof harnesses (`cargo kani -p rsk-sdk`).
#[cfg(kani)]
#[path = "apdu_kani.rs"]
mod proofs;

#[cfg(test)]
#[path = "apdu_tests.rs"]
mod tests;
