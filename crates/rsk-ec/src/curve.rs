// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The curve vocabulary, and the one-byte tag both card applets store keys
//! under.
//!
//! [`Curve::id`] is **persisted**: it is `kdata[0]` of every sealed EC key blob
//! (`[curve_id] ‖ scalar`) the OpenPGP applet has ever written, and the same
//! byte in the PIV applet's own seal. A device provisioned by an older build
//! loads its keys through [`Curve::from_id`], so the table below is frozen —
//! `curve_id_tags_are_frozen` pins every value.

/// The supported EC curves. The one-byte id is an internal tag (stored as
/// `kdata[0]`), only ever read back by this firmware.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Curve {
    P256,
    P384,
    P521,
    K256,
    /// brainpoolP256r1 (RFC 5639).
    Bp256,
    /// brainpoolP384r1 (RFC 5639).
    Bp384,
    Ed25519,
    /// Curve25519 ECDH (the decipher key); OpenPGP "Cv25519".
    X25519,
}

impl Curve {
    /// The persisted one-byte tag (`kdata[0]`). Frozen — see the module doc.
    pub fn id(self) -> u8 {
        match self {
            Curve::P256 => 3,
            Curve::P384 => 4,
            Curve::P521 => 5,
            Curve::K256 => 12,
            Curve::Bp256 => 6,
            Curve::Bp384 => 7,
            Curve::Ed25519 => 30,
            Curve::X25519 => 31,
        }
    }

    /// The inverse of [`Curve::id`]; `None` for a tag this build has no
    /// curve for.
    pub fn from_id(b: u8) -> Option<Self> {
        Some(match b {
            3 => Curve::P256,
            4 => Curve::P384,
            5 => Curve::P521,
            12 => Curve::K256,
            6 => Curve::Bp256,
            7 => Curve::Bp384,
            30 => Curve::Ed25519,
            31 => Curve::X25519,
            _ => return None,
        })
    }
}

#[cfg(test)]
#[path = "curve_tests.rs"]
mod tests;
