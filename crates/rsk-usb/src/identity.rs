// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Public boot identity copied by Secure; contains no authorization or secrets.

#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::cast_possible_truncation
    )
)]

const HEADER: usize = 11;
pub const STRING_BYTES: usize = 64;
pub const SERIAL_BYTES: usize = 32;
pub const SIZE: usize = HEADER + 2 * STRING_BYTES + SERIAL_BYTES;

pub struct Identity {
    bytes: [u8; SIZE],
}
impl Identity {
    #[expect(
        clippy::too_many_arguments,
        reason = "the boot record carries five scalar fields and three descriptor strings"
    )]
    pub fn new(
        vid: u16,
        pid: u16,
        release: u16,
        interfaces: u8,
        yubico_atr: bool,
        manufacturer: &str,
        product: &str,
        serial: &str,
    ) -> Option<Self> {
        let mut bytes = [0; SIZE];
        bytes.get_mut(0..2)?.copy_from_slice(&vid.to_le_bytes());
        bytes.get_mut(2..4)?.copy_from_slice(&pid.to_le_bytes());
        bytes.get_mut(4..6)?.copy_from_slice(&release.to_le_bytes());
        *bytes.get_mut(6)? = interfaces;
        *bytes.get_mut(7)? = u8::from(yubico_atr);
        for (index, offset, capacity, value) in [
            (8, HEADER, STRING_BYTES, manufacturer),
            (9, HEADER + STRING_BYTES, STRING_BYTES, product),
            (10, HEADER + 2 * STRING_BYTES, SERIAL_BYTES, serial),
        ] {
            if value.len() > capacity {
                return None;
            }
            *bytes.get_mut(index)? = u8::try_from(value.len()).ok()?;
            bytes
                .get_mut(offset..offset + value.len())?
                .copy_from_slice(value.as_bytes());
        }
        Some(Self { bytes })
    }
    pub fn from_bytes(bytes: [u8; SIZE]) -> Option<Self> {
        let identity = Self { bytes };
        identity.manufacturer()?;
        identity.product()?;
        identity.serial()?;
        Some(identity)
    }
    pub fn bytes(&self) -> &[u8; SIZE] {
        &self.bytes
    }
    fn word(&self, offset: usize) -> Option<u16> {
        let bytes = self.bytes.get(offset..offset + 2)?;
        Some(u16::from_le_bytes(bytes.try_into().ok()?))
    }
    pub fn vid(&self) -> Option<u16> {
        self.word(0)
    }
    pub fn pid(&self) -> Option<u16> {
        self.word(2)
    }
    pub fn release(&self) -> Option<u16> {
        self.word(4)
    }
    pub fn interfaces(&self) -> u8 {
        self.bytes.get(6).copied().unwrap_or(0)
    }
    pub fn yubico_atr(&self) -> bool {
        self.bytes.get(7) == Some(&1)
    }
    fn string(&self, index: usize, offset: usize, capacity: usize) -> Option<&str> {
        let length = usize::from(*self.bytes.get(index)?);
        if length > capacity {
            return None;
        }
        core::str::from_utf8(self.bytes.get(offset..offset + length)?).ok()
    }
    pub fn manufacturer(&self) -> Option<&str> {
        self.string(8, HEADER, STRING_BYTES)
    }
    pub fn product(&self) -> Option<&str> {
        self.string(9, HEADER + STRING_BYTES, STRING_BYTES)
    }
    pub fn serial(&self) -> Option<&str> {
        self.string(10, HEADER + 2 * STRING_BYTES, SERIAL_BYTES)
    }
}
#[cfg(test)]
#[path = "identity_tests.rs"]
mod tests;
