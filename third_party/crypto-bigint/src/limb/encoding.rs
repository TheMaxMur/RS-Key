//! Limb encoding

use super::{Limb, Word};
use crate::{Encoding, bitlen};

impl Limb {
    /// Decode from big endian bytes.
    #[inline]
    #[must_use]
    pub const fn from_be_bytes(bytes: [u8; Self::BYTES]) -> Self {
        Limb(Word::from_be_bytes(bytes))
    }

    /// Decode from little endian bytes.
    #[inline]
    #[must_use]
    pub const fn from_le_bytes(bytes: [u8; Self::BYTES]) -> Self {
        Limb(Word::from_le_bytes(bytes))
    }

    /// Decode limb from a big endian byte slice, which may be shorter than [`Limb::BYTES`].
    ///
    /// # Panics
    /// If the slice larger than [`Limb::BYTES`].
    #[must_use]
    #[track_caller]
    pub const fn from_be_slice(bytes: &[u8]) -> Self {
        let offset = Self::BYTES
            .checked_sub(bytes.len())
            .expect("The given slice is larger than Limb::BYTES");

        let mut repr = [0u8; Self::BYTES];
        let mut i = 0;
        while i < bytes.len() {
            repr[offset + i] = bytes[i];
            i += 1;
        }
        Self::from_be_bytes(repr)
    }

    /// Decode limb from a little endian byte slice, which may be shorter than [`Limb::BYTES`].
    ///
    /// # Panics
    /// If the slice larger than [`Limb::BYTES`].
    #[must_use]
    #[track_caller]
    pub const fn from_le_slice(bytes: &[u8]) -> Self {
        assert!(
            bytes.len() <= Self::BYTES,
            "The given slice is larger than Limb::BYTES"
        );

        let mut repr = [0u8; Self::BYTES];
        let mut i = 0;
        while i < bytes.len() {
            repr[i] = bytes[i];
            i += 1;
        }
        Self::from_le_bytes(repr)
    }

    /// Decode limb from the provided big endian bytes, zero padding if necessary, and
    /// truncating to the least significant bytes in the event the given amount of data exceeds
    /// `bits_precision`.
    ///
    /// # Panics
    /// If `bits_precision > Self::BITS`.
    #[inline]
    #[must_use]
    #[track_caller]
    pub const fn from_be_slice_truncated(mut bytes: &[u8], bits_precision: u32) -> Self {
        assert!(bits_precision <= Self::BITS);
        let bytes_precision = bitlen::to_bytes(bits_precision);
        if bytes.len() > bytes_precision {
            bytes = bytes
                .split_at(bytes.len().saturating_sub(bytes_precision))
                .1;
        }

        let mut ret = Self::from_be_slice(bytes);
        ret.mask_to_precision(bits_precision);
        ret
    }

    /// Decode limb from the provided little endian bytes, zero padding if necessary, and
    /// truncating to the least significant bytes in the event the given amount of data exceeds
    /// `bits_precision`.
    ///
    /// # Panics
    /// If `bits_precision > Self::BITS`.
    #[inline]
    #[must_use]
    #[track_caller]
    pub const fn from_le_slice_truncated(mut bytes: &[u8], bits_precision: u32) -> Self {
        assert!(bits_precision <= Self::BITS);
        let bytes_precision = bitlen::to_bytes(bits_precision);
        if bytes.len() > bytes_precision {
            bytes = bytes.split_at(bytes_precision).0;
        }

        let mut ret = Self::from_le_slice(bytes);
        ret.mask_to_precision(bits_precision);
        ret
    }

    /// Encode as big endian bytes.
    #[inline]
    #[must_use]
    pub const fn to_be_bytes(&self) -> [u8; Self::BYTES] {
        self.0.to_be_bytes()
    }

    /// Encode as little endian bytes.
    #[inline]
    #[must_use]
    pub const fn to_le_bytes(&self) -> [u8; Self::BYTES] {
        self.0.to_le_bytes()
    }

    /// Mask to the given number of bits precision.
    #[inline(always)]
    pub(crate) const fn mask_to_precision(&mut self, bits_precision: u32) {
        debug_assert!(bits_precision <= Self::BITS);
        self.0 &= Word::MAX >> (Limb::BITS.saturating_sub(bits_precision));
    }
}

impl Encoding for Limb {
    type Repr = [u8; Self::BYTES];

    #[inline]
    fn from_be_bytes(bytes: Self::Repr) -> Self {
        Self::from_be_bytes(bytes)
    }

    #[inline]
    fn from_le_bytes(bytes: Self::Repr) -> Self {
        Self::from_le_bytes(bytes)
    }

    #[inline]
    fn from_be_slice_truncated(bytes: &[u8], bits_precision: u32) -> Self {
        Self::from_be_slice_truncated(bytes, bits_precision)
    }

    #[inline]
    fn from_le_slice_truncated(bytes: &[u8], bits_precision: u32) -> Self {
        Self::from_le_slice_truncated(bytes, bits_precision)
    }

    #[inline]
    fn to_be_bytes(&self) -> Self::Repr {
        self.to_be_bytes()
    }

    #[inline]
    fn to_le_bytes(&self) -> Self::Repr {
        self.to_le_bytes()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    cpubits::cpubits! {
        32 => { const LIMB: Limb = Limb(0x7654_3210); }
        64 => { const LIMB: Limb = Limb(0xFEDCBA9876543210); }
    }

    #[test]
    fn from_be_slice_truncated() {
        // Enough capacity
        let limb = Limb::from_be_slice_truncated(&[1], 32);
        assert_eq!(limb, Limb::ONE);

        // Result needs masking
        let limb = Limb::from_be_slice_truncated(&[3], 1);
        assert_eq!(limb, Limb::ONE);
    }

    #[test]
    #[should_panic]
    fn from_be_slice_truncated_oversized() {
        let _ = Limb::from_be_slice_truncated(b"", 65);
    }

    #[test]
    fn from_le_slice_truncated() {
        // Enough capacity
        let limb = Limb::from_le_slice_truncated(&[1], 32);
        assert_eq!(limb, Limb::ONE);

        // Result needs masking
        let limb = Limb::from_le_slice_truncated(&[1], 1);
        assert_eq!(limb, Limb::ONE);
    }

    #[test]
    #[should_panic]
    fn from_le_slice_truncated_oversized() {
        let _ = Limb::from_le_slice_truncated(b"", 65);
    }

    #[test]
    fn roundtrip() {
        assert_eq!(LIMB, Limb::from_be_bytes(LIMB.to_be_bytes()));
        assert_eq!(LIMB, Limb::from_le_bytes(LIMB.to_le_bytes()));
    }

    #[test]
    fn reverse() {
        let mut bytes = LIMB.to_be_bytes();
        bytes.reverse();
        assert_eq!(LIMB, Limb::from_le_bytes(bytes));

        let mut bytes = LIMB.to_le_bytes();
        bytes.reverse();
        assert_eq!(LIMB, Limb::from_be_bytes(bytes));
    }
}
