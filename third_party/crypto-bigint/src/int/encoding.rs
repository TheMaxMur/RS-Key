//! Const-friendly decoding/encoding operations for [`Int`].

use crate::{EncodedUint, Encoding, Int, Uint};

impl<const LIMBS: usize> Int<LIMBS> {
    /// Create a new [`Int`] from the provided big endian hex string.
    ///
    /// See [`Uint::from_be_hex`] for more details.
    ///
    /// # Panics
    /// - if the hex is malformed or not zero-padded accordingly for the size.
    #[must_use]
    pub const fn from_be_hex(hex: &str) -> Self {
        Self(Uint::from_be_hex(hex))
    }
}

impl<const LIMBS: usize> Encoding for Int<LIMBS> {
    type Repr = EncodedUint<LIMBS>;

    #[inline]
    fn from_be_bytes(bytes: Self::Repr) -> Self {
        Self(Uint::from_be_bytes(bytes))
    }

    #[inline]
    fn from_le_bytes(bytes: Self::Repr) -> Self {
        Self(Uint::from_le_bytes(bytes))
    }

    #[inline]
    fn to_be_bytes(&self) -> Self::Repr {
        self.0.to_be_bytes()
    }

    #[inline]
    fn to_le_bytes(&self) -> Self::Repr {
        self.0.to_le_bytes()
    }
}
