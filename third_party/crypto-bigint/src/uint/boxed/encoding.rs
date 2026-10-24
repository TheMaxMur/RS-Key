//! Const-friendly decoding operations for [`BoxedUint`].

use super::BoxedUint;
use crate::{CtEq, CtOption, DecodeError, Encoding, Limb, Word, bitlen, uint::encoding};
use alloc::{boxed::Box, string::String, vec::Vec};

#[cfg(feature = "serde")]
mod serde;

impl BoxedUint {
    /// Create a new [`BoxedUint`] from the provided big endian bytes.
    ///
    /// The `bits_precision` argument represents the precision of the resulting integer, which is
    /// fixed as this type is not arbitrary-precision.
    ///
    /// The new [`BoxedUint`] will be created with `bits_precision` rounded up to a multiple of
    /// [`Limb::BITS`].
    ///
    /// # Errors
    /// - Returns [`DecodeError::InputSize`] if the length of `bytes` is larger than
    ///   `bits_precision` (rounded up to a multiple of 8).
    /// - Returns [`DecodeError::Precision`] if the size of the decoded integer is larger than
    ///   `bits_precision`.
    pub fn from_be_slice(bytes: &[u8], bits_precision: u32) -> Result<Self, DecodeError> {
        if bytes.len() > bitlen::to_bytes(bits_precision) {
            return Err(DecodeError::InputSize);
        }

        Ok(Self::from_be_slice_truncated(bytes, bits_precision))
    }

    /// Create a new [`BoxedUint`] from the provided big endian bytes, zero padding if necessary,
    /// and truncating to the least significant bytes in the event the given amount of data exceeds
    /// `bits_precision`.
    #[must_use]
    #[allow(clippy::missing_panics_doc, reason = "should not panic in practice")]
    pub fn from_be_slice_truncated(bytes: &[u8], bits_precision: u32) -> Self {
        let mut ret = Self::zero_with_precision(bits_precision);
        encoding::fill_limbs_from_be_slice_truncated(bytes, &mut ret.limbs, bits_precision)
            .expect("should fit in requested precision");
        ret
    }

    /// Create a new [`BoxedUint`] from the provided big endian bytes, automatically selecting its
    /// precision based on the size of the input.
    ///
    /// This method is variable-time with respect to all subsequent operations since it chooses the
    /// limb count based on the input size, and is therefore only suitable for public inputs.
    ///
    /// When working with secret values, use [`BoxedUint::from_be_slice`].
    #[must_use]
    pub fn from_be_slice_vartime(bytes: &[u8]) -> Self {
        Self::from_be_slice_truncated(bytes, bitlen::from_bytes(bytes.len()))
    }

    /// Create a new [`BoxedUint`] from the provided little endian bytes.
    ///
    /// The `bits_precision` argument represents the precision of the resulting integer, which is
    /// fixed as this type is not arbitrary-precision.
    ///
    /// The new [`BoxedUint`] will be created with `bits_precision`
    /// rounded up to a multiple of [`Limb::BITS`].
    ///
    /// # Errors
    /// - Returns [`DecodeError::InputSize`] if the length of `bytes` is larger than
    ///   `bits_precision` (rounded up to a multiple of 8).
    /// - Returns [`DecodeError::Precision`] if the size of the decoded integer is larger than
    ///   `bits_precision`.
    pub fn from_le_slice(bytes: &[u8], bits_precision: u32) -> Result<Self, DecodeError> {
        if bytes.len() > bitlen::to_bytes(bits_precision) {
            return Err(DecodeError::InputSize);
        }

        Ok(Self::from_le_slice_truncated(bytes, bits_precision))
    }

    /// Create a new [`BoxedUint`] from the provided little endian bytes, zero padding if necessary,
    /// and truncating to the least significant bytes in the event the given amount of data exceeds
    /// `bits_precision`.
    #[must_use]
    #[allow(clippy::missing_panics_doc, reason = "should not panic in practice")]
    pub fn from_le_slice_truncated(bytes: &[u8], bits_precision: u32) -> Self {
        let mut ret = Self::zero_with_precision(bits_precision);
        encoding::fill_limbs_from_le_slice_truncated(bytes, &mut ret.limbs, bits_precision)
            .expect("should fit in requested precision");
        ret
    }

    /// Create a new [`BoxedUint`] from the provided little endian bytes, automatically selecting
    /// its precision based on the size of the input.
    ///
    /// This method is variable-time with respect to all subsequent operations since it chooses the
    /// limb count based on the input size, and is therefore only suitable for public inputs.
    ///
    /// When working with secret values, use [`BoxedUint::from_le_slice`].
    #[must_use]
    pub fn from_le_slice_vartime(bytes: &[u8]) -> Self {
        Self::from_le_slice_truncated(bytes, bitlen::from_bytes(bytes.len()))
    }

    /// Serialize this [`BoxedUint`] as big-endian.
    #[inline]
    #[must_use]
    pub fn to_be_bytes(&self) -> Box<[u8]> {
        let mut out = vec![0u8; self.limbs.len() * Limb::BYTES];

        for (src, dst) in self
            .limbs
            .iter()
            .rev()
            .cloned()
            .zip(out.chunks_exact_mut(Limb::BYTES))
        {
            dst.copy_from_slice(&src.0.to_be_bytes());
        }

        out.into()
    }

    /// Serialize this [`BoxedUint`] as big-endian without leading zeroes.
    #[inline]
    #[must_use]
    #[allow(clippy::integer_division_remainder_used, reason = "vartime")]
    pub fn to_be_bytes_trimmed_vartime(&self) -> Box<[u8]> {
        let zeroes = self.leading_zeros() as usize / 8;
        (&self.to_be_bytes()[zeroes..]).into()
    }

    /// Serialize this [`BoxedUint`] as little-endian.
    #[inline]
    #[must_use]
    pub fn to_le_bytes(&self) -> Box<[u8]> {
        let mut out = vec![0u8; self.limbs.len() * Limb::BYTES];

        for (src, dst) in self
            .limbs
            .iter()
            .cloned()
            .zip(out.chunks_exact_mut(Limb::BYTES))
        {
            dst.copy_from_slice(&src.0.to_le_bytes());
        }

        out.into()
    }

    /// Serialize this [`BoxedUint`] as little-endian without trailing zeroes.
    #[inline]
    #[must_use]
    #[allow(clippy::integer_division_remainder_used, reason = "vartime")]
    pub fn to_le_bytes_trimmed_vartime(&self) -> Box<[u8]> {
        let zeroes = self.leading_zeros() as usize / 8;
        let bytes = self.to_le_bytes();
        (&bytes[..bytes.len() - zeroes]).into()
    }

    /// Create a new [`BoxedUint`] from the provided big endian hex string.
    ///
    /// # Panics
    /// - if hex string is not the expected size
    #[must_use]
    pub fn from_be_hex(hex: &str, bits_precision: u32) -> CtOption<Self> {
        let nlimbs = bitlen::to_limbs(bits_precision);
        let bytes = hex.as_bytes();

        assert_eq!(
            bytes.len(),
            Limb::BYTES * nlimbs * 2,
            "hex string is not the expected size"
        );

        let mut res = vec![Limb::ZERO; nlimbs];
        let mut buf = [0u8; Limb::BYTES];
        let mut i = 0;
        let mut err = 0;

        while i < nlimbs {
            let mut j = 0;
            while j < Limb::BYTES {
                let offset = (i * Limb::BYTES + j) * 2;
                let (result, byte_err) =
                    encoding::decode_hex_byte([bytes[offset], bytes[offset + 1]]);
                err |= byte_err;
                buf[j] = result;
                j += 1;
            }
            res[nlimbs - i - 1] = Limb(Word::from_be_bytes(buf));
            i += 1;
        }

        CtOption::new(Self { limbs: res.into() }, err.ct_eq(&0))
    }

    /// Create a new [`BoxedUint`] from a big-endian string in a given base.
    ///
    /// The string may begin with a `+` character, and may use underscore
    /// characters to separate digits.
    ///
    /// # Errors
    /// - Returns [`DecodeError::InvalidDigit`] if the input value contains non-digit characters or
    ///   digits outside of the range `0..radix`.
    ///
    /// # Panics
    /// - if `radix` is not in the range from 2 to 36.
    pub fn from_str_radix_vartime(src: &str, radix: u32) -> Result<Self, DecodeError> {
        let mut dec = VecDecodeByLimb::default();
        encoding::radix_decode_str(src, radix, &mut dec)?;
        Ok(Self {
            limbs: dec.limbs.into(),
        })
    }

    /// Create a new [`BoxedUint`] from a big-endian string in a given base,
    /// with a given precision.
    ///
    /// The string may begin with a `+` character, and may use underscore
    /// characters to separate digits.
    ///
    /// The `bits_precision` argument represents the precision of the resulting integer, which is
    /// fixed as this type is not arbitrary-precision.
    ///
    /// The new [`BoxedUint`] will be created with `bits_precision` rounded up to a multiple
    /// of [`Limb::BITS`].
    ///
    /// # Errors
    /// - Returns [`DecodeError::InputSize`] if the length of `bytes` is larger than
    ///   `bits_precision` (rounded up to a multiple of 8).
    /// - Returns [`DecodeError::InvalidDigit`] if the input value contains non-digit characters or
    ///   digits are outside the range `0..radix`.
    /// - Returns [`DecodeError::Precision`] if the size of the decoded integer is larger than
    ///   `bits_precision`.
    ///
    /// # Panics
    /// - if `radix` is not in the range from 2 to 36.
    pub fn from_str_radix_with_precision_vartime(
        src: &str,
        radix: u32,
        bits_precision: u32,
    ) -> Result<Self, DecodeError> {
        let mut ret = Self::zero_with_precision(bits_precision);
        encoding::radix_decode_str(
            src,
            radix,
            &mut encoding::SliceDecodeByLimb::new(&mut ret.limbs),
        )?;
        if bits_precision < ret.bits() {
            return Err(DecodeError::Precision);
        }
        Ok(ret)
    }

    /// Format a [`BoxedUint`] as a string in a given base.
    ///
    /// # Panics
    /// - if `radix` is not in the range from 2 to 36.
    #[must_use]
    pub fn to_string_radix_vartime(&self, radix: u32) -> String {
        encoding::radix_encode_limbs_to_string(radix, &self.limbs)
    }
}

impl Encoding for BoxedUint {
    type Repr = Box<[u8]>;

    fn from_be_bytes(bytes: Self::Repr) -> Self {
        Self::from_be_slice_vartime(&bytes)
    }

    fn from_le_bytes(bytes: Self::Repr) -> Self {
        Self::from_le_slice_vartime(&bytes)
    }

    fn from_be_slice_truncated(bytes: &[u8], bits_precision: u32) -> Self {
        Self::from_be_slice_truncated(bytes, bits_precision)
    }

    fn from_le_slice_truncated(bytes: &[u8], bits_precision: u32) -> Self {
        Self::from_le_slice_truncated(bytes, bits_precision)
    }

    fn to_be_bytes(&self) -> Self::Repr {
        Self::to_be_bytes(self)
    }

    fn to_le_bytes(&self) -> Self::Repr {
        Self::to_le_bytes(self)
    }
}

/// Decoder target producing a Vec<Limb>
#[derive(Default)]
struct VecDecodeByLimb {
    limbs: Vec<Limb>,
}

impl encoding::DecodeByLimb for VecDecodeByLimb {
    #[inline]
    fn limbs_mut(&mut self) -> &mut [Limb] {
        self.limbs.as_mut_slice()
    }

    #[inline]
    fn push_limb(&mut self, limb: Limb) -> bool {
        self.limbs.push(limb);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{BoxedUint, DecodeError};
    use crate::Limb;
    use hex_literal::hex;

    cpubits::cpubits! {
        32 => {
            #[test]
            fn from_be_slice_eq() {
                let bytes = hex!("0011223344556677");
                let n = BoxedUint::from_be_slice(&bytes, 64).unwrap();
                assert_eq!(n.as_limbs(), &[Limb(0x44556677), Limb(0x00112233)]);
            }

            #[test]
            fn from_be_slice_short() {
                let bytes = hex!("0011223344556677");
                let n = BoxedUint::from_be_slice(&bytes, 128).unwrap();
                assert_eq!(
                    n.as_limbs(),
                    &[Limb(0x44556677), Limb(0x00112233), Limb::ZERO, Limb::ZERO]
                );
            }

            #[test]
            fn from_be_slice_not_word_sized() {
                let bytes = hex!("112233445566778899aabbccddeeff");
                let n = BoxedUint::from_be_slice(&bytes, 127).unwrap();
                assert_eq!(
                    n.as_limbs(),
                    &[
                        Limb(0xccddeeff),
                        Limb(0x8899aabb),
                        Limb(0x44556677),
                        Limb(0x00112233)
                    ]
                );
                assert_eq!(n.bits_precision(), 128);
            }

            #[test]
            fn from_le_slice_eq() {
                let bytes = hex!("7766554433221100");
                let n = BoxedUint::from_le_slice(&bytes, 64).unwrap();
                assert_eq!(n.as_limbs(), &[Limb(0x44556677), Limb(0x00112233)]);
            }

            #[test]
            fn from_le_slice_short() {
                let bytes = hex!("7766554433221100");
                let n = BoxedUint::from_le_slice(&bytes, 128).unwrap();
                assert_eq!(
                    n.as_limbs(),
                    &[Limb(0x44556677), Limb(0x00112233), Limb::ZERO, Limb::ZERO]
                );
            }

            #[test]
            fn from_le_slice_not_word_sized() {
                let bytes = hex!("ffeeddccbbaa998877665544332211");
                let n = BoxedUint::from_le_slice(&bytes, 127).unwrap();
                assert_eq!(
                    n.as_limbs(),
                    &[
                        Limb(0xccddeeff),
                        Limb(0x8899aabb),
                        Limb(0x44556677),
                        Limb(0x00112233)
                    ]
                );
                assert_eq!(n.bits_precision(), 128);
            }
        }
        64 => {
            #[test]
            #[should_panic]
            fn from_be_hex_short() {
                let hex = "00112233445566778899aabbccddee";
                let _ = BoxedUint::from_be_hex(hex, 128).unwrap();
            }

            #[test]
            fn from_be_slice_eq() {
                let bytes = hex!("00112233445566778899aabbccddeeff");
                let n = BoxedUint::from_be_slice(&bytes, 128).unwrap();
                assert_eq!(
                    n.as_limbs(),
                    &[Limb(0x8899aabbccddeeff), Limb(0x0011223344556677)]
                );
            }

            #[test]
            fn from_be_slice_short() {
                let bytes = hex!("00112233445566778899aabbccddeeff");
                let n = BoxedUint::from_be_slice(&bytes, 256).unwrap();
                assert_eq!(
                    n.as_limbs(),
                    &[
                        Limb(0x8899aabbccddeeff),
                        Limb(0x0011223344556677),
                        Limb::ZERO,
                        Limb::ZERO
                    ]
                );
            }

            #[test]
            fn from_be_slice_not_word_sized() {
                let bytes = hex!("112233445566778899aabbccddeeff");
                let n = BoxedUint::from_be_slice(&bytes, 127).unwrap();
                assert_eq!(
                    n.as_limbs(),
                    &[Limb(0x8899aabbccddeeff), Limb(0x0011223344556677)]
                );
                assert_eq!(n.bits_precision(), 128);
            }

            #[test]
            fn from_le_slice_eq() {
                let bytes = hex!("ffeeddccbbaa99887766554433221100");
                let n = BoxedUint::from_le_slice(&bytes, 128).unwrap();
                assert_eq!(
                    n.as_limbs(),
                    &[Limb(0x8899aabbccddeeff), Limb(0x0011223344556677)]
                );
            }

            #[test]
            fn from_le_slice_short() {
                let bytes = hex!("ffeeddccbbaa99887766554433221100");
                let n = BoxedUint::from_le_slice(&bytes, 256).unwrap();
                assert_eq!(
                    n.as_limbs(),
                    &[
                        Limb(0x8899aabbccddeeff),
                        Limb(0x0011223344556677),
                        Limb::ZERO,
                        Limb::ZERO
                    ]
                );
            }

            #[test]
            fn from_le_slice_not_word_sized() {
                let bytes = hex!("ffeeddccbbaa998877665544332211");
                let n = BoxedUint::from_le_slice(&bytes, 127).unwrap();
                assert_eq!(
                    n.as_limbs(),
                    &[Limb(0x8899aabbccddeeff), Limb(0x0011223344556677)]
                );
                assert_eq!(n.bits_precision(), 128);
            }
        }
    }

    #[test]
    fn from_be_slice_too_long() {
        let bytes = hex!("00112233445566778899aabbccddeeff");
        assert_eq!(
            BoxedUint::from_be_slice(&bytes, 64),
            Err(DecodeError::InputSize)
        );
    }

    #[test]
    fn from_be_slice_non_multiple_precision() {
        let bytes = hex!("0f112233445566778899aabbccddeeff");
        let n = BoxedUint::from_be_slice(&bytes, 121).unwrap();
        assert_eq!(n.bits(), 121);
    }

    #[test]
    fn from_be_slice_rejects_value_exceeding_precision() {
        assert_eq!(
            BoxedUint::from_be_slice(&[0x01, 0x00], 8),
            Err(DecodeError::InputSize)
        );
    }

    #[test]
    fn from_be_slice_truncated_exact_fit() {
        let bytes = [0u8; 32];
        let n = BoxedUint::from_be_slice_truncated(&bytes, 256);
        assert_eq!(&*n.to_be_bytes(), &bytes);
    }

    #[test]
    fn from_be_slice_truncated_truncates_to_lsb() {
        let n = BoxedUint::from_be_slice_truncated(&[0xDE, 0xAD, 0xBE, 0xEF], 16);
        let out = n.to_be_bytes();
        assert_eq!(&out[(out.len() - 2)..], &[0xBE, 0xEF]);
    }

    #[test]
    fn from_be_slice_truncated_zero_pads_short_input() {
        let n = BoxedUint::from_be_slice_truncated(&[0x42], 32);
        assert_eq!(n.to_be_bytes().last(), Some(&0x42));
        assert!(n.to_be_bytes().iter().rev().skip(1).all(|&b| b == 0));
    }

    #[test]
    fn from_be_slice_truncated_top_byte_masked() {
        let n = BoxedUint::from_be_slice_truncated(&[0xFF, 0xFF], 12);
        assert!(n.bits() <= 12);
    }

    #[test]
    fn from_le_slice_truncated_exact_fit() {
        let bytes = [0u8; 32];
        let n = BoxedUint::from_le_slice_truncated(&bytes, 256);
        assert_eq!(&*n.to_le_bytes(), &bytes);
    }

    #[test]
    fn from_le_slice_truncated_truncates_to_lsb() {
        let n = BoxedUint::from_le_slice_truncated(&[0xEF, 0xBE, 0xAD, 0xDE], 16);
        assert_eq!(&n.to_le_bytes()[..2], &[0xEF, 0xBE]);
    }

    #[test]
    fn from_le_slice_truncated_top_byte_masked() {
        let n = BoxedUint::from_le_slice_truncated(&[0xFF, 0xFF], 12);
        assert!(n.bits() <= 12,);
    }

    #[test]
    fn from_be_slice_vartime() {
        let bytes = hex!(
            "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111F"
        );
        let uint = BoxedUint::from_be_slice_vartime(&bytes);
        assert_eq!(&*uint.to_be_bytes_trimmed_vartime(), bytes.as_slice());
    }

    #[test]
    fn from_le_slice_too_long() {
        let bytes = hex!("ffeeddccbbaa99887766554433221100");
        assert_eq!(
            BoxedUint::from_be_slice(&bytes, 64),
            Err(DecodeError::InputSize)
        );
    }

    #[test]
    fn from_le_slice_non_multiple_precision() {
        let bytes = hex!("ffeeddccbbaa998877665544332211ff");
        let n = BoxedUint::from_le_slice(&bytes, 121).unwrap();
        assert_eq!(n.bits(), 121);
    }

    #[test]
    fn from_le_slice_vartime() {
        let bytes = hex!(
            "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111F"
        );
        let uint = BoxedUint::from_le_slice_vartime(&bytes);
        assert_eq!(&*uint.to_le_bytes_trimmed_vartime(), bytes.as_slice());
    }

    #[test]
    fn to_be_bytes() {
        let bytes = hex!("00112233445566778899aabbccddeeff");
        let n = BoxedUint::from_be_slice(&bytes, 128).unwrap();
        assert_eq!(bytes.as_slice(), &*n.to_be_bytes());
    }

    #[test]
    fn to_be_bytes_trimmed_vartime() {
        let bytes = hex!("ff112233445566778899aabbccddeeff");
        let n = BoxedUint::from_be_slice(&bytes, 128).unwrap();
        assert_eq!(&bytes, &*n.to_be_bytes_trimmed_vartime());

        let bytes = hex!("00112233445566778899aabbccddeeff");
        let n = BoxedUint::from_be_slice(&bytes, 128).unwrap();
        assert_eq!(&bytes.as_slice()[1..], &*n.to_be_bytes_trimmed_vartime());

        let bytes: &[u8] = b"";
        let n = BoxedUint::from_be_slice(bytes, 128).unwrap();
        assert_eq!(
            hex!("00000000000000000000000000000000"),
            n.to_be_bytes().as_ref()
        );
        assert_eq!(bytes, n.to_be_bytes_trimmed_vartime().as_ref());

        let bytes = hex!("00012233445566778899aabbccddeeff");
        let n = BoxedUint::from_be_slice(&bytes, 128).unwrap();
        assert_eq!(&bytes.as_slice()[1..], &*n.to_be_bytes_trimmed_vartime());

        let bytes = hex!("00000000000000000000000000000001");
        let n = BoxedUint::from_be_slice(&bytes, 128).unwrap();
        assert_eq!(bytes, n.to_be_bytes().as_ref());
        assert_eq!(&bytes.as_slice()[15..], &*n.to_be_bytes_trimmed_vartime());
    }

    #[test]
    fn to_le_bytes() {
        let bytes = hex!("ffeeddccbbaa99887766554433221100");
        let n = BoxedUint::from_le_slice(&bytes, 128).unwrap();
        assert_eq!(bytes.as_slice(), &*n.to_le_bytes());
    }

    #[test]
    fn to_le_bytes_trimmed_vartime() {
        let bytes = hex!("ffeeddccbbaa998877665544332211ff");
        let n = BoxedUint::from_le_slice(&bytes, 128).unwrap();
        assert_eq!(bytes.as_slice(), &*n.to_le_bytes_trimmed_vartime());

        let bytes = hex!("ffeeddccbbaa99887766554433221100");
        let n = BoxedUint::from_le_slice(&bytes, 128).unwrap();
        assert_eq!(&bytes.as_slice()[..15], &*n.to_le_bytes_trimmed_vartime());

        let bytes = hex!("ff000000000000000000000000000000");
        let n = BoxedUint::from_le_slice(&bytes, 128).unwrap();
        assert_eq!(&bytes.as_slice()[..1], &*n.to_le_bytes_trimmed_vartime());

        let bytes = hex!("01000000000000000000000000000000");
        let n = BoxedUint::from_le_slice(&bytes, 128).unwrap();
        assert_eq!(&bytes.as_slice()[..1], &*n.to_le_bytes_trimmed_vartime());

        let bytes = hex!("00000000000000000000000000000000");
        let n = BoxedUint::from_le_slice(&bytes, 128).unwrap();
        assert_eq!(b"", &*n.to_le_bytes_trimmed_vartime());
    }

    #[test]
    fn from_str_radix_invalid() {
        assert_eq!(
            BoxedUint::from_str_radix_vartime("?", 10,),
            Err(DecodeError::InvalidDigit)
        );
        assert_eq!(
            BoxedUint::from_str_radix_with_precision_vartime(
                "ffffffffffffffff_ffffffffffffffff_f",
                16,
                128
            ),
            Err(DecodeError::InputSize)
        );
        assert_eq!(
            BoxedUint::from_str_radix_with_precision_vartime("1111111111111111", 2, 10),
            Err(DecodeError::Precision)
        );
    }

    #[test]
    fn from_str_radix_10() {
        let dec = "+340_282_366_920_938_463_463_374_607_431_768_211_455";
        let res = BoxedUint::from_str_radix_vartime(dec, 10).expect("error decoding");
        assert_eq!(res, BoxedUint::max(128));
    }

    #[test]
    fn from_str_radix_16() {
        let hex = "fedcba9876543210fedcba9876543210";
        let res = BoxedUint::from_str_radix_vartime(hex, 16).expect("error decoding");
        assert_eq!(hex, format!("{res:x}"));
    }

    #[test]
    #[cfg(feature = "rand_core")]
    fn encode_radix_round_trip() {
        use crate::RandomBits;
        use rand_core::SeedableRng;
        let mut rng = chacha20::ChaCha8Rng::seed_from_u64(1);

        let rounds = if cfg!(miri) { 10 } else { 100 };
        let bits = if cfg!(miri) { 256 } else { 4096 };
        for _ in 0..rounds {
            let uint = BoxedUint::random_bits(&mut rng, bits);
            for radix in 2..=36 {
                let enc = uint.to_string_radix_vartime(radix);
                let res = BoxedUint::from_str_radix_vartime(&enc, radix).expect("decoding error");
                assert_eq!(
                    res, uint,
                    "round trip failure: radix {radix} encoded {uint} as {enc}"
                );
            }
        }
    }
}
