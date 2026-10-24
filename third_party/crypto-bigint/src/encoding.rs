//! Shared encoding support.

use crate::bitlen;
use core::fmt;

#[cfg(feature = "hybrid-array")]
use {
    crate::Integer,
    core::ops::Add,
    hybrid_array::{Array, ArraySize, typenum::Unsigned},
};

/// Byte order used when encoding/decoding field elements as bytestrings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ByteOrder {
    /// Big endian.
    BigEndian,

    /// Little endian.
    LittleEndian,
}

/// Alias for a byte array whose size is defined by [`ArrayEncoding::ByteSize`].
#[cfg(feature = "hybrid-array")]
pub type ByteArray<T> = Array<u8, <T as ArrayEncoding>::ByteSize>;

/// Support for encoding a big integer as a `Array`.
#[cfg(feature = "hybrid-array")]
pub trait ArrayEncoding: Encoding {
    /// Size of a byte array which encodes a big integer.
    type ByteSize: ArraySize + Add + Eq + Ord + Unsigned;

    /// Deserialize from a big-endian byte array.
    fn from_be_byte_array(bytes: ByteArray<Self>) -> Self;

    /// Deserialize from a little-endian byte array.
    fn from_le_byte_array(bytes: ByteArray<Self>) -> Self;

    /// Deserialize from a byte array with the specified [`ByteOrder`].
    #[inline]
    fn from_byte_array(bytes: ByteArray<Self>, byte_order: ByteOrder) -> Self {
        match byte_order {
            ByteOrder::BigEndian => Self::from_be_byte_array(bytes),
            ByteOrder::LittleEndian => Self::from_le_byte_array(bytes),
        }
    }

    /// Serialize to a big-endian byte array.
    fn to_be_byte_array(&self) -> ByteArray<Self>;

    /// Serialize to a little-endian byte array.
    fn to_le_byte_array(&self) -> ByteArray<Self>;

    /// Serialize to a byte array with the specified [`ByteOrder`].
    #[inline]
    fn to_byte_array(&self, byte_order: ByteOrder) -> ByteArray<Self> {
        match byte_order {
            ByteOrder::BigEndian => self.to_be_byte_array(),
            ByteOrder::LittleEndian => self.to_le_byte_array(),
        }
    }
}

/// Support for decoding a `Array` as a big integer.
#[cfg(feature = "hybrid-array")]
pub trait ArrayDecoding {
    /// Big integer which decodes a `Array`.
    type Output: ArrayEncoding + Integer;

    /// Deserialize from a big-endian `Array`.
    fn into_uint_be(self) -> Self::Output;

    /// Deserialize from a little-endian `Array`.
    fn into_uint_le(self) -> Self::Output;
}

/// Encoding support.
// TODO(tarcieri): seal this trait in the next breaking release.
pub trait Encoding: Sized {
    /// Byte array representation.
    type Repr: AsRef<[u8]>
        + AsMut<[u8]>
        + Clone
        + Sized
        + for<'a> TryFrom<&'a [u8], Error: core::error::Error>;

    /// Decode from big endian bytes.
    #[must_use]
    fn from_be_bytes(bytes: Self::Repr) -> Self;

    /// Decode from little endian bytes.
    #[must_use]
    fn from_le_bytes(bytes: Self::Repr) -> Self;

    /// Decode from bytes using the specified [`ByteOrder`].
    #[inline]
    #[must_use]
    fn from_bytes(bytes: Self::Repr, byte_order: ByteOrder) -> Self {
        match byte_order {
            ByteOrder::BigEndian => Self::from_be_bytes(bytes),
            ByteOrder::LittleEndian => Self::from_le_bytes(bytes),
        }
    }

    /// Decode from the provided big endian bytes, truncating to the least significant bits in the
    /// event the given amount of data exceeds `bits_precision`.
    ///
    /// Implementations may panic if `bits_precision` exceeds their underlying size.
    #[must_use]
    fn from_be_slice_truncated(bytes: &[u8], bits_precision: u32) -> Self {
        assert_eq!(bits_precision, bitlen::from_bytes(size_of::<Self::Repr>()));
        let bytes = truncate_be(bytes, bits_precision);
        Self::from_be_bytes(bytes.try_into().expect("input too short"))
    }

    /// Decode from the provided little endian bytes, truncating to the least significant bits in
    /// the event the given amount of data exceeds `bits_precision`.
    ///
    /// Implementations may panic if `bits_precision` exceeds their underlying size.
    #[must_use]
    fn from_le_slice_truncated(bytes: &[u8], bits_precision: u32) -> Self {
        assert_eq!(bits_precision, bitlen::from_bytes(size_of::<Self::Repr>()));
        let bytes = truncate_le(bytes, bits_precision);
        Self::from_le_bytes(bytes.try_into().expect("input too short"))
    }

    /// Decode from the provided bytes, interpreting them using the specified [`ByteOrder`],
    /// truncating to the least significant bits in the event the given amount of data exceeds
    /// `bits_precision`.
    ///
    /// Implementations may panic if `bits_precision` exceeds their underlying size.
    #[inline]
    #[must_use]
    fn from_slice_truncated(bytes: &[u8], bits_precision: u32, byte_order: ByteOrder) -> Self {
        match byte_order {
            ByteOrder::BigEndian => Self::from_be_slice_truncated(bytes, bits_precision),
            ByteOrder::LittleEndian => Self::from_le_slice_truncated(bytes, bits_precision),
        }
    }

    /// Encode to big endian bytes.
    #[must_use]
    fn to_be_bytes(&self) -> Self::Repr;

    /// Encode to little endian bytes.
    #[must_use]
    fn to_le_bytes(&self) -> Self::Repr;

    /// Encode to bytes using the specified [`ByteOrder`].
    #[inline]
    #[must_use]
    fn to_bytes(&self, byte_order: ByteOrder) -> Self::Repr {
        match byte_order {
            ByteOrder::BigEndian => self.to_be_bytes(),
            ByteOrder::LittleEndian => self.to_le_bytes(),
        }
    }
}

/// A trait mapping between encoded representations of integers.
pub trait EncodedSize {
    /// The equivalent encoded representation.
    type Target;
}

/// Possible errors in variable-time integer decoding methods.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// The input value was empty.
    Empty,

    /// The input was not consistent with the format restrictions.
    InvalidDigit,

    /// Input size is too small to fit in the given precision.
    InputSize,

    /// The deserialized number is larger than the given precision.
    Precision,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty value provided"),
            Self::InvalidDigit => {
                write!(f, "invalid digit character")
            }
            Self::InputSize => write!(f, "input size is too small to fit in the given precision"),
            Self::Precision => write!(
                f,
                "the deserialized number is larger than the given precision"
            ),
        }
    }
}

impl core::error::Error for DecodeError {}

/// Interpret `bytes` as a big endian integer and extract `bits_precision` number of least
/// significant bits, returning a truncated input if it exceeds the requested precision.
pub(crate) fn truncate_be(bytes: &[u8], bits_precision: u32) -> &[u8] {
    let bytes_precision = bitlen::to_bytes(bits_precision);
    if bytes.len() > bytes_precision {
        &bytes[bytes.len().saturating_sub(bytes_precision)..]
    } else {
        bytes
    }
}

/// Interpret `bytes` as a little endian integer and extract `bits_precision` number of least
/// significant bits, returning a truncated input if it exceeds the requested precision.
pub(crate) fn truncate_le(bytes: &[u8], bits_precision: u32) -> &[u8] {
    let bytes_precision = bitlen::to_bytes(bits_precision);
    if bytes.len() > bytes_precision {
        &bytes[..bytes_precision]
    } else {
        bytes
    }
}
