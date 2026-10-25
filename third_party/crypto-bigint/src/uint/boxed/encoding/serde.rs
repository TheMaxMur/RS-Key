use serdect::serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};

use crate::BoxedUint;

impl<'de> Deserialize<'de> for BoxedUint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let slice = serdect::slice::deserialize_hex_or_bin_vec(deserializer)?;

        let bit_precision = u32::try_from(slice.len())
            .ok()
            .and_then(|nbytes| nbytes.checked_mul(8))
            .ok_or(Error::custom(
                "Deserialized value overflows u32 bit precision!",
            ))?;

        Self::from_le_slice(&slice, bit_precision).map_err(Error::custom)
    }
}

impl Serialize for BoxedUint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serdect::slice::serialize_hex_lower_or_bin(&self.to_le_bytes(), serializer)
    }
}
