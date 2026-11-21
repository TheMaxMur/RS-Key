//! Serde trait coverage tests.

#![cfg(feature = "serde")]

use crypto_bigint::{
    Checked, I64, I128, I256, I512, Limb, NonZero, Odd, U64, U128, U256, U512, Wrapping,
    const_monty_params, modular::ConstMontyForm,
};
use serdect::serde::{
    Deserialize, Serialize,
    de::value::{Error, StrDeserializer},
};

const_monty_params!(
    Modulus,
    U256,
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
);

type FieldElement = ConstMontyForm<Modulus, { U256::LIMBS }>;

macro_rules! assert_serde_impls {
    ($($ty:ty),+ $(,)?) => {
        $(
            assert_serde::<$ty>();
        )+
    };
}

fn assert_serde<T>()
where
    T: Serialize + for<'de> Deserialize<'de>,
{
}

#[test]
fn serde_impl_matrix() {
    assert_serde_impls!(
        Limb,
        U64,
        U128,
        U256,
        U512,
        I64,
        I128,
        I256,
        I512,
        NonZero<Limb>,
        NonZero<U256>,
        NonZero<I256>,
        NonZero<FieldElement>,
        Odd<Limb>,
        Odd<U256>,
        Odd<I256>,
        Wrapping<Limb>,
        Wrapping<U256>,
        Wrapping<I256>,
        Wrapping<FieldElement>,
        Checked<Limb>,
        Checked<U256>,
        Checked<I256>,
        Checked<FieldElement>,
        FieldElement,
    );

    #[cfg(feature = "alloc")]
    assert_serde_impls!(
        crypto_bigint::BoxedUint,
        NonZero<crypto_bigint::BoxedUint>,
        Odd<crypto_bigint::BoxedUint>,
        Wrapping<crypto_bigint::BoxedUint>,
    );
}

#[test]
fn int_serde_deserialization_uses_serdect_encoding() {
    let minus_one = "ff".repeat(I256::BYTES);
    assert_eq!(
        I256::deserialize(StrDeserializer::<Error>::new(&minus_one)).expect("I256 deserializes"),
        I256::MINUS_ONE
    );

    let zero = "00".repeat(I256::BYTES);
    assert!(NonZero::<I256>::deserialize(StrDeserializer::<Error>::new(&zero)).is_err());

    let two = format!("02{}", "00".repeat(I256::BYTES - 1));
    assert!(Odd::<I256>::deserialize(StrDeserializer::<Error>::new(&two)).is_err());
}
