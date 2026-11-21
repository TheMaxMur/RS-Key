//! Field arithmetic modulo p = 2^{384} − 2^{128} − 2^{96} + 2^{32} − 1
//!
//! Arithmetic implementations have been synthesized using fiat-crypto.
//!
//! # License
//!
//! Copyright (c) 2015-2020 the fiat-crypto authors
//!
//! fiat-crypto is distributed under the terms of the MIT License, the
//! Apache License (Version 2.0), and the BSD 1-Clause License;
//! users may pick which license to apply.

use elliptic_curve::{
    bigint::{U384, cpubits},
    ff::PrimeField,
    ops::BatchInvert,
    subtle::{Choice, ConstantTimeEq, CtOption},
};

// Default backend: fiat-crypto
cpubits! {
    32 => {
        #[cfg(p384_backend = "fiat")]
        use fiat_crypto::p384_32::*;
    }
    64 => {
        #[cfg(p384_backend = "fiat")]
        use fiat_crypto::p384_64::*;
    }
}

/// Constant representing the modulus
/// p = 2^{384} − 2^{128} − 2^{96} + 2^{32} − 1
const MODULUS_HEX: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";

primefield::monty_field_params! {
    name: FieldParams,
    modulus: MODULUS_HEX,
    uint: U384,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 19,
    doc: "Montgomery parameters for the NIST P-384 field modulus: `p = 2^{384} − 2^{128} − 2^{96} + 2^{32} − 1`."
}

primefield::monty_field_element! {
    name: FieldElement,
    params: FieldParams,
    uint: U384,
    doc: "Element in the finite field modulo `p = 2^{384} − 2^{128} − 2^{96} + 2^{32} − 1`."
}

#[cfg(all(target_pointer_width = "32", not(p384_backend = "fiat")))]
#[path = "montgomery32.rs"]
mod montgomery32;

// Expanded from primefield 0.14's monty_field_arithmetic to specialize products.
#[cfg(not(p384_backend = "fiat"))]
impl FieldElement {
    /// Convert into Montgomery form without checking the input against p.
    #[inline]
    pub(crate) const fn from_uint_unchecked(w: U384) -> Self {
        Self(primefield::MontyFieldElement::from_uint_reduced(&w))
    }

    /// Return the canonical integer outside the Montgomery domain.
    #[inline]
    pub const fn to_canonical(self) -> U384 {
        self.0.to_canonical()
    }

    // Keep twelve-limb additions out of each point-formula call site on Cortex-M.
    /// Add elements.
    #[cfg_attr(target_pointer_width = "32", inline(never))]
    #[cfg_attr(not(target_pointer_width = "32"), inline)]
    pub const fn add(&self, rhs: &Self) -> Self {
        Self(self.0.add(&rhs.0))
    }

    /// Double an element.
    #[cfg_attr(target_pointer_width = "32", inline(never))]
    #[cfg_attr(not(target_pointer_width = "32"), inline)]
    #[must_use]
    pub const fn double(&self) -> Self {
        Self(self.0.double())
    }

    /// Subtract elements.
    #[cfg_attr(target_pointer_width = "32", inline(never))]
    #[cfg_attr(not(target_pointer_width = "32"), inline)]
    pub const fn sub(&self, rhs: &Self) -> Self {
        Self(self.0.sub(&rhs.0))
    }

    /// Multiply elements.
    #[inline]
    pub const fn multiply(&self, rhs: &Self) -> Self {
        #[cfg(target_pointer_width = "32")]
        {
            Self(primefield::MontyFieldElement::from_montgomery_words(
                montgomery32::multiply(self.0.to_montgomery_words(), rhs.0.to_montgomery_words()),
            ))
        }
        #[cfg(not(target_pointer_width = "32"))]
        {
            Self(self.0.multiply(&rhs.0))
        }
    }

    /// Negate an element.
    #[inline]
    pub const fn neg(&self) -> Self {
        Self(self.0.neg())
    }

    /// Square an element.
    #[inline]
    #[must_use]
    pub const fn square(&self) -> Self {
        #[cfg(target_pointer_width = "32")]
        {
            Self(primefield::MontyFieldElement::from_montgomery_words(
                montgomery32::square(self.0.to_montgomery_words()),
            ))
        }
        #[cfg(not(target_pointer_width = "32"))]
        {
            Self(self.0.square())
        }
    }

    /// Invert an element in constant time.
    #[inline]
    pub fn invert(&self) -> CtOption<Self> {
        self.0.invert().map(Self)
    }

    /// Invert an element in variable time.
    #[inline]
    pub fn invert_vartime(&self) -> CtOption<Self> {
        self.0.invert_vartime().map(Self)
    }

    /// Invert a nonzero constant at compile time; zero panics.
    pub const fn const_invert(&self) -> Self {
        Self(self.0.const_invert())
    }
}

#[cfg(p384_backend = "fiat")]
primefield::fiat_monty_field_arithmetic! {
    name: FieldElement,
    params: FieldParams,
    uint: U384,
    non_mont: fiat_p384_non_montgomery_domain_field_element,
    mont: fiat_p384_montgomery_domain_field_element,
    from_mont: fiat_p384_from_montgomery,
    to_mont: fiat_p384_to_montgomery,
    add: fiat_p384_add,
    sub: fiat_p384_sub,
    mul: fiat_p384_mul,
    neg: fiat_p384_opp,
    square: fiat_p384_square,
    divstep_precomp: fiat_p384_divstep_precomp,
    divstep: fiat_p384_divstep,
    msat: fiat_p384_msat,
    selectnz: fiat_p384_selectznz
}

impl BatchInvert for FieldElement {}

#[cfg(test)]
mod tests {
    use super::{FieldElement, U384};
    #[cfg(p384_backend = "fiat")]
    use super::{
        FieldParams, fiat_p384_montgomery_domain_field_element, fiat_p384_msat,
        fiat_p384_non_montgomery_domain_field_element, fiat_p384_to_montgomery,
    };

    primefield::test_primefield!(FieldElement, U384);

    #[cfg(p384_backend = "fiat")]
    primefield::test_fiat_monty_field_arithmetic!(
        name: FieldElement,
        params: FieldParams,
        uint: U384,
        non_mont: fiat_p384_non_montgomery_domain_field_element,
        mont: fiat_p384_montgomery_domain_field_element,
        to_mont: fiat_p384_to_montgomery,
        msat: fiat_p384_msat
    );
}
