// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors
pub use p256::elliptic_curve::bigint::ctutils;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct Limb(pub u32);

impl Limb {
    pub const ZERO: Self = Self(0);

    pub const fn carrying_add(self, rhs: Self, carry: Self) -> (Self, Self) {
        let sum = self.0 as u64 + rhs.0 as u64 + carry.0 as u64;
        (Self(sum as u32), Self((sum >> 32) as u32))
    }

    pub const fn carrying_mul_add(self, rhs: Self, addend: Self, carry: Self) -> (Self, Self) {
        let product = self.0 as u64 * rhs.0 as u64 + addend.0 as u64 + carry.0 as u64;
        (Self(product as u32), Self((product >> 32) as u32))
    }

    pub const fn borrowing_sub(self, rhs: Self, borrow: Self) -> (Self, Self) {
        let incoming = ctutils::Choice::from_u8_lsb((borrow.0 >> 31) as u8);
        let (difference, next) = ctutils::primitives::borrowing_sub_u32(self.0, rhs.0, incoming);
        (Self(difference), Self(next.to_u32_mask()))
    }

    pub const fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct U256([Limb; 8]);

impl U256 {
    pub const ZERO: Self = Self([Limb::ZERO; 8]);

    pub const fn new(limbs: [Limb; 8]) -> Self {
        Self(limbs)
    }

    pub const fn as_limbs(&self) -> &[Limb; 8] {
        &self.0
    }
}

pub const MODULUS: U256 = U256::new([
    Limb(0xffff_ffff),
    Limb(0xffff_ffff),
    Limb(0xffff_ffff),
    Limb(0),
    Limb(0),
    Limb(0),
    Limb(1),
    Limb(0xffff_ffff),
]);

pub mod modular {
    use super::{MODULUS, U256};

    pub trait ConstMontyParams {
        const PARAMS: Params;
    }

    pub struct Params;
    pub struct Modulus;

    impl Params {
        pub const fn modulus(&self) -> Modulus {
            Modulus
        }
    }

    impl Modulus {
        pub const fn as_ref(&self) -> &'static U256 {
            &MODULUS
        }
    }
}
