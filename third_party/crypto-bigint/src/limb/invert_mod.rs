use super::Limb;
use crate::{Odd, primitives};

impl Odd<Limb> {
    /// Returns the multiplicative inverse of the argument modulo 2^N, where
    /// 2^N is the capacity of a [`Limb`].
    pub(crate) const fn multiplicative_inverse(self) -> Limb {
        cpubits::cpubits! {
            32 => {
                Limb(primitives::u32_invert_odd(self.as_ref().0))
            }
            64 => {
                Limb(primitives::u64_invert_odd(self.as_ref().0))
            }
        }
    }
}
