use core::{
    iter::{Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use rand_core::RngCore;
use zeroize::Zeroize;

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

use crypto_bigint::{Encoding, Word, U256};

use curve25519_dalek::FieldElement as FfFieldElement;
use group::ff::{Field, FieldBits, FromUniformBytes, PrimeField, PrimeFieldBits};

use crate::{constant_time, math, math_op, u8_from_bool};

/// A constant-time implementation of the Ed25519 field.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Zeroize)]
#[repr(transparent)]
pub struct FieldElement(FfFieldElement);

constant_time!(FieldElement, FfFieldElement);
math!(
    FieldElement,
    FieldElement,
    |x: FfFieldElement, y: FfFieldElement| x.add(&y),
    |x: FfFieldElement, y: FfFieldElement| x.sub(&y),
    |x: FfFieldElement, y: FfFieldElement| x.mul(&y)
);

macro_rules! from_wrapper {
    ($uint: ident) => {
        impl From<$uint> for FieldElement {
            fn from(a: $uint) -> FieldElement {
                Self(FfFieldElement::from_repr(U256::from(a).to_le_bytes()).unwrap())
            }
        }
    };
}

from_wrapper!(u8);
from_wrapper!(u16);
from_wrapper!(u32);
from_wrapper!(u64);
from_wrapper!(u128);

impl Neg for FieldElement {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl Neg for &FieldElement {
    type Output = FieldElement;
    fn neg(self) -> Self::Output {
        (*self).neg()
    }
}

impl Field for FieldElement {
    const ZERO: Self = Self(FfFieldElement::ZERO);
    const ONE: Self = Self(FfFieldElement::ONE);

    fn random(rng: impl RngCore) -> Self {
        Self(FfFieldElement::random(rng))
    }

    fn square(&self) -> Self {
        FieldElement(self.0.square())
    }
    fn double(&self) -> Self {
        FieldElement(self.0.double())
    }

    fn invert(&self) -> CtOption<Self> {
        self.0.invert().map(Self)
    }

    fn sqrt(&self) -> CtOption<Self> {
        self.0.sqrt().map(Self)
    }

    fn sqrt_ratio(u: &FieldElement, v: &FieldElement) -> (Choice, FieldElement) {
        let (choice, fe) = FfFieldElement::sqrt_ratio(&u.0, &v.0);
        (choice, Self(fe))
    }
}

impl PrimeField for FieldElement {
    type Repr = [u8; 32];

    const MODULUS: &'static str = <FfFieldElement as PrimeField>::MODULUS;
    const NUM_BITS: u32 = <FfFieldElement as PrimeField>::NUM_BITS;
    const CAPACITY: u32 = <FfFieldElement as PrimeField>::CAPACITY;
    const TWO_INV: Self = Self(<FfFieldElement as PrimeField>::TWO_INV);
    const MULTIPLICATIVE_GENERATOR: Self =
        Self(<FfFieldElement as PrimeField>::MULTIPLICATIVE_GENERATOR);
    const S: u32 = <FfFieldElement as PrimeField>::S;
    const ROOT_OF_UNITY: Self = Self(<FfFieldElement as PrimeField>::ROOT_OF_UNITY);
    const ROOT_OF_UNITY_INV: Self = Self(<FfFieldElement as PrimeField>::ROOT_OF_UNITY_INV);
    const DELTA: Self = Self(<FfFieldElement as PrimeField>::DELTA);

    fn from_repr(bytes: [u8; 32]) -> CtOption<Self> {
        FfFieldElement::from_repr(bytes).map(Self)
    }
    fn to_repr(&self) -> [u8; 32] {
        self.0.to_repr()
    }
    fn is_odd(&self) -> Choice {
        self.0.is_odd()
    }
    fn from_u128(num: u128) -> Self {
        Self::from(num)
    }
}

impl PrimeFieldBits for FieldElement {
    type ReprBits = [u8; 32];

    fn to_le_bits(&self) -> FieldBits<Self::ReprBits> {
        self.0.to_le_bits()
    }
    fn char_le_bits() -> FieldBits<Self::ReprBits> {
        FfFieldElement::char_le_bits()
    }
}

impl FieldElement {
    /// Create a FieldElement from a `crypto_bigint::U256`.
    ///
    /// This will reduce the `U256` by the modulus, into a member of the field.
    pub const fn from_u256(u256: &U256) -> Self {
        let mut bytes = [0; 32];
        let mut i = 0;
        while i < bytes.len() {
            bytes[i] = (u256.as_words()[i / ((Word::BITS as usize) / 8)]
                >> (8 * (i % ((Word::BITS as usize) / 8)))) as u8;
            i += 1;
        }
        Self(FfFieldElement::const_from_bytes(bytes))
    }

    /// Create a `FieldElement` from the reduction of a 512-bit number.
    ///
    /// The bytes are interpreted in little-endian format.
    pub fn wide_reduce(value: [u8; 64]) -> Self {
        Self(FfFieldElement::from_uniform_bytes(&value))
    }

    /// Perform an exponentiation.
    pub fn pow(&self, other: FieldElement) -> FieldElement {
        let mut table = [FieldElement::ONE; 16];
        table[1] = *self;
        for i in 2..16 {
            table[i] = table[i - 1] * self;
        }

        let mut res = FieldElement::ONE;
        let mut bits = 0;
        for (i, mut bit) in other.to_le_bits().iter_mut().rev().enumerate() {
            bits <<= 1;
            let mut bit = u8_from_bool(&mut bit);
            bits |= bit;
            bit.zeroize();

            if ((i + 1) % 4) == 0 {
                if i != 3 {
                    for _ in 0..4 {
                        res *= res;
                    }
                }

                let mut scale_by = FieldElement::ONE;
                #[allow(clippy::needless_range_loop)]
                for i in 0..16 {
                    #[allow(clippy::cast_possible_truncation)] // Safe since 0 .. 16
                    {
                        scale_by =
                            <_>::conditional_select(&scale_by, &table[i], bits.ct_eq(&(i as u8)));
                    }
                }
                res *= scale_by;
                bits = 0;
            }
        }
        res
    }
}

impl FromUniformBytes<64> for FieldElement {
    fn from_uniform_bytes(bytes: &[u8; 64]) -> Self {
        Self::wide_reduce(*bytes)
    }
}

impl Sum<FieldElement> for FieldElement {
    fn sum<I: Iterator<Item = FieldElement>>(iter: I) -> FieldElement {
        let mut res = FieldElement::ZERO;
        for item in iter {
            res += item;
        }
        res
    }
}

impl<'a> Sum<&'a FieldElement> for FieldElement {
    fn sum<I: Iterator<Item = &'a FieldElement>>(iter: I) -> FieldElement {
        iter.copied().sum()
    }
}

impl Product<FieldElement> for FieldElement {
    fn product<I: Iterator<Item = FieldElement>>(iter: I) -> FieldElement {
        let mut res = FieldElement::ONE;
        for item in iter {
            res *= item;
        }
        res
    }
}

impl<'a> Product<&'a FieldElement> for FieldElement {
    fn product<I: Iterator<Item = &'a FieldElement>>(iter: I) -> FieldElement {
        iter.copied().product()
    }
}

#[test]
fn test_field() {
    ff_group_tests::prime_field::test_prime_field_bits::<_, FieldElement>(&mut rand_core::OsRng);
}
