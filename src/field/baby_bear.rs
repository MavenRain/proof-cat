//! The `BabyBear` prime field: integers modulo `p = 2^31 - 1`.
//!
//! `BabyBear` is a Mersenne prime field widely used in modern proof
//! systems (Plonky3, SP1).  Its small characteristic enables fast
//! modular arithmetic on 64-bit hardware.

use plonkish_cat::Field;

/// The `BabyBear` modulus: `2^31 - 1 = 2_147_483_647`.
const P: u64 = 2_147_483_647;

/// A field element in the `BabyBear` prime field (mod `2^31 - 1`).
///
/// Stored as a `u64` to avoid overflow during multiplication:
/// the worst-case intermediate value is `(p-1)^2 < 2^62 < 2^64`.
///
/// # Examples
///
/// ```
/// use proof_cat::BabyBear;
/// use plonkish_cat::Field;
///
/// let a = BabyBear::new(42);
/// let b = BabyBear::new(7);
///
/// // Arithmetic reduces modulo p = 2^31 - 1.
/// let sum = a + b;
/// assert_eq!(sum.value(), 49);
///
/// // Multiplicative inverse via Fermat's little theorem.
/// let a_inv = a.inv()?;
/// assert_eq!(a * a_inv, BabyBear::one());
/// # Ok::<(), plonkish_cat::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BabyBear(u64);

impl BabyBear {
    /// Create a new field element, reducing modulo `p`.
    ///
    /// # Examples
    ///
    /// ```
    /// use proof_cat::BabyBear;
    ///
    /// let a = BabyBear::new(42);
    /// assert_eq!(a.value(), 42);
    ///
    /// // Values larger than p are reduced.
    /// let b = BabyBear::new(2_147_483_648);
    /// assert_eq!(b.value(), 1);
    /// ```
    #[must_use]
    pub fn new(value: u64) -> Self {
        Self(value % P)
    }

    /// The underlying integer value in `[0, p)`.
    #[must_use]
    pub fn value(self) -> u64 {
        self.0
    }
}

impl core::fmt::Display for BabyBear {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::ops::Add for BabyBear {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self((self.0 + rhs.0) % P)
    }
}

impl std::ops::Sub for BabyBear {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self((self.0 + P - rhs.0) % P)
    }
}

impl std::ops::Mul for BabyBear {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Self((self.0 * rhs.0) % P)
    }
}

impl std::ops::Neg for BabyBear {
    type Output = Self;
    fn neg(self) -> Self {
        Self((P - self.0) % P)
    }
}

impl Field for BabyBear {
    fn zero() -> Self {
        Self(0)
    }

    fn one() -> Self {
        Self(1)
    }

    fn inv(&self) -> Result<Self, plonkish_cat::Error> {
        if self.0 == 0 {
            Err(plonkish_cat::Error::DivisionByZero)
        } else {
            // Fermat's little theorem: a^{-1} = a^{p-2} mod p
            Ok(pow_mod(self.0, P - 2, P))
        }
    }
}

/// Modular exponentiation by repeated squaring: `base^exp mod modulus`.
///
/// Uses a fold over the bit positions of `exp`.
fn pow_mod(base: u64, exp: u64, modulus: u64) -> BabyBear {
    let result = (0..64u32)
        .filter(|i| (exp >> i) & 1 == 1)
        .fold(1u64, |acc, i| {
            // Compute base^(2^i) mod modulus via i squarings.
            let power = (0..i).fold(base, |b, _| (b * b) % modulus);
            (acc * power) % modulus
        });
    BabyBear(result % modulus)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_additive_identity() {
        let a = BabyBear::new(123_456);
        assert_eq!(a + BabyBear::zero(), a);
        assert_eq!(BabyBear::zero() + a, a);
    }

    #[test]
    fn one_is_multiplicative_identity() {
        let a = BabyBear::new(123_456);
        assert_eq!(a * BabyBear::one(), a);
        assert_eq!(BabyBear::one() * a, a);
    }

    #[test]
    fn additive_inverse() {
        let a = BabyBear::new(999_999);
        assert_eq!(a + (-a), BabyBear::zero());
    }

    #[test]
    fn multiplicative_inverse() -> Result<(), plonkish_cat::Error> {
        let a = BabyBear::new(42);
        let a_inv = a.inv()?;
        assert_eq!(a * a_inv, BabyBear::one());
        Ok(())
    }

    #[test]
    fn inverse_of_zero_fails() {
        let result = BabyBear::zero().inv();
        assert!(result.is_err());
    }

    #[test]
    fn sample_inverses() -> Result<(), plonkish_cat::Error> {
        // Check a handful of representative values.
        let samples = [1u64, 2, 7, 100, 1_000_000, P - 1, P - 2];
        samples.iter().try_for_each(|&v| {
            let a = BabyBear::new(v);
            let a_inv = a.inv()?;
            assert_eq!(a * a_inv, BabyBear::one(), "failed for {v}");
            Ok(())
        })
    }

    #[test]
    fn subtraction_is_add_neg() {
        let a = BabyBear::new(1_000_000);
        let b = BabyBear::new(500_000);
        assert_eq!(a - b, a + (-b));
    }

    #[test]
    fn multiplication_is_commutative() {
        let a = BabyBear::new(12_345);
        let b = BabyBear::new(67_890);
        assert_eq!(a * b, b * a);
    }

    #[test]
    fn distributivity() {
        let a = BabyBear::new(111);
        let b = BabyBear::new(222);
        let c = BabyBear::new(333);
        assert_eq!(a * (b + c), a * b + a * c);
    }

    #[test]
    fn new_reduces_mod_p() {
        assert_eq!(BabyBear::new(P), BabyBear::new(0));
        assert_eq!(BabyBear::new(P + 1), BabyBear::new(1));
        assert_eq!(BabyBear::new(2 * P), BabyBear::new(0));
    }
}
