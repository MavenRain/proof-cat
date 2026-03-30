//! Multilinear polynomials over the Boolean hypercube.
//!
//! A [`MultilinearPoly<F>`] is uniquely determined by its `2^n`
//! evaluations on `{0,1}^n`.  It supports efficient evaluation at
//! arbitrary points via iterated partial evaluation (folding).
//!
//! This is the core data structure for the sumcheck protocol:
//! each round binds one variable, halving the evaluation table.

use crate::error::Error;
use plonkish_cat::Field;

/// The number of variables in a multilinear polynomial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NumVars(usize);

impl NumVars {
    /// Create a new variable count.
    #[must_use]
    pub fn new(n: usize) -> Self {
        Self(n)
    }

    /// The underlying count.
    #[must_use]
    pub fn count(self) -> usize {
        self.0
    }
}

impl core::fmt::Display for NumVars {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A multilinear polynomial represented by its evaluation table.
///
/// The table has `2^num_vars` entries in big-endian bit order:
/// the first variable is the most significant bit.  For a
/// 2-variable polynomial `f(x0, x1)`:
///
/// | Index | x0 | x1 | Value |
/// |-------|----|----|-------|
/// | 0     | 0  | 0  | `evals[0]` |
/// | 1     | 0  | 1  | `evals[1]` |
/// | 2     | 1  | 0  | `evals[2]` |
/// | 3     | 1  | 1  | `evals[3]` |
///
/// # Examples
///
/// ```
/// use plonkish_cat::F101;
/// use proof_cat::MultilinearPoly;
///
/// // f(x0, x1): f(0,0)=1, f(0,1)=2, f(1,0)=3, f(1,1)=4
/// let poly = MultilinearPoly::from_evals(vec![
///     F101::new(1), F101::new(2), F101::new(3), F101::new(4),
/// ])?;
///
/// assert_eq!(poly.num_vars().count(), 2);
///
/// // Sum over the Boolean hypercube: 1 + 2 + 3 + 4 = 10
/// assert_eq!(poly.sum_over_boolean_hypercube(), F101::new(10));
///
/// // Evaluate at a Boolean point: f(1, 0) = 3
/// let val = poly.evaluate(&[F101::new(1), F101::new(0)])?;
/// assert_eq!(val, F101::new(3));
/// # Ok::<(), proof_cat::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct MultilinearPoly<F: Field> {
    evals: Vec<F>,
    num_vars: NumVars,
}

impl<F: Field> MultilinearPoly<F> {
    /// Construct from an evaluation table.
    ///
    /// The table length must be a power of two (including 1).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotPowerOfTwo`] if `evals.len()` is not
    /// a power of two or is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use plonkish_cat::F101;
    /// use proof_cat::MultilinearPoly;
    ///
    /// // A 1-variable polynomial: f(0) = 3, f(1) = 7.
    /// let poly = MultilinearPoly::from_evals(vec![
    ///     F101::new(3), F101::new(7),
    /// ])?;
    /// assert_eq!(poly.num_vars().count(), 1);
    ///
    /// // Non-power-of-two lengths are rejected.
    /// let err = MultilinearPoly::<F101>::from_evals(vec![
    ///     F101::new(1), F101::new(2), F101::new(3),
    /// ]);
    /// assert!(err.is_err());
    /// # Ok::<(), proof_cat::Error>(())
    /// ```
    pub fn from_evals(evals: Vec<F>) -> Result<Self, Error> {
        let len = evals.len();
        if len.is_power_of_two() {
            // log2 of a power of two: count trailing zeros.
            let num_vars = NumVars::new(
                usize::try_from(len.trailing_zeros())
                    .map_err(|_| Error::NotPowerOfTwo { value: len })?,
            );
            Ok(Self { evals, num_vars })
        } else {
            Err(Error::NotPowerOfTwo { value: len })
        }
    }

    /// The number of variables.
    #[must_use]
    pub fn num_vars(&self) -> NumVars {
        self.num_vars
    }

    /// The evaluation table.
    #[must_use]
    pub fn evals(&self) -> &[F] {
        &self.evals
    }

    /// Sum of all evaluations on the Boolean hypercube.
    ///
    /// This equals `sum_{x in {0,1}^n} f(x)`.
    #[must_use]
    pub fn sum_over_boolean_hypercube(&self) -> F {
        self.evals
            .iter()
            .cloned()
            .fold(F::zero(), |acc, v| acc + v)
    }

    /// Evaluate the multilinear extension at an arbitrary point.
    ///
    /// Uses iterated partial evaluation: for each variable `i`,
    /// the table is split in half and each pair `(lo, hi)` is
    /// interpolated as `lo * (1 - r_i) + hi * r_i`.  After `n`
    /// rounds a single value remains.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DimensionMismatch`] if `point.len() != num_vars`.
    ///
    /// # Examples
    ///
    /// ```
    /// use plonkish_cat::F101;
    /// use proof_cat::MultilinearPoly;
    ///
    /// // f(x) = 3*(1-x) + 7*x = 3 + 4x
    /// let poly = MultilinearPoly::from_evals(vec![
    ///     F101::new(3), F101::new(7),
    /// ])?;
    ///
    /// // f(0) = 3, f(1) = 7, f(2) = 11
    /// assert_eq!(poly.evaluate(&[F101::new(0)])?, F101::new(3));
    /// assert_eq!(poly.evaluate(&[F101::new(1)])?, F101::new(7));
    /// assert_eq!(poly.evaluate(&[F101::new(2)])?, F101::new(11));
    /// # Ok::<(), proof_cat::Error>(())
    /// ```
    pub fn evaluate(&self, point: &[F]) -> Result<F, Error> {
        if point.len() == self.num_vars.0 {
            let final_table = point.iter().fold(self.evals.clone(), |table, r_i| {
                let half = table.len() / 2;
                (0..half)
                    .map(|j| {
                        let lo = table[j].clone();
                        let hi = table[j + half].clone();
                        // lo * (1 - r_i) + hi * r_i
                        lo * (F::one() - r_i.clone()) + hi * r_i.clone()
                    })
                    .collect()
            });
            // After num_vars folds, exactly one element remains.
            final_table
                .into_iter()
                .next()
                .ok_or(Error::DimensionMismatch {
                    expected: self.num_vars.0,
                    actual: point.len(),
                })
        } else {
            Err(Error::DimensionMismatch {
                expected: self.num_vars.0,
                actual: point.len(),
            })
        }
    }

    /// Bind the first variable to `r`, producing a polynomial
    /// with one fewer variable.
    ///
    /// The resulting table has `2^(n-1)` entries where each
    /// entry `j` is `evals[2j] * (1 - r) + evals[2j+1] * r`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DimensionMismatch`] if the polynomial
    /// has zero variables.
    pub fn bind_first_var(&self, r: &F) -> Result<Self, Error> {
        if self.num_vars.0 > 0 {
            let half = self.evals.len() / 2;
            let new_evals: Vec<F> = (0..half)
                .map(|j| {
                    let lo = self.evals[j].clone();
                    let hi = self.evals[j + half].clone();
                    lo * (F::one() - r.clone()) + hi * r.clone()
                })
                .collect();
            Self::from_evals(new_evals)
        } else {
            Err(Error::DimensionMismatch {
                expected: 1,
                actual: 0,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonkish_cat::F101;

    #[test]
    fn from_evals_requires_power_of_two() {
        let result = MultilinearPoly::<F101>::from_evals(vec![
            F101::new(1),
            F101::new(2),
            F101::new(3),
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn from_evals_empty_fails() {
        let result = MultilinearPoly::<F101>::from_evals(vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn single_element_poly() -> Result<(), Error> {
        // 0 variables, one evaluation.
        let poly = MultilinearPoly::from_evals(vec![F101::new(42)])?;
        assert_eq!(poly.num_vars().count(), 0);
        assert_eq!(poly.evaluate(&[])?, F101::new(42));
        Ok(())
    }

    #[test]
    fn one_var_evaluation_at_boolean_points() -> Result<(), Error> {
        // f(0) = 3, f(1) = 7
        let poly = MultilinearPoly::from_evals(vec![F101::new(3), F101::new(7)])?;
        assert_eq!(poly.num_vars().count(), 1);
        assert_eq!(poly.evaluate(&[F101::new(0)])?, F101::new(3));
        assert_eq!(poly.evaluate(&[F101::new(1)])?, F101::new(7));
        Ok(())
    }

    #[test]
    fn one_var_evaluation_at_midpoint() -> Result<(), Error> {
        // f(0) = 3, f(1) = 7
        // f(r) = 3*(1-r) + 7*r = 3 + 4r
        // f(2) = 3 + 8 = 11
        let poly = MultilinearPoly::from_evals(vec![F101::new(3), F101::new(7)])?;
        assert_eq!(poly.evaluate(&[F101::new(2)])?, F101::new(11));
        Ok(())
    }

    #[test]
    fn two_var_evaluation() -> Result<(), Error> {
        // f(x0, x1) with evaluations:
        //   f(0,0) = 1, f(0,1) = 2, f(1,0) = 3, f(1,1) = 4
        let poly = MultilinearPoly::from_evals(vec![
            F101::new(1),
            F101::new(2),
            F101::new(3),
            F101::new(4),
        ])?;
        assert_eq!(poly.num_vars().count(), 2);
        // Boolean point checks:
        assert_eq!(poly.evaluate(&[F101::new(0), F101::new(0)])?, F101::new(1));
        assert_eq!(poly.evaluate(&[F101::new(0), F101::new(1)])?, F101::new(2));
        assert_eq!(poly.evaluate(&[F101::new(1), F101::new(0)])?, F101::new(3));
        assert_eq!(poly.evaluate(&[F101::new(1), F101::new(1)])?, F101::new(4));
        Ok(())
    }

    #[test]
    fn sum_over_hypercube() -> Result<(), Error> {
        let poly = MultilinearPoly::from_evals(vec![
            F101::new(1),
            F101::new(2),
            F101::new(3),
            F101::new(4),
        ])?;
        // 1 + 2 + 3 + 4 = 10
        assert_eq!(poly.sum_over_boolean_hypercube(), F101::new(10));
        Ok(())
    }

    #[test]
    fn bind_first_var() -> Result<(), Error> {
        // f(x0, x1): f(0,0)=1, f(0,1)=2, f(1,0)=3, f(1,1)=4
        let poly = MultilinearPoly::from_evals(vec![
            F101::new(1),
            F101::new(2),
            F101::new(3),
            F101::new(4),
        ])?;
        // Bind x0 = 0: get f(0, x1) = [1, 2]
        let bound_zero = poly.bind_first_var(&F101::new(0))?;
        assert_eq!(bound_zero.num_vars().count(), 1);
        assert_eq!(bound_zero.evals(), &[F101::new(1), F101::new(2)]);

        // Bind x0 = 1: get f(1, x1) = [3, 4]
        let bound_one = poly.bind_first_var(&F101::new(1))?;
        assert_eq!(bound_one.evals(), &[F101::new(3), F101::new(4)]);
        Ok(())
    }

    #[test]
    fn dimension_mismatch_error() {
        let poly =
            MultilinearPoly::from_evals(vec![F101::new(1), F101::new(2)]).unwrap_or_else(|_| {
                MultilinearPoly::from_evals(vec![F101::new(0)]).unwrap_or_else(|_| unreachable!())
            });
        // Wrong number of evaluation coordinates.
        let result = poly.evaluate(&[F101::new(0), F101::new(0)]);
        assert!(result.is_err());
    }
}
