//! Sumcheck protocol types.
//!
//! Defines the claim, round messages, and proof structure for
//! the sumcheck interactive proof.

use plonkish_cat::Field;

use crate::poly::MultilinearPoly;

/// A sumcheck claim: the polynomial and its purported sum.
///
/// The claim asserts that
/// `sum_{x in {0,1}^n} poly(x) = claimed_sum`.
#[derive(Debug, Clone)]
pub struct SumcheckClaim<F: Field> {
    poly: MultilinearPoly<F>,
    claimed_sum: F,
}

impl<F: Field> SumcheckClaim<F> {
    /// Create a new sumcheck claim.
    #[must_use]
    pub fn new(poly: MultilinearPoly<F>, claimed_sum: F) -> Self {
        Self { poly, claimed_sum }
    }

    /// The polynomial being summed.
    #[must_use]
    pub fn poly(&self) -> &MultilinearPoly<F> {
        &self.poly
    }

    /// The claimed sum.
    #[must_use]
    pub fn claimed_sum(&self) -> &F {
        &self.claimed_sum
    }
}

/// A degree-1 univariate polynomial sent by the prover each round.
///
/// Represented by its evaluations at 0 and 1:
/// `s(t) = eval_zero * (1 - t) + eval_one * t`.
#[derive(Debug, Clone)]
pub struct RoundPoly<F: Field> {
    eval_zero: F,
    eval_one: F,
}

impl<F: Field> RoundPoly<F> {
    /// Create a round polynomial from its evaluations at 0 and 1.
    #[must_use]
    pub fn new(eval_zero: F, eval_one: F) -> Self {
        Self {
            eval_zero,
            eval_one,
        }
    }

    /// `s(0)`: evaluation at zero.
    #[must_use]
    pub fn eval_zero(&self) -> &F {
        &self.eval_zero
    }

    /// `s(1)`: evaluation at one.
    #[must_use]
    pub fn eval_one(&self) -> &F {
        &self.eval_one
    }

    /// Evaluate at an arbitrary point via linear interpolation:
    /// `s(t) = eval_zero * (1 - t) + eval_one * t`.
    #[must_use]
    pub fn evaluate(&self, t: &F) -> F {
        self.eval_zero.clone() * (F::one() - t.clone()) + self.eval_one.clone() * t.clone()
    }
}

/// A complete sumcheck proof: one round polynomial per variable.
#[derive(Debug, Clone)]
pub struct SumcheckProof<F: Field> {
    round_polys: Vec<RoundPoly<F>>,
}

impl<F: Field> SumcheckProof<F> {
    /// Create a proof from the round polynomials.
    #[must_use]
    pub fn new(round_polys: Vec<RoundPoly<F>>) -> Self {
        Self { round_polys }
    }

    /// The round polynomials (one per variable).
    #[must_use]
    pub fn round_polys(&self) -> &[RoundPoly<F>] {
        &self.round_polys
    }
}
