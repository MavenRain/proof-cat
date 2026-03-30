//! Sumcheck prover.
//!
//! Produces a [`SumcheckProof`] for a [`SumcheckClaim`] by
//! iterating over variables, computing round polynomials,
//! absorbing them into the transcript, and binding each
//! variable to the resulting challenge.

use crate::error::Error;
use crate::field::FieldBytes;
use crate::transcript::Transcript;

use super::protocol::{RoundPoly, SumcheckClaim, SumcheckProof};

/// Prover state threaded through the round fold.
struct ProverState<F: plonkish_cat::Field> {
    evals: Vec<F>,
    transcript: Transcript,
    round_polys: Vec<RoundPoly<F>>,
    challenges: Vec<F>,
}

/// Run the sumcheck prover, producing a proof and the challenge vector.
///
/// Given a claim that `sum_{x in {0,1}^n} poly(x) = claimed_sum`,
/// the prover executes `n` rounds.  Each round:
/// 1. Computes `s(0)` and `s(1)` by summing the first and second
///    halves of the current evaluation table.
/// 2. Absorbs `s(0)`, `s(1)` into the transcript.
/// 3. Squeezes a challenge `r_i`.
/// 4. Binds the first variable to `r_i`, halving the eval table.
///
/// Returns `(proof, challenge_vector, final_transcript)`.
///
/// # Errors
///
/// Returns an error if the transcript fails to produce a challenge.
///
/// # Examples
///
/// ```
/// use plonkish_cat::F101;
/// use proof_cat::{MultilinearPoly, SumcheckClaim, Transcript, sumcheck_prove};
///
/// // f(x0, x1) with sum = 10.
/// let poly = MultilinearPoly::from_evals(vec![
///     F101::new(1), F101::new(2), F101::new(3), F101::new(4),
/// ])?;
/// let claim = SumcheckClaim::new(poly, F101::new(10));
///
/// let (proof, challenges, _transcript) =
///     sumcheck_prove(&claim, Transcript::new(b"example"))?;
///
/// assert_eq!(proof.round_polys().len(), 2);
/// assert_eq!(challenges.len(), 2);
/// # Ok::<(), proof_cat::Error>(())
/// ```
pub fn sumcheck_prove<F: FieldBytes>(
    claim: &SumcheckClaim<F>,
    transcript: Transcript,
) -> Result<(SumcheckProof<F>, Vec<F>, Transcript), Error> {
    let num_rounds = claim.poly().num_vars().count();

    let initial = ProverState {
        evals: claim.poly().evals().to_vec(),
        transcript,
        round_polys: Vec::with_capacity(num_rounds),
        challenges: Vec::with_capacity(num_rounds),
    };

    let final_state = (0..num_rounds).try_fold(initial, |state, _| -> Result<ProverState<F>, Error> {
        let half = state.evals.len() / 2;

        // s(0) = sum of first half (variable = 0).
        let eval_zero = state.evals[..half]
            .iter()
            .cloned()
            .fold(F::zero(), |acc, v| acc + v);

        // s(1) = sum of second half (variable = 1).
        let eval_one = state.evals[half..]
            .iter()
            .cloned()
            .fold(F::zero(), |acc, v| acc + v);

        let round_poly = RoundPoly::new(eval_zero.clone(), eval_one.clone());

        // Absorb round polynomial into transcript.
        let transcript = state
            .transcript
            .absorb_field(&eval_zero)
            .absorb_field(&eval_one);

        // Squeeze challenge.
        let (challenge, transcript): (F, Transcript) = transcript.squeeze_challenge()?;

        // Bind first variable: new_evals[j] = evals[j]*(1-r) + evals[j+half]*r
        let new_evals: Vec<F> = (0..half)
            .map(|j| {
                let lo = state.evals[j].clone();
                let hi = state.evals[j + half].clone();
                lo * (F::one() - challenge.clone()) + hi * challenge.clone()
            })
            .collect();

        let round_polys = state
            .round_polys
            .into_iter()
            .chain(core::iter::once(round_poly))
            .collect();

        let challenges = state
            .challenges
            .into_iter()
            .chain(core::iter::once(challenge))
            .collect();

        Ok(ProverState {
            evals: new_evals,
            transcript,
            round_polys,
            challenges,
        })
    })?;

    Ok((
        SumcheckProof::new(final_state.round_polys),
        final_state.challenges,
        final_state.transcript,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poly::MultilinearPoly;
    use plonkish_cat::{F101, Field};

    #[test]
    fn zero_polynomial_sum_is_zero() -> Result<(), Error> {
        let poly = MultilinearPoly::from_evals(vec![F101::zero(), F101::zero()])?;
        let claim = SumcheckClaim::new(poly, F101::zero());
        let transcript = Transcript::new(b"test");
        let (proof, challenges, _) = sumcheck_prove(&claim, transcript)?;
        assert_eq!(proof.round_polys().len(), 1);
        assert_eq!(challenges.len(), 1);
        // s(0) + s(1) should equal claimed sum (0).
        let rp = &proof.round_polys()[0];
        assert_eq!(
            rp.eval_zero().clone() + rp.eval_one().clone(),
            F101::zero()
        );
        Ok(())
    }

    #[test]
    fn constant_polynomial() -> Result<(), Error> {
        // f(0) = 5, f(1) = 5 => sum = 10
        let poly = MultilinearPoly::from_evals(vec![F101::new(5), F101::new(5)])?;
        let claim = SumcheckClaim::new(poly, F101::new(10));
        let transcript = Transcript::new(b"test");
        let (proof, _, _) = sumcheck_prove(&claim, transcript)?;
        let rp = &proof.round_polys()[0];
        assert_eq!(
            rp.eval_zero().clone() + rp.eval_one().clone(),
            F101::new(10)
        );
        Ok(())
    }

    #[test]
    fn two_variable_polynomial() -> Result<(), Error> {
        // f(0,0)=1, f(0,1)=2, f(1,0)=3, f(1,1)=4 => sum = 10
        let poly = MultilinearPoly::from_evals(vec![
            F101::new(1),
            F101::new(2),
            F101::new(3),
            F101::new(4),
        ])?;
        let claim = SumcheckClaim::new(poly, F101::new(10));
        let transcript = Transcript::new(b"test");
        let (proof, challenges, _) = sumcheck_prove(&claim, transcript)?;
        assert_eq!(proof.round_polys().len(), 2);
        assert_eq!(challenges.len(), 2);
        // Big-endian: evals = [f(0,0), f(0,1), f(1,0), f(1,1)] = [1, 2, 3, 4].
        // First round binds x0: s(0) = f(0,0)+f(0,1) = 3, s(1) = f(1,0)+f(1,1) = 7.
        let rp0 = &proof.round_polys()[0];
        assert_eq!(rp0.eval_zero().clone(), F101::new(3));
        assert_eq!(rp0.eval_one().clone(), F101::new(7));
        assert_eq!(
            rp0.eval_zero().clone() + rp0.eval_one().clone(),
            F101::new(10)
        );
        Ok(())
    }
}
