//! Sumcheck verifier.
//!
//! Checks a [`SumcheckProof`] by replaying the transcript,
//! verifying each round's consistency, and returning the
//! final evaluation claim and challenge vector.

use crate::error::Error;
use crate::field::FieldBytes;
use crate::poly::NumVars;
use crate::transcript::Transcript;

use super::protocol::SumcheckProof;

/// Verifier state threaded through the round fold.
struct VerifierState<F: plonkish_cat::Field> {
    current_claim: F,
    transcript: Transcript,
    challenges: Vec<F>,
}

/// Run the sumcheck verifier.
///
/// Checks each round polynomial against the running claim:
/// `s_i(0) + s_i(1) == current_claim`.  Then squeezes a
/// challenge and updates the claim to `s_i(r_i)`.
///
/// Returns `(final_eval_claim, challenge_vector, transcript)`.
/// The caller must independently verify that the polynomial
/// evaluates to `final_eval_claim` at the challenge vector.
///
/// # Errors
///
/// Returns [`Error::RoundCountMismatch`] if the proof has the
/// wrong number of rounds, or [`Error::SumcheckFinalMismatch`]
/// if any round check fails.
///
/// # Examples
///
/// ```
/// use plonkish_cat::F101;
/// use proof_cat::{
///     MultilinearPoly, NumVars, SumcheckClaim, Transcript,
///     sumcheck_prove, sumcheck_verify,
/// };
///
/// let poly = MultilinearPoly::from_evals(vec![
///     F101::new(1), F101::new(2), F101::new(3), F101::new(4),
/// ])?;
/// let sum = poly.sum_over_boolean_hypercube();
/// let claim = SumcheckClaim::new(poly.clone(), sum.clone());
///
/// // Prover produces a proof.
/// let (proof, _, _) =
///     sumcheck_prove(&claim, Transcript::new(b"example"))?;
///
/// // Verifier checks it (using the same transcript label).
/// let (final_eval, challenges, _) = sumcheck_verify(
///     &proof,
///     &sum,
///     poly.num_vars(),
///     Transcript::new(b"example"),
/// )?;
///
/// // The final evaluation must match the polynomial at the
/// // challenge point.
/// assert_eq!(final_eval, poly.evaluate(&challenges)?);
/// # Ok::<(), proof_cat::Error>(())
/// ```
pub fn sumcheck_verify<F: FieldBytes>(
    proof: &SumcheckProof<F>,
    claimed_sum: &F,
    num_vars: NumVars,
    transcript: Transcript,
) -> Result<(F, Vec<F>, Transcript), Error> {
    if proof.round_polys().len() == num_vars.count() {
        let initial = VerifierState {
            current_claim: claimed_sum.clone(),
            transcript,
            challenges: Vec::with_capacity(num_vars.count()),
        };

        let final_state =
            proof
                .round_polys()
                .iter()
                .try_fold(initial, |state, round_poly| {
                    // Check: s(0) + s(1) == current_claim.
                    let sum = round_poly.eval_zero().clone() + round_poly.eval_one().clone();
                    if sum == state.current_claim {
                        // Absorb round polynomial (same order as prover).
                        let transcript = state
                            .transcript
                            .absorb_field(round_poly.eval_zero())
                            .absorb_field(round_poly.eval_one());

                        // Squeeze challenge (same as prover).
                        let (challenge, transcript): (F, Transcript) =
                            transcript.squeeze_challenge()?;

                        // New claim: s(r_i) via linear interpolation.
                        let new_claim = round_poly.evaluate(&challenge);

                        let challenges = state
                            .challenges
                            .into_iter()
                            .chain(core::iter::once(challenge))
                            .collect();

                        Ok(VerifierState {
                            current_claim: new_claim,
                            transcript,
                            challenges,
                        })
                    } else {
                        Err(Error::SumcheckFinalMismatch)
                    }
                })?;

        Ok((
            final_state.current_claim,
            final_state.challenges,
            final_state.transcript,
        ))
    } else {
        Err(Error::RoundCountMismatch {
            expected: num_vars.count(),
            actual: proof.round_polys().len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poly::MultilinearPoly;
    use crate::sumcheck::protocol::SumcheckClaim;
    use crate::sumcheck::prover::sumcheck_prove;
    use plonkish_cat::{F101, Field};

    #[test]
    fn prover_verifier_agree_on_zero_poly() -> Result<(), Error> {
        let poly =
            MultilinearPoly::from_evals(vec![F101::zero(), F101::zero()])?;
        let claim = SumcheckClaim::new(poly.clone(), F101::zero());

        let prover_transcript = Transcript::new(b"test");
        let (proof, prover_challenges, _) =
            sumcheck_prove(&claim, prover_transcript)?;

        let verifier_transcript = Transcript::new(b"test");
        let (final_eval, verifier_challenges, _) = sumcheck_verify(
            &proof,
            &F101::zero(),
            poly.num_vars(),
            verifier_transcript,
        )?;

        assert_eq!(prover_challenges, verifier_challenges);
        // The final eval should match the polynomial evaluated at challenges.
        let expected = poly.evaluate(&verifier_challenges)?;
        assert_eq!(final_eval, expected);
        Ok(())
    }

    #[test]
    fn prover_verifier_agree_on_two_var() -> Result<(), Error> {
        let poly = MultilinearPoly::from_evals(vec![
            F101::new(1),
            F101::new(2),
            F101::new(3),
            F101::new(4),
        ])?;
        let sum = poly.sum_over_boolean_hypercube();
        let claim = SumcheckClaim::new(poly.clone(), sum.clone());

        let (proof, prover_challenges, _) =
            sumcheck_prove(&claim, Transcript::new(b"test"))?;

        let (final_eval, verifier_challenges, _) = sumcheck_verify(
            &proof,
            &sum,
            poly.num_vars(),
            Transcript::new(b"test"),
        )?;

        assert_eq!(prover_challenges, verifier_challenges);
        let expected = poly.evaluate(&verifier_challenges)?;
        assert_eq!(final_eval, expected);
        Ok(())
    }

    #[test]
    fn wrong_claimed_sum_rejected() -> Result<(), Error> {
        let poly = MultilinearPoly::from_evals(vec![
            F101::new(1),
            F101::new(2),
            F101::new(3),
            F101::new(4),
        ])?;
        // Correct sum is 10, claim 99.
        let claim = SumcheckClaim::new(poly.clone(), F101::new(10));
        let (proof, _, _) =
            sumcheck_prove(&claim, Transcript::new(b"test"))?;

        // Verify with wrong claimed sum.
        let result = sumcheck_verify(
            &proof,
            &F101::new(99),
            poly.num_vars(),
            Transcript::new(b"test"),
        );
        assert!(result.is_err());
        Ok(())
    }
}
