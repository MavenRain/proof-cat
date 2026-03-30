//! End-to-end proof generation and verification.
//!
//! Bridges plonkish-cat's [`ConstraintSet`] with the sumcheck
//! protocol: given a constraint set and a satisfying witness,
//! [`prove`] produces a [`Proof`]; [`verify`] checks it.
//!
//! The current protocol is binding but **not** zero-knowledge:
//! all wire values are opened via Merkle proofs.  A future
//! version will replace Merkle openings with polynomial
//! commitment evaluations for full zero-knowledge.

use plonkish_cat::{
    Constraint, ConstraintSet, Expression, Field, Wire,
};

use crate::commit::merkle::{MerkleProof, MerkleRoot, MerkleTree};
use crate::error::Error;
use crate::field::FieldBytes;
use crate::poly::MultilinearPoly;
use crate::sumcheck::{SumcheckClaim, SumcheckProof, sumcheck_prove, sumcheck_verify};
use crate::transcript::Transcript;

/// Domain separation label for the proof transcript.
const TRANSCRIPT_LABEL: &[u8] = b"proof-cat-v0.1";

// ── Types ────────────────────────────────────────────────────

/// A witness: wire values satisfying the constraint set.
///
/// Entry `i` is the value of [`Wire::new(i)`](plonkish_cat::Wire).
/// The vector must be long enough to cover every wire index
/// referenced by the constraint set.
///
/// # Examples
///
/// ```
/// use plonkish_cat::F101;
/// use proof_cat::Witness;
///
/// // Three wires: w0=3, w1=4, w2=7.
/// let w = Witness::new(vec![F101::new(3), F101::new(4), F101::new(7)]);
/// assert_eq!(w.values().len(), 3);
/// ```
#[derive(Debug, Clone)]
pub struct Witness<F: Field> {
    values: Vec<F>,
}

impl<F: Field> Witness<F> {
    /// Create a witness from a vector of wire values.
    #[must_use]
    pub fn new(values: Vec<F>) -> Self {
        Self { values }
    }

    /// The wire values.
    #[must_use]
    pub fn values(&self) -> &[F] {
        &self.values
    }

    /// Build an assignment closure for constraint evaluation.
    fn assignment(&self) -> impl Fn(Wire) -> Result<F, plonkish_cat::Error> + '_ {
        |wire| {
            self.values
                .get(wire.index())
                .cloned()
                .ok_or(plonkish_cat::Error::WireOutOfBounds {
                    wire_index: wire.index(),
                    allocated: self.values.len(),
                })
        }
    }
}

/// An opened wire value with its Merkle proof.
#[derive(Debug, Clone)]
pub struct WireOpening<F: Field> {
    wire_index: usize,
    value: F,
    merkle_proof: MerkleProof,
}

impl<F: Field> WireOpening<F> {
    /// The wire index.
    #[must_use]
    pub fn wire_index(&self) -> usize {
        self.wire_index
    }

    /// The opened value.
    #[must_use]
    pub fn value(&self) -> &F {
        &self.value
    }

    /// The Merkle proof.
    #[must_use]
    pub fn merkle_proof(&self) -> &MerkleProof {
        &self.merkle_proof
    }
}

/// A complete proof of constraint satisfaction.
#[derive(Debug, Clone)]
pub struct Proof<F: Field> {
    witness_commitment: MerkleRoot,
    sumcheck: SumcheckProof<F>,
    wire_openings: Vec<WireOpening<F>>,
}

impl<F: Field> Proof<F> {
    /// The Merkle root committing to the witness.
    #[must_use]
    pub fn witness_commitment(&self) -> &MerkleRoot {
        &self.witness_commitment
    }

    /// The sumcheck proof.
    #[must_use]
    pub fn sumcheck_proof(&self) -> &SumcheckProof<F> {
        &self.sumcheck
    }

    /// The opened wire values with Merkle proofs.
    #[must_use]
    pub fn wire_openings(&self) -> &[WireOpening<F>] {
        &self.wire_openings
    }
}

// ── Proving ──────────────────────────────────────────────────

/// Produce a proof that a witness satisfies a constraint set.
///
/// # Protocol
///
/// 1. Convert copy constraints to polynomial constraints.
/// 2. Validate the witness satisfies all constraints.
/// 3. Commit to the witness via a Merkle tree.
/// 4. Evaluate each constraint (all zero for valid witness).
/// 5. Build a multilinear polynomial from the evaluations.
/// 6. Run sumcheck to prove the evaluations sum to zero.
/// 7. Open all wire values with Merkle proofs.
///
/// # Errors
///
/// Returns an error if the witness does not satisfy the
/// constraints, or if any internal step fails.
///
/// # Examples
///
/// ```
/// use plonkish_cat::{Constraint, ConstraintSet, Expression, Wire, F101};
/// use proof_cat::{Witness, prove, verify};
///
/// // Constraint: w2 - w0 - w1 = 0  (addition gate).
/// let expr = Expression::Wire(Wire::new(2))
///     - Expression::Wire(Wire::new(0))
///     - Expression::Wire(Wire::new(1));
/// let cs = ConstraintSet::empty()
///     .with_constraint(Constraint::new(expr));
///
/// // Valid witness: 3 + 4 = 7.
/// let witness = Witness::new(vec![
///     F101::new(3), F101::new(4), F101::new(7),
/// ]);
///
/// let proof = prove(&cs, &witness)?;
/// assert!(verify(&cs, &proof)?);
/// # Ok::<(), proof_cat::Error>(())
/// ```
pub fn prove<F: FieldBytes>(
    constraints: &ConstraintSet<F>,
    witness: &Witness<F>,
) -> Result<Proof<F>, Error> {
    // 1. Flatten: convert copy constraints to polynomial form.
    let all_constraints = flatten_constraints(constraints);

    if all_constraints.is_empty() {
        Err(Error::EmptyConstraintSet)
    } else {
        // 2. Validate witness satisfies all constraints.
        validate_witness(&all_constraints, witness)?;

        // 3. Commit witness to Merkle tree.
        let tree = MerkleTree::from_field_values(witness.values());

        // 4. Evaluate each constraint (should all be zero).
        let evals = evaluate_constraints(&all_constraints, witness)?;

        // 5. Pad to power-of-two length and build MLE.
        let padded = pad_to_power_of_two(evals);
        let poly = MultilinearPoly::from_evals(padded)?;

        // 6. Initialize transcript and run sumcheck.
        let transcript = Transcript::new(TRANSCRIPT_LABEL)
            .absorb_bytes(tree.root().as_bytes())
            .absorb_bytes(&all_constraints.len().to_le_bytes());

        let (sumcheck, _, _) = sumcheck_prove(
            &SumcheckClaim::new(poly, F::zero()),
            transcript,
        )?;

        // 7. Open all wire values.
        let wire_openings: Result<Vec<WireOpening<F>>, Error> = (0..witness.values().len())
            .map(|i| {
                let merkle_proof = tree.open(i)?;
                Ok(WireOpening {
                    wire_index: i,
                    value: witness.values()[i].clone(),
                    merkle_proof,
                })
            })
            .collect();

        Ok(Proof {
            witness_commitment: tree.root(),
            sumcheck,
            wire_openings: wire_openings?,
        })
    }
}

// ── Verification ─────────────────────────────────────────────

/// Verify a proof of constraint satisfaction.
///
/// The verifier does not need the witness; it works entirely
/// from the [`Proof`] (which contains Merkle-opened wire values)
/// and the public [`ConstraintSet`].
///
/// # Protocol
///
/// 1. Flatten copy constraints to polynomial form.
/// 2. Replay the transcript and run the sumcheck verifier.
/// 3. Verify all Merkle openings against the committed root.
/// 4. Re-evaluate constraints from the opened wire values.
/// 5. Check the sumcheck final evaluation matches.
///
/// Returns `true` if the proof is valid.
///
/// # Errors
///
/// Returns an error if any verification step encounters
/// a structural problem (wrong round count, etc.).
///
/// # Examples
///
/// ```
/// use plonkish_cat::{Constraint, ConstraintSet, Expression, Wire, F101};
/// use proof_cat::{Witness, prove, verify};
///
/// // Constraint: w1 - w0 * w0 = 0  (squaring).
/// let expr = Expression::Wire(Wire::new(1))
///     - Expression::Wire(Wire::new(0)) * Expression::Wire(Wire::new(0));
/// let cs = ConstraintSet::empty()
///     .with_constraint(Constraint::new(expr));
///
/// // Witness: 7^2 = 49.
/// let proof = prove(
///     &cs,
///     &Witness::new(vec![F101::new(7), F101::new(49)]),
/// )?;
///
/// // Verification succeeds.
/// assert!(verify(&cs, &proof)?);
/// # Ok::<(), proof_cat::Error>(())
/// ```
pub fn verify<F: FieldBytes>(
    constraints: &ConstraintSet<F>,
    proof: &Proof<F>,
) -> Result<bool, Error> {
    // 1. Flatten constraints.
    let all_constraints = flatten_constraints(constraints);

    if all_constraints.is_empty() {
        Err(Error::EmptyConstraintSet)
    } else {
        // 2. Replay transcript and run sumcheck verifier.
        let padded_len = pad_to_power_of_two_len(all_constraints.len());
        let num_vars = usize::try_from(padded_len.trailing_zeros())
            .map_err(|_| Error::NotPowerOfTwo { value: padded_len })?;

        let transcript = Transcript::new(TRANSCRIPT_LABEL)
            .absorb_bytes(proof.witness_commitment.as_bytes())
            .absorb_bytes(&all_constraints.len().to_le_bytes());

        let (final_eval, challenges, _) = sumcheck_verify(
            &proof.sumcheck,
            &F::zero(),
            crate::poly::NumVars::new(num_vars),
            transcript,
        )?;

        // 3. Verify all Merkle openings.
        let all_openings_valid = proof.wire_openings.iter().all(|opening| {
            MerkleTree::verify_opening(
                &proof.witness_commitment,
                opening.wire_index,
                &opening.value,
                &opening.merkle_proof,
            )
        });

        if all_openings_valid {
            // 4. Build assignment from opened wire values.
            let assignment = build_assignment_from_openings(&proof.wire_openings);

            // 5. Re-evaluate constraints.
            let evals = evaluate_constraints_with(
                &all_constraints,
                &assignment,
            )?;
            let padded = pad_to_power_of_two(evals);
            let poly = MultilinearPoly::from_evals(padded)?;

            // 6. Check MLE evaluation at challenges matches sumcheck claim.
            let expected_eval = poly.evaluate(&challenges)?;
            Ok(expected_eval == final_eval)
        } else {
            Err(Error::MerkleVerificationFailed)
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────

/// Convert copy constraints to polynomial constraints and merge
/// with the existing polynomial constraints.
fn flatten_constraints<F: Field>(cs: &ConstraintSet<F>) -> Vec<Constraint<F>> {
    let polynomial: Vec<Constraint<F>> = cs.constraints().to_vec();
    let from_copies: Vec<Constraint<F>> = cs
        .copy_constraints()
        .iter()
        .map(|cc| {
            let expr = Expression::Wire(cc.left()) - Expression::Wire(cc.right());
            Constraint::new(expr)
        })
        .collect();
    polynomial
        .into_iter()
        .chain(from_copies)
        .collect()
}

/// Validate that the witness satisfies all constraints.
fn validate_witness<F: Field>(
    constraints: &[Constraint<F>],
    witness: &Witness<F>,
) -> Result<(), Error> {
    let assign = witness.assignment();
    constraints
        .iter()
        .enumerate()
        .try_for_each(|(i, c)| {
            c.is_satisfied(&assign)
                .map_err(Error::from)
                .and_then(|ok| {
                    if ok {
                        Ok(())
                    } else {
                        Err(Error::UnsatisfiedConstraint { index: i })
                    }
                })
        })
}

/// Evaluate all constraints against the witness.
fn evaluate_constraints<F: Field>(
    constraints: &[Constraint<F>],
    witness: &Witness<F>,
) -> Result<Vec<F>, Error> {
    let assign = witness.assignment();
    constraints
        .iter()
        .map(|c| c.expression().evaluate(&assign).map_err(Error::from))
        .collect()
}

/// Evaluate constraints against an opened-value assignment.
fn evaluate_constraints_with<F: Field>(
    constraints: &[Constraint<F>],
    assignment: &impl Fn(Wire) -> Result<F, plonkish_cat::Error>,
) -> Result<Vec<F>, Error> {
    constraints
        .iter()
        .map(|c| c.expression().evaluate(assignment).map_err(Error::from))
        .collect()
}

/// Build an assignment function from wire openings.
fn build_assignment_from_openings<F: Field>(
    openings: &[WireOpening<F>],
) -> impl Fn(Wire) -> Result<F, plonkish_cat::Error> + '_ {
    move |wire| {
        openings
            .iter()
            .find(|o| o.wire_index == wire.index())
            .map(|o| o.value.clone())
            .ok_or(plonkish_cat::Error::WireOutOfBounds {
                wire_index: wire.index(),
                allocated: openings.len(),
            })
    }
}

/// Pad a vector to the next power-of-two length with `F::zero()`.
fn pad_to_power_of_two<F: Field>(v: Vec<F>) -> Vec<F> {
    let target = pad_to_power_of_two_len(v.len());
    let padding_count = target - v.len();
    v.into_iter()
        .chain((0..padding_count).map(|_| F::zero()))
        .collect()
}

/// The next power of two >= n (minimum 1).
fn pad_to_power_of_two_len(n: usize) -> usize {
    if n <= 1 { 1 } else { n.next_power_of_two() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonkish_cat::{CopyConstraint, Expression, Wire, F101};

    #[test]
    fn add_gate_prove_verify() -> Result<(), Error> {
        // Circuit: add gate.  Wires: in0=w0, in1=w1, out=w2.
        // Constraint: w2 - w0 - w1 = 0.
        let expr =
            Expression::Wire(Wire::new(2))
                - Expression::Wire(Wire::new(0))
                - Expression::Wire(Wire::new(1));
        let cs = ConstraintSet::empty()
            .with_constraint(Constraint::new(expr));

        // Valid witness: 3 + 4 = 7.
        let witness = Witness::new(vec![
            F101::new(3),
            F101::new(4),
            F101::new(7),
        ]);
        let proof = prove(&cs, &witness)?;
        let valid = verify(&cs, &proof)?;
        assert!(valid);
        Ok(())
    }

    #[test]
    fn mul_gate_prove_verify() -> Result<(), Error> {
        // Constraint: w2 - w0 * w1 = 0.
        let expr = Expression::Wire(Wire::new(2))
            - Expression::Wire(Wire::new(0)) * Expression::Wire(Wire::new(1));
        let cs = ConstraintSet::empty()
            .with_constraint(Constraint::new(expr));

        // Valid witness: 5 * 6 = 30.
        let witness = Witness::new(vec![
            F101::new(5),
            F101::new(6),
            F101::new(30),
        ]);
        let proof = prove(&cs, &witness)?;
        assert!(verify(&cs, &proof)?);
        Ok(())
    }

    #[test]
    fn invalid_witness_rejected() {
        let expr =
            Expression::Wire(Wire::new(2))
                - Expression::Wire(Wire::new(0))
                - Expression::Wire(Wire::new(1));
        let cs = ConstraintSet::empty()
            .with_constraint(Constraint::new(expr));

        // Invalid: 3 + 4 != 8.
        let witness = Witness::new(vec![
            F101::new(3),
            F101::new(4),
            F101::new(8),
        ]);
        let result = prove(&cs, &witness);
        assert!(result.is_err());
    }

    #[test]
    fn copy_constraint_prove_verify() -> Result<(), Error> {
        // Copy constraint: w0 == w1.
        let cs = ConstraintSet::empty()
            .with_copy(CopyConstraint::new(Wire::new(0), Wire::new(1)));

        let witness = Witness::new(vec![F101::new(42), F101::new(42)]);
        let proof = prove(&cs, &witness)?;
        assert!(verify(&cs, &proof)?);
        Ok(())
    }

    #[test]
    fn copy_constraint_invalid_rejected() {
        let cs = ConstraintSet::empty()
            .with_copy(CopyConstraint::new(Wire::new(0), Wire::new(1)));

        let witness = Witness::new(vec![F101::new(1), F101::new(2)]);
        let result = prove(&cs, &witness);
        assert!(result.is_err());
    }

    #[test]
    fn const_gate_prove_verify() -> Result<(), Error> {
        // Constraint: w0 - 42 = 0.
        let expr = Expression::Wire(Wire::new(0)) - Expression::Constant(F101::new(42));
        let cs = ConstraintSet::empty()
            .with_constraint(Constraint::new(expr));

        let witness = Witness::new(vec![F101::new(42)]);
        let proof = prove(&cs, &witness)?;
        assert!(verify(&cs, &proof)?);
        Ok(())
    }
}
