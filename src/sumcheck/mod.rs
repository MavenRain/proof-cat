//! The sumcheck interactive proof protocol.
//!
//! Proves claims of the form `sum_{x in {0,1}^n} g(x) = v`
//! where `g` is a multilinear polynomial.  The protocol runs
//! in `n` rounds, reducing verification to a single evaluation
//! of `g` at a random point.
//!
//! - [`prover::sumcheck_prove`] produces a [`SumcheckProof`].
//! - [`verifier::sumcheck_verify`] checks the proof and returns
//!   the final evaluation claim and challenge vector.

pub mod protocol;
pub mod prover;
pub mod verifier;

pub use protocol::{RoundPoly, SumcheckClaim, SumcheckProof};
pub use prover::sumcheck_prove;
pub use verifier::sumcheck_verify;
