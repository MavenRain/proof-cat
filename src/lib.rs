//! proof-cat: sumcheck-based proving backend for plonkish-cat.
//!
//! Given a [`ConstraintSet`](plonkish_cat::ConstraintSet) (the
//! output of `plonkish_cat::compile`) and a satisfying
//! [`Witness`](prove::Witness), this crate produces a
//! cryptographic [`Proof`](prove::Proof) that the witness is
//! valid, without the verifier needing to know the witness.
//!
//! # Architecture
//!
//! ```text
//! plonkish_cat::compile(graph, path) -> ConstraintSet<F>
//!                                            |
//!                            proof_cat::prove(constraints, witness)
//!                                            |
//!                                        Proof<F>
//!                                            |
//!                            proof_cat::verify(constraints, proof)
//!                                            |
//!                                       Ok(true)
//! ```
//!
//! Internally the proof uses the **sumcheck protocol** over
//! multilinear polynomials, with a **Merkle tree** commitment
//! for the witness values.
//!
//! # Modules
//!
//! - [`field`] -- `BabyBear` prime field and serialization trait.
//! - [`poly`] -- Multilinear polynomial evaluation tables.
//! - [`transcript`] -- Fiat-Shamir non-interactive transcript.
//! - [`commit`] -- Merkle tree commitment scheme.
//! - [`sumcheck`] -- Sumcheck prover and verifier.
//! - [`prove`] -- End-to-end proof generation and verification.

pub mod commit;
pub mod error;
pub mod field;
pub mod poly;
pub mod prove;
pub mod sumcheck;
pub mod transcript;

pub use error::Error;
pub use field::{BabyBear, FieldBytes};
pub use poly::{MultilinearPoly, NumVars};
pub use prove::{Proof, Witness, prove, verify};
pub use sumcheck::{SumcheckClaim, SumcheckProof, sumcheck_prove, sumcheck_verify};
pub use transcript::Transcript;
