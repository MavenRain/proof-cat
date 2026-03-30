//! Polynomial commitment schemes.
//!
//! Provides the [`MerkleTree`] commitment scheme for binding
//! a prover to a vector of field elements.  Future versions
//! will add additional schemes (e.g., `BaseFold`, FRI) as
//! natural transformations of the commitment functor.

pub mod merkle;

pub use merkle::{MerkleProof, MerkleRoot, MerkleTree};
