//! Project-wide error type.

/// All errors that can arise in proof-cat.
#[derive(Debug)]
pub enum Error {
    /// An error propagated from plonkish-cat.
    Plonkish(plonkish_cat::Error),
    /// Witness length does not match the wire count.
    WitnessSizeMismatch {
        /// The number of wires expected.
        expected: usize,
        /// The number of wire values provided.
        actual: usize,
    },
    /// A constraint was not satisfied by the witness.
    UnsatisfiedConstraint {
        /// The zero-based index of the failing constraint.
        index: usize,
    },
    /// Sumcheck round count does not match the number of variables.
    RoundCountMismatch {
        /// The expected number of rounds.
        expected: usize,
        /// The actual number of rounds in the proof.
        actual: usize,
    },
    /// Sumcheck final evaluation check failed.
    SumcheckFinalMismatch,
    /// Merkle opening proof does not match the committed root.
    MerkleVerificationFailed,
    /// Polynomial evaluation point has wrong dimension.
    DimensionMismatch {
        /// The expected number of variables.
        expected: usize,
        /// The actual dimension of the point.
        actual: usize,
    },
    /// Constraint set is empty; nothing to prove.
    EmptyConstraintSet,
    /// A value is not a power of two where one was required.
    NotPowerOfTwo {
        /// The non-power-of-two value.
        value: usize,
    },
    /// Field element could not be decoded from bytes.
    InvalidFieldEncoding,
    /// Leaf index out of bounds for the Merkle tree.
    LeafIndexOutOfBounds {
        /// The requested index.
        index: usize,
        /// The number of leaves.
        leaf_count: usize,
    },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Plonkish(e) => write!(f, "plonkish-cat error: {e}"),
            Self::WitnessSizeMismatch { expected, actual } => {
                write!(f, "witness size mismatch: expected {expected}, got {actual}")
            }
            Self::UnsatisfiedConstraint { index } => {
                write!(f, "constraint {index} not satisfied by witness")
            }
            Self::RoundCountMismatch { expected, actual } => {
                write!(
                    f,
                    "sumcheck round count mismatch: expected {expected}, got {actual}"
                )
            }
            Self::SumcheckFinalMismatch => {
                write!(f, "sumcheck final evaluation does not match claim")
            }
            Self::MerkleVerificationFailed => {
                write!(f, "Merkle opening verification failed")
            }
            Self::DimensionMismatch { expected, actual } => {
                write!(
                    f,
                    "dimension mismatch: expected {expected} variables, got {actual}"
                )
            }
            Self::EmptyConstraintSet => write!(f, "constraint set is empty"),
            Self::NotPowerOfTwo { value } => {
                write!(f, "{value} is not a power of two")
            }
            Self::InvalidFieldEncoding => write!(f, "invalid field element encoding"),
            Self::LeafIndexOutOfBounds { index, leaf_count } => {
                write!(
                    f,
                    "leaf index {index} out of bounds (tree has {leaf_count} leaves)"
                )
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Plonkish(e) => Some(e),
            Self::WitnessSizeMismatch { .. }
            | Self::UnsatisfiedConstraint { .. }
            | Self::RoundCountMismatch { .. }
            | Self::SumcheckFinalMismatch
            | Self::MerkleVerificationFailed
            | Self::DimensionMismatch { .. }
            | Self::EmptyConstraintSet
            | Self::NotPowerOfTwo { .. }
            | Self::InvalidFieldEncoding
            | Self::LeafIndexOutOfBounds { .. } => None,
        }
    }
}

impl From<plonkish_cat::Error> for Error {
    fn from(e: plonkish_cat::Error) -> Self {
        Self::Plonkish(e)
    }
}
