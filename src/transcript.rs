//! Fiat-Shamir transcript for non-interactive proofs.
//!
//! The [`Transcript`] accumulates protocol messages (absorb) and
//! produces verifier challenges (squeeze) deterministically via
//! SHA-256.  It is functional: each operation consumes the
//! transcript and returns a new one, following the same pattern
//! as [`WireAllocator`](plonkish_cat::WireAllocator).

use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::field::FieldBytes;

/// A Fiat-Shamir transcript.
///
/// Operations consume `self` and return a new transcript,
/// ensuring the hash state evolves deterministically.
/// This follows the same functional-update pattern as
/// [`WireAllocator`](plonkish_cat::WireAllocator).
///
/// # Examples
///
/// ```
/// use proof_cat::{BabyBear, Transcript};
///
/// // Create a transcript, absorb some data, squeeze a challenge.
/// let transcript = Transcript::new(b"my-protocol")
///     .absorb_field(&BabyBear::new(42));
/// let (challenge, _transcript): (BabyBear, _) =
///     transcript.squeeze_challenge()?;
///
/// // The challenge is deterministic: same inputs produce
/// // the same challenge every time.
/// # Ok::<(), proof_cat::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct Transcript {
    state: Vec<u8>,
}

impl Transcript {
    /// Create a new transcript with a domain separation label.
    #[must_use]
    pub fn new(label: &[u8]) -> Self {
        Self {
            state: label.to_vec(),
        }
    }

    /// Absorb raw bytes into the transcript.
    #[must_use]
    pub fn absorb_bytes(self, data: &[u8]) -> Self {
        Self {
            state: self
                .state
                .into_iter()
                .chain(data.iter().copied())
                .collect(),
        }
    }

    /// Absorb a field element into the transcript.
    #[must_use]
    pub fn absorb_field<F: FieldBytes>(self, elem: &F) -> Self {
        self.absorb_bytes(&elem.to_le_bytes())
    }

    /// Squeeze a challenge field element from the transcript.
    ///
    /// Hashes the current state with SHA-256, interprets the
    /// output as a field element, and returns the challenge
    /// along with an updated transcript.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidFieldEncoding`] if the hash output
    /// cannot be interpreted as a field element.
    pub fn squeeze_challenge<F: FieldBytes>(self) -> Result<(F, Self), Error> {
        let digest = Sha256::digest(&self.state);
        let challenge = F::from_le_bytes(digest.as_slice())?;
        let new_state = self
            .state
            .into_iter()
            .chain(digest.iter().copied())
            .collect();
        Ok((challenge, Self { state: new_state }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::BabyBear;
    use plonkish_cat::F101;

    #[test]
    fn deterministic_challenges() -> Result<(), Error> {
        let t1 = Transcript::new(b"test")
            .absorb_field(&BabyBear::new(42));
        let t2 = Transcript::new(b"test")
            .absorb_field(&BabyBear::new(42));
        let (c1, _) = t1.squeeze_challenge::<BabyBear>()?;
        let (c2, _) = t2.squeeze_challenge::<BabyBear>()?;
        assert_eq!(c1, c2);
        Ok(())
    }

    #[test]
    fn different_inputs_different_challenges() -> Result<(), Error> {
        let t1 = Transcript::new(b"test")
            .absorb_field(&BabyBear::new(1));
        let t2 = Transcript::new(b"test")
            .absorb_field(&BabyBear::new(2));
        let (c1, _) = t1.squeeze_challenge::<BabyBear>()?;
        let (c2, _) = t2.squeeze_challenge::<BabyBear>()?;
        assert_ne!(c1, c2);
        Ok(())
    }

    #[test]
    fn absorb_order_matters() -> Result<(), Error> {
        let t1 = Transcript::new(b"test")
            .absorb_field(&F101::new(1))
            .absorb_field(&F101::new(2));
        let t2 = Transcript::new(b"test")
            .absorb_field(&F101::new(2))
            .absorb_field(&F101::new(1));
        let (c1, _) = t1.squeeze_challenge::<F101>()?;
        let (c2, _) = t2.squeeze_challenge::<F101>()?;
        assert_ne!(c1, c2);
        Ok(())
    }

    #[test]
    fn label_matters() -> Result<(), Error> {
        let t1 = Transcript::new(b"label_a")
            .absorb_field(&BabyBear::new(42));
        let t2 = Transcript::new(b"label_b")
            .absorb_field(&BabyBear::new(42));
        let (c1, _) = t1.squeeze_challenge::<BabyBear>()?;
        let (c2, _) = t2.squeeze_challenge::<BabyBear>()?;
        assert_ne!(c1, c2);
        Ok(())
    }
}
