//! Field element serialization for the Fiat-Shamir transcript.
//!
//! [`FieldBytes`] extends [`Field`](plonkish_cat::Field) with
//! byte-level serialization, enabling field elements to be
//! absorbed into and squeezed from a [`Transcript`](crate::transcript::Transcript).

use crate::error::Error;
use plonkish_cat::{F101, Field};

use super::baby_bear::BabyBear;

/// Byte serialization for field elements.
///
/// Required by the transcript to absorb and squeeze field elements.
pub trait FieldBytes: Field {
    /// Serialize this element to little-endian bytes.
    #[must_use]
    fn to_le_bytes(&self) -> Vec<u8>;

    /// Deserialize from little-endian bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidFieldEncoding`] if the bytes cannot
    /// be interpreted as a valid field element.
    fn from_le_bytes(bytes: &[u8]) -> Result<Self, Error>;
}

impl FieldBytes for BabyBear {
    fn to_le_bytes(&self) -> Vec<u8> {
        self.value().to_le_bytes()[..4].to_vec()
    }

    fn from_le_bytes(bytes: &[u8]) -> Result<Self, Error> {
        (bytes.len() >= 4)
            .then(|| {
                let arr: [u8; 4] = [bytes[0], bytes[1], bytes[2], bytes[3]];
                Self::new(u64::from(u32::from_le_bytes(arr)))
            })
            .ok_or(Error::InvalidFieldEncoding)
    }
}

impl FieldBytes for F101 {
    fn to_le_bytes(&self) -> Vec<u8> {
        vec![u8::try_from(self.value()).unwrap_or(0)]
    }

    fn from_le_bytes(bytes: &[u8]) -> Result<Self, Error> {
        bytes
            .first()
            .map(|&b| Self::new(u64::from(b)))
            .ok_or(Error::InvalidFieldEncoding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baby_bear_roundtrip() -> Result<(), Error> {
        let a = BabyBear::new(1_234_567);
        let bytes = a.to_le_bytes();
        let b = BabyBear::from_le_bytes(&bytes)?;
        assert_eq!(a, b);
        Ok(())
    }

    #[test]
    fn f101_roundtrip() -> Result<(), Error> {
        let a = F101::new(42);
        let bytes = a.to_le_bytes();
        let b = F101::from_le_bytes(&bytes)?;
        assert_eq!(a, b);
        Ok(())
    }

    #[test]
    fn baby_bear_zero_roundtrip() -> Result<(), Error> {
        let a = BabyBear::zero();
        let b = BabyBear::from_le_bytes(&a.to_le_bytes())?;
        assert_eq!(a, b);
        Ok(())
    }

    #[test]
    fn empty_bytes_fails() {
        let result = BabyBear::from_le_bytes(&[]);
        assert!(result.is_err());
    }
}
