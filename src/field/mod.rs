//! Field implementations and serialization.
//!
//! Provides [`BabyBear`], a prime field with characteristic `2^31 - 1`,
//! and the [`FieldBytes`] trait for transcript serialization.

pub mod baby_bear;
pub mod serialize;

pub use baby_bear::BabyBear;
pub use serialize::FieldBytes;
