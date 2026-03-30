//! Merkle tree commitment scheme.
//!
//! Commits to a vector of field elements by hashing each as a
//! leaf, building a binary hash tree, and exposing the root as
//! the binding commitment.  Opening proofs are sibling paths
//! from leaf to root.

use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::field::FieldBytes;

/// A Merkle tree root hash: the binding commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MerkleRoot([u8; 32]);

impl MerkleRoot {
    /// The raw 32-byte root hash.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A Merkle opening proof: sibling hashes from leaf to root.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    leaf_index: usize,
    siblings: Vec<[u8; 32]>,
}

impl MerkleProof {
    /// The index of the opened leaf.
    #[must_use]
    pub fn leaf_index(&self) -> usize {
        self.leaf_index
    }

    /// The sibling hashes along the path to the root.
    #[must_use]
    pub fn siblings(&self) -> &[[u8; 32]] {
        &self.siblings
    }
}

/// A Merkle tree over field element leaves.
///
/// The tree is stored as a flat array where `nodes[1]` is the
/// root, `nodes[2i]` and `nodes[2i+1]` are children of `nodes[i]`,
/// and leaves occupy `nodes[n..2n]` where `n = 2^depth`.
///
/// # Examples
///
/// ```
/// use plonkish_cat::F101;
/// use proof_cat::commit::merkle::MerkleTree;
///
/// let values = [F101::new(10), F101::new(20), F101::new(30), F101::new(40)];
/// let tree = MerkleTree::from_field_values(&values);
///
/// // Open leaf 2 and verify the opening.
/// let proof = tree.open(2)?;
/// assert!(MerkleTree::verify_opening(
///     &tree.root(), 2, &F101::new(30), &proof,
/// ));
///
/// // A wrong value fails verification.
/// assert!(!MerkleTree::verify_opening(
///     &tree.root(), 2, &F101::new(99), &proof,
/// ));
/// # Ok::<(), proof_cat::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// Flat array: index 0 unused, index 1 = root, leaves at [n..2n).
    nodes: Vec<[u8; 32]>,
    /// Tree depth (number of levels below root).
    depth: usize,
    /// Number of actual (non-padding) leaves.
    leaf_count: usize,
}

/// Hash a leaf value with its index for domain separation.
fn hash_leaf(index: usize, value_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"leaf:");
    hasher.update(index.to_le_bytes());
    hasher.update(value_bytes);
    hasher.finalize().into()
}

/// Hash a padding leaf.
fn hash_padding(index: usize) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"padding:");
    hasher.update(index.to_le_bytes());
    hasher.finalize().into()
}

/// Hash two children into a parent node.
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Compute the next power of two >= n (minimum 1).
fn next_power_of_two(n: usize) -> usize {
    if n <= 1 { 1 } else { n.next_power_of_two() }
}

impl MerkleTree {
    /// Build a Merkle tree from a slice of field elements.
    ///
    /// Pads to the next power of two with distinct padding leaves.
    #[must_use]
    pub fn from_field_values<F: FieldBytes>(values: &[F]) -> Self {
        let leaf_count = values.len();
        let n = next_power_of_two(leaf_count);
        // Safety: trailing_zeros of a usize fits in usize on all platforms.
        let depth = usize::try_from(n.trailing_zeros()).unwrap_or(0);

        // Allocate flat array: 2*n entries, index 0 unused.
        // Leaves at indices [n..2n).
        let leaf_hashes: Vec<[u8; 32]> = (0..n)
            .map(|i| {
                if i < leaf_count {
                    hash_leaf(i, &values[i].to_le_bytes())
                } else {
                    hash_padding(i)
                }
            })
            .collect();

        // Build the flat node array.
        // Start with 2*n zeros, fill leaves, then compute parents.
        let nodes_len = 2 * n;
        let zeroed: Vec<[u8; 32]> = (0..nodes_len).map(|_| [0u8; 32]).collect();

        // Place leaves at positions [n..2n).
        let with_leaves: Vec<[u8; 32]> = zeroed
            .iter()
            .enumerate()
            .map(|(idx, zero)| {
                if idx >= n && idx < 2 * n {
                    leaf_hashes[idx - n]
                } else {
                    *zero
                }
            })
            .collect();

        // Build internal nodes from bottom up: levels from (n-1) down to 1.
        // Each parent[i] = hash(child[2i], child[2i+1]).
        // We fold from the deepest internal level upward.
        let nodes = (1..=depth).fold(with_leaves, |acc, level_from_bottom| {
            // Nodes at this level: indices [start, end).
            let start = n >> level_from_bottom;
            let end = n >> (level_from_bottom - 1);
            (0..acc.len())
                .map(|idx| {
                    if idx >= start && idx < end {
                        hash_pair(&acc[idx * 2], &acc[idx * 2 + 1])
                    } else {
                        acc[idx]
                    }
                })
                .collect()
        });

        Self {
            nodes,
            depth,
            leaf_count,
        }
    }

    /// The root commitment.
    #[must_use]
    pub fn root(&self) -> MerkleRoot {
        if self.nodes.len() > 1 {
            MerkleRoot(self.nodes[1])
        } else {
            MerkleRoot([0u8; 32])
        }
    }

    /// The number of actual (non-padding) leaves.
    #[must_use]
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Generate an opening proof for the leaf at `index`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LeafIndexOutOfBounds`] if `index >= leaf_count`.
    pub fn open(&self, index: usize) -> Result<MerkleProof, Error> {
        if index >= self.leaf_count {
            Err(Error::LeafIndexOutOfBounds {
                index,
                leaf_count: self.leaf_count,
            })
        } else {
            let n = 1usize << self.depth;
            // Collect siblings from leaf position up to the root.
            let siblings = (0..self.depth)
                .scan(n + index, |pos, _| {
                    let sibling_pos = *pos ^ 1;
                    let sibling = self.nodes[sibling_pos];
                    *pos /= 2;
                    Some(sibling)
                })
                .collect();
            Ok(MerkleProof {
                leaf_index: index,
                siblings,
            })
        }
    }

    /// Verify an opening proof against a root and leaf value.
    ///
    /// Recomputes the root from the leaf hash and sibling path,
    /// then checks it matches the expected root.
    #[must_use]
    pub fn verify_opening<F: FieldBytes>(
        root: &MerkleRoot,
        index: usize,
        value: &F,
        proof: &MerkleProof,
    ) -> bool {
        let leaf_hash = hash_leaf(index, &value.to_le_bytes());
        let n = 1usize << proof.siblings.len();
        let computed_root = proof
            .siblings
            .iter()
            .enumerate()
            .fold((leaf_hash, n + index), |(current, pos), (_, sibling)| {
                let parent = if pos % 2 == 0 {
                    hash_pair(&current, sibling)
                } else {
                    hash_pair(sibling, &current)
                };
                (parent, pos / 2)
            })
            .0;
        computed_root == root.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::BabyBear;
    use plonkish_cat::F101;

    #[test]
    fn single_leaf_roundtrip() -> Result<(), Error> {
        let tree = MerkleTree::from_field_values(&[F101::new(42)]);
        let proof = tree.open(0)?;
        assert!(MerkleTree::verify_opening(
            &tree.root(),
            0,
            &F101::new(42),
            &proof
        ));
        Ok(())
    }

    #[test]
    fn two_leaf_roundtrip() -> Result<(), Error> {
        let values = [BabyBear::new(10), BabyBear::new(20)];
        let tree = MerkleTree::from_field_values(&values);
        let proof0 = tree.open(0)?;
        let proof1 = tree.open(1)?;
        assert!(MerkleTree::verify_opening(
            &tree.root(),
            0,
            &BabyBear::new(10),
            &proof0
        ));
        assert!(MerkleTree::verify_opening(
            &tree.root(),
            1,
            &BabyBear::new(20),
            &proof1
        ));
        Ok(())
    }

    #[test]
    fn tampered_value_fails() -> Result<(), Error> {
        let tree = MerkleTree::from_field_values(&[F101::new(42)]);
        let proof = tree.open(0)?;
        // Wrong value:
        assert!(!MerkleTree::verify_opening(
            &tree.root(),
            0,
            &F101::new(99),
            &proof
        ));
        Ok(())
    }

    #[test]
    fn out_of_bounds_open_fails() {
        let tree = MerkleTree::from_field_values(&[F101::new(1), F101::new(2)]);
        assert!(tree.open(2).is_err());
    }

    #[test]
    fn four_leaves() -> Result<(), Error> {
        let values = [
            BabyBear::new(1),
            BabyBear::new(2),
            BabyBear::new(3),
            BabyBear::new(4),
        ];
        let tree = MerkleTree::from_field_values(&values);
        (0..4).try_for_each(|i| {
            let proof = tree.open(i)?;
            assert!(
                MerkleTree::verify_opening(&tree.root(), i, &values[i], &proof),
                "failed at leaf {i}"
            );
            Ok(())
        })
    }
}
