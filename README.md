# proof-cat

Sumcheck-based proving backend for [plonkish-cat](https://github.com/MavenRain/plonkish-cat) circuits, built on [comp-cat-rs](https://github.com/MavenRain/comp-cat-rs).

Given a `ConstraintSet<F>` (the output of `plonkish_cat::compile`) and a satisfying witness, proof-cat produces a cryptographic proof that the witness is valid.  A verifier can check the proof without knowing the witness values.

## Architecture

```text
plonkish_cat::compile(graph, path)
         |
         v
  ConstraintSet<F>  +  Witness<F>
         |
    proof_cat::prove(constraints, witness)
         |
         v
      Proof<F>
         |
    proof_cat::verify(constraints, proof)
         |
         v
     Ok(true)
```

Internally, the proof uses the **sumcheck protocol** over multilinear polynomials, with a **Merkle tree** commitment binding the prover to the witness before challenges are generated.

## Modules

| Module | Purpose |
|--------|---------|
| `field` | `BabyBear` prime field (p = 2^31 - 1) and `FieldBytes` serialization trait |
| `poly` | `MultilinearPoly<F>`: evaluation tables on {0,1}^n with partial evaluation |
| `transcript` | Functional Fiat-Shamir transcript (SHA-256) for non-interactive proofs |
| `commit` | `MerkleTree`: hash-based commitment to field element vectors |
| `sumcheck` | Sumcheck prover and verifier for multilinear polynomial sums |
| `prove` | End-to-end `prove()` and `verify()` bridging `ConstraintSet` to sumcheck |

## Quick start

```rust
use plonkish_cat::{Constraint, ConstraintSet, Expression, Wire, F101};
use proof_cat::{Witness, prove, verify};

fn main() -> Result<(), proof_cat::Error> {
    // Define a constraint: w2 - w0 * w1 = 0  (multiplication gate).
    let expr = Expression::Wire(Wire::new(2))
        - Expression::Wire(Wire::new(0)) * Expression::Wire(Wire::new(1));
    let cs = ConstraintSet::empty()
        .with_constraint(Constraint::new(expr));

    // Provide a satisfying witness: 5 * 6 = 30.
    let witness = Witness::new(vec![F101::new(5), F101::new(6), F101::new(30)]);

    // Produce a proof.
    let proof = prove(&cs, &witness)?;

    // Verify the proof (no witness needed).
    assert!(verify(&cs, &proof)?);
    Ok(())
}
```

## How it works

### Proof protocol

1. **Flatten**: copy constraints become polynomial constraints (`w_a - w_b = 0`).
2. **Validate**: the prover checks that the witness satisfies every constraint.
3. **Commit**: the witness vector is committed via a Merkle tree.
4. **Evaluate**: each constraint is evaluated against the witness (all zeros for a valid witness).
5. **Multilinear extension**: the evaluation vector is padded to a power-of-two length and interpreted as a multilinear polynomial `g` over {0,1}^n.
6. **Sumcheck**: the prover runs the sumcheck protocol to prove `sum_{x in {0,1}^n} g(x) = 0`.
7. **Open**: the prover opens all wire values with Merkle proofs.
8. **Verify**: the verifier replays the transcript, checks sumcheck round consistency, verifies Merkle openings, re-evaluates the constraints, and confirms the final sumcheck claim.

### Sumcheck protocol

The sumcheck protocol proves claims of the form `sum_{x in {0,1}^n} g(x) = v` where `g` is a multilinear polynomial.  It runs in `n` rounds:

- **Round i**: the prover sends a degree-1 univariate `s_i(t)` summarizing the partial sum over remaining variables.  The verifier checks `s_i(0) + s_i(1)` equals the running claim, then sends a random challenge `r_i`.
- **After n rounds**: the verifier holds a random point `r = (r_1, ..., r_n)` and a claimed evaluation `g(r)`.  The verifier checks this directly.

The Fiat-Shamir transcript makes the protocol non-interactive by deriving challenges from a SHA-256 hash of the protocol messages.

### Security properties

- **Binding**: the Merkle commitment prevents the prover from changing the witness after challenges are generated.
- **Soundness**: a cheating prover (with a non-satisfying witness) must guess the verifier's random challenges, which happens with negligible probability over a large field.
- **Not zero-knowledge** (v0.1): the prover opens all wire values.  A future version will replace Merkle openings with polynomial commitment evaluations for full zero-knowledge.

## Fields

proof-cat provides `BabyBear` (p = 2^31 - 1), a Mersenne prime field used in modern proof systems (Plonky3, SP1).  Any type implementing `plonkish_cat::Field` plus `proof_cat::FieldBytes` (byte serialization) can be used.

## Building

```bash
cargo build
cargo test
RUSTFLAGS="-D warnings" cargo clippy
cargo doc --no-deps --open
```

## Dependencies

- **plonkish-cat**: circuit constraint infrastructure (`Field`, `ConstraintSet`, `Expression`, `Wire`)
- **sha2**: SHA-256 for the Fiat-Shamir transcript

## Roadmap

- **v0.1** (current): sumcheck + Merkle commitment, binding but not zero-knowledge
- **v0.2**: polynomial commitment scheme (BaseFold or FRI) for succinct verification
- **v0.3**: full zero-knowledge via hiding commitments; `NatTrans` from comp-cat-rs for PCS backend polymorphism

## License

MIT
