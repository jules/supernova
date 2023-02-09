//! Defines the common functionality for any kind of program arithmetization to be used
//! in the SuperNova protocol.
//! Additionally, includes a model which defines this functionality for R1CS.

pub mod r1cs;

use ark_bls12_381::{Fq, G1Projective};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;

/// A foldable circuit representation.
pub trait Arithmetization: Sized {
    type ConstraintSystem;

    // Returns the latest IO hash.
    fn hash(&self) -> Fq;

    // Returns the current witness commitment.
    fn witness_commitment(&self) -> G1Projective;

    // Checks if the arithmetization is correct.
    fn is_satisfied(&self, generators: &[G1Projective]) -> bool;

    // Checks if the arithmetization is equivalent to the base case.
    fn is_zero(&self) -> bool;

    // Returns the circuit metadata used for hashing.
    fn params(&self) -> Fq;

    // Returns the circuit output.
    fn output(&self) -> &[Fq];

    // Ensures that the arithmetization hasn't been folded yet.
    fn has_crossterms(&self) -> bool;

    // Returns a set of base case inputs. Should in all cases just return
    // as many one scalars as there are inputs.
    fn z0(&self) -> Vec<Fq>;

    #[allow(clippy::too_many_arguments)]
    fn synthesize(
        &mut self,
        params: Fq,
        latest_witness: G1Projective,
        latest_hash: Fq,
        old_pc: usize,
        new_pc: usize,
        i: usize,
        constants: &PoseidonConfig<Fq>,
        generators: &[G1Projective],
    ) -> Self;

    fn fold(&mut self, other: &Self, constants: &PoseidonConfig<Fq>, generators: &[G1Projective]);
}
