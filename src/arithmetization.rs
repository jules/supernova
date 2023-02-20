//! Defines the common functionality for any kind of program arithmetization to be used
//! in the SuperNova protocol.
//! Additionally, includes a model which defines this functionality for R1CS.

pub mod r1cs;

use ark_bls12_381::{Fq, G1Affine};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;

/// A foldable circuit representation.
pub trait Arithmetization {
    type ConstraintSystem;
    type Input;

    // Returns the latest IO hash.
    fn hash(&self) -> Fq;

    // Returns the current witness commitment.
    fn witness_commitment(&self) -> G1Affine;

    // Returns the crossterms for hashing.
    fn crossterms(&self) -> Vec<Fq>;

    // Checks if the arithmetization is correct.
    fn is_satisfied(&self, generators: &[G1Affine]) -> bool;

    // Returns the circuit metadata used for hashing.
    fn params(&self, constants: &PoseidonConfig<Fq>) -> Fq;

    // Returns the circuit output.
    fn output(&self) -> &[Fq];

    // Ensures that the arithmetization hasn't been folded yet.
    fn has_crossterms(&self) -> bool;

    // Returns a set of base case inputs. Should in all cases just return
    // as many one scalars as there are inputs.
    fn z0(&self) -> Vec<Fq>;

    // Synthesizes a new invocation of the augmented step circuit, which folds the two current
    // instance-witness pairs in-circuit and returns a new instance-witness pair representing the
    // invocation.
    #[allow(clippy::too_many_arguments)]
    fn synthesize<C: Fn(Self::ConstraintSystem, &[Self::Input]) -> Vec<Self::Input>>(
        &mut self,
        params: Fq,
        latest_witness: G1Affine,
        latest_hash: Fq,
        old_pc: usize,
        new_pc: usize,
        i: usize,
        constants: &PoseidonConfig<Fq>,
        generators: &[G1Affine],
        circuit: C,
    ) -> Self;

    // Performs the folding of the two instance-witness pairs natively. Should only be called after
    // [`synthesize`].
    fn fold(
        &mut self,
        other: &Self,
        constants: &PoseidonConfig<Fq>,
        generators: &[G1Affine],
        params: Fq,
    );
}
