//! Defines the common functionality for any kind of program arithmetization to be used
//! in the SuperNova protocol.
//! Additionally, includes a model which defines this functionality for R1CS.

pub mod r1cs;

use ark_bls12_381::{Fq, Fr, G1Projective};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ec::short_weierstrass::SWCurveConfig;
use core::ops::{Add, AddAssign};

/// A foldable circuit representation.
pub trait Arithmetization: Add<Self> + AddAssign<Self> + Sized {
    type ConstraintSystem;

    // Returns the latest IO hash.
    fn hash(&self) -> Fq;

    // Returns the current witness commitment.
    fn witness_commitment(&self) -> G1Projective;

    // Checks if the arithmetization is correct.
    fn is_satisfied(&self) -> bool;

    // Checks if the arithmetization is equivalent to the base case.
    fn is_zero(&self) -> bool;

    // Returns the circuit metadata used for hashing.
    fn params(&self) -> Fq;

    // Returns the public inputs of the circuit.
    fn public_inputs(&self) -> &[Fq];

    // Returns the circuit output.
    fn output(&self) -> &[Fq];

    // Ensures that the arithmetization hasn't been folded yet.
    fn has_crossterms(&self) -> bool;

    // Returns a set of base case inputs. Should in all cases just return
    // as many one scalars as there are inputs.
    fn z0(&self) -> Vec<Fq>;

    fn synthesize(
        &mut self,
        params: Fq,
        latest_witness: G1Projective,
        latest_hash: Fq,
        old_pc: usize,
        new_pc: usize,
        i: usize,
        constants: &PoseidonConfig<Fq>,
    ) -> Self;
}
