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

    // Returns a digest of the circuit.
    fn digest(&self, constants: &PoseidonConfig<Fr>) -> Fr;

    // Checks if the arithmetization is correct.
    fn is_satisfied(&self) -> bool;

    // Checks if the arithmetization is equivalent to the base case.
    fn is_zero(&self) -> bool;

    // Returns the circuit metadata used for hashing.
    fn params(&self) -> Fr;

    // Returns the public inputs of the circuit.
    fn public_inputs(&self) -> &[Fr];

    // Returns the circuit output.
    fn output(&self) -> &[Fq];

    // Ensures that the arithmetization hasn't been folded yet.
    fn has_crossterms(&self) -> bool;

    // Returns a set of base case inputs. Should in all cases just return
    // as many one scalars as there are inputs.
    fn z0(&self) -> Vec<Fr>;

    fn synthesize(
        &mut self,
        params: Fr,
        latest_witness: G1Projective,
        latest_hash: Fr,
        pc: usize,
        i: usize,
        cs: &mut Self::ConstraintSystem,
    );
}
