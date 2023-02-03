//! Defines the common functionality for any kind of program arithmetization to be used
//! in the SuperNova protocol.

pub mod plonk;
pub mod r1cs;

use bellperson::{
    gadgets::num::AllocatedNum, ConstraintSystem as BellpersonConstraintSystem, SynthesisError,
};
use core::ops::{Add, AddAssign};
use group::ff::PrimeField;
use pasta_curves::arithmetic::CurveExt;

/// A foldable circuit representation.
pub trait Arithmetization<G: CurveExt>: Clone + Add<Self> + AddAssign<Self> {
    // Returns a digest of the circuit.
    fn digest(&self) -> G::ScalarExt;

    // Checks if the arithmetization is correct.
    fn is_satisfied(&self) -> bool;

    // Checks if the arithmetization is equivalent to the base case.
    fn is_zero(&self) -> bool;

    // Returns the circuit metadata used for hashing.
    fn params(&self) -> G::ScalarExt;

    fn public_inputs(&self) -> &[G::ScalarExt];

    // Returns the circuit output.
    fn output(&self) -> &[G::ScalarExt];

    // Pushes a hash into the public IO of the circuit.
    fn push_hash(&mut self, elements: Vec<G::ScalarExt>);

    // Ensures that the arithmetization hasn't been folded yet.
    fn has_crossterms(&self) -> bool;

    // Returns a set of base case inputs. Should in all cases just return
    // as many zero scalars as there are inputs.
    fn z0(&self) -> Vec<G::ScalarExt>;
}

pub trait ConstraintSystem<F: PrimeField>: BellpersonConstraintSystem<F> {
    fn set_output(&mut self, output: Vec<F>);
}

pub trait Circuit<F: PrimeField> {
    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[F],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError>;

    fn output(&self, z: &[F]) -> Vec<F>;
}
