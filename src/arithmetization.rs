//! Defines the common functionality for any kind of program arithmetization to be used
//! in the SuperNova protocol.

pub mod plonk;
pub mod r1cs;

use core::ops::{Add, AddAssign};
use group::Group;

/// A foldable circuit representation.
pub trait Arithmetization<G: Group>: Clone + Add<Self> + AddAssign<Self> {
    // Returns a digest of the circuit.
    fn digest(&self) -> G::Scalar;

    // Checks if the arithmetization is correct.
    fn is_satisfied(&self) -> bool;

    // Checks if the arithmetization is equivalent to the base case.
    fn is_zero(&self) -> bool;

    // Returns the list of public inputs corresponding to the arithmetization.
    fn public_inputs(&self) -> &[G::Scalar];

    // Returns the circuit metadata used for hashing.
    fn params(&self) -> G::Scalar;

    // Pushes a hash into the public IO of the circuit.
    fn push_hash(&mut self, x: G::Scalar);

    // Ensures that the arithmetization hasn't been folded yet.
    fn has_crossterms(&self) -> bool;

    // Returns a set of base case inputs. Should in all cases just return
    // as many zero scalars as there are inputs.
    fn z0(&self) -> Vec<G::Scalar>;
}
