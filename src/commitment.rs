//! Commitment logic used for the creation of committed circuit structures.

use ark_ec::CurveGroup;
use rand_core::OsRng;
use rayon::prelude::*;

// TODO: this is janky and should be updated
pub fn create_generators<G: CurveGroup>(n: usize) -> Vec<G> {
    let cap = n.next_power_of_two();
    let mut gens: Vec<G> = Vec::with_capacity(cap);
    for _ in 0..cap {
        gens.push(G::rand(&mut OsRng {}));
    }
    gens
}

pub fn commit<G: CurveGroup>(generators: &[G], scalars: &[G::ScalarField]) -> G {
    scalars
        .par_iter()
        .zip(generators)
        .map(|(scalar, gen)| *gen * scalar)
        .reduce(|| G::zero(), |a, b| a + b)
}
