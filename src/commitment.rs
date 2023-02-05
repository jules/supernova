//! Commitment logic used for the creation of committed circuit structures.

use pasta_curves::arithmetic::CurveExt;
use rand_core::OsRng;
use rayon::prelude::*;

// TODO: this is janky and should be updated
pub fn create_generators<G: CurveExt>(n: usize) -> Vec<G> {
    let cap = n.next_power_of_two();
    let mut gens: Vec<G> = Vec::with_capacity(cap);
    for _ in 0..cap {
        gens.push(G::random(OsRng {}));
    }
    gens
}

pub fn commit<G: CurveExt>(generators: &[G], scalars: &[G::ScalarExt]) -> G {
    scalars
        .par_iter()
        .zip(generators)
        .map(|(scalar, gen)| *gen * scalar)
        .reduce(|| G::identity(), |a, b| a + b)
}
