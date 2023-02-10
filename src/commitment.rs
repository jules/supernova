//! Commitment logic used for the creation of committed circuit structures.

use ark_bls12_381::{Fq, G1Affine};
use ark_ec::AffineRepr;
use ark_ff::{PrimeField, UniformRand};
use rand_core::OsRng;
use rayon::prelude::*;

// TODO: this is janky and should be updated
pub fn create_generators(n: usize) -> Vec<G1Affine> {
    let cap = n.next_power_of_two();
    let mut gens: Vec<G1Affine> = Vec::with_capacity(cap);
    for _ in 0..cap {
        gens.push(G1Affine::rand(&mut OsRng {}));
    }
    gens
}

pub fn commit(generators: &[G1Affine], scalars: &[Fq]) -> G1Affine {
    scalars
        .par_iter()
        .zip(generators)
        .map(|(scalar, gen)| gen.mul_bigint(scalar.into_bigint()).into())
        .reduce(|| G1Affine::zero(), |a, b| (a + b).into())
}
