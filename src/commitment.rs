//! Commitment logic used for the creation of committed circuit structures.

use halo2curves::CurveExt;
use rayon::prelude::*;
use sha3::{
    digest::{ExtendableOutput, Input},
    Shake256,
};
use std::io::Read;

// TODO: this is janky and should be updated
pub fn create_generators<G: CurveExt<Repr = [u8; 32]>>(label: &'static [u8], n: usize) -> Vec<G> {
    let mut shake = Shake256::default();
    shake.input(label);
    let mut reader = shake.xof_result();
    let mut gens: Vec<G> = Vec::new();
    let mut uniform_bytes = [0u8; 32];
    for _ in 0..n.next_power_of_two() {
        reader.read_exact(&mut uniform_bytes).unwrap();
        gens.push(G::from_bytes(&uniform_bytes).unwrap());
    }
    gens
}

pub fn commit<G: CurveExt>(generators: &[G], scalars: &[G::ScalarExt]) -> G {
    generators
        .par_iter()
        .zip_eq(scalars)
        .map(|(gen, scalar)| *gen * scalar)
        .reduce(|| G::identity(), |a, b| a + b)
}
