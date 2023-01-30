//! This library implements the SuperNova prover-verifier algorithm, and is generic
//! over any kind of arithmetization, as long as it implements the [`Arithmetization`] trait.

#![allow(non_snake_case)]

pub mod arithmetization;
pub use arithmetization::*;
mod commitment;
pub use commitment::*;
mod errors;
use errors::VerificationError;

use core::marker::PhantomData;
use group::ff::Field;
use halo2curves::CurveExt;
use poseidon::Poseidon;

/// A SuperNova proof, which keeps track of a variable amount of loose circuits,
/// a most recent instance-witness pair, a program counter and the iteration
/// that the proof is currently at.
pub struct Proof<G: CurveExt, A: Arithmetization<G>, const L: usize> {
    folded: [A; L],
    latest: A,
    pc: usize,
    i: usize,
    _p: PhantomData<G>,
}

impl<G: CurveExt, A: Arithmetization<G>, const L: usize> Proof<G, A, L> {
    /// Instantiate a SuperNova proof by giving it the set of circuits
    /// it should track.
    pub fn new(folded: [A; L], latest: A) -> Self {
        Self {
            folded,
            latest,
            pc: 0,
            i: 0,
            _p: Default::default(),
        }
    }

    /// Update a SuperNova proof with a new instance/witness pair.
    pub fn update(&mut self, next: A, pc: usize) {
        self.folded[self.pc] += self.latest.clone();
        self.latest = next;
        self.pc = pc;
        self.i += 1;
        self.latest.push_hash(hash_public_io(
            self.folded.clone(),
            self.i,
            self.pc,
            self.latest.z0(),
            self.latest.public_inputs(),
        ));
    }
}

/// Verify a SuperNova proof.
pub fn verify<G: CurveExt, A: Arithmetization<G>, const L: usize>(
    proof: Proof<G, A, L>,
) -> Result<(), VerificationError<G::ScalarExt>> {
    // If this is only the first iteration, we can skip the other checks,
    // as no computation has been folded.
    if proof.i == 0 {
        if proof.folded.iter().any(|pair| !pair.is_zero()) {
            return Err(VerificationError::ExpectedBaseCase);
        }

        if !proof.latest.is_zero() {
            return Err(VerificationError::ExpectedBaseCase);
        }

        return Ok(());
    }

    // Check that the public IO of the latest instance includes
    // the correct hash.
    let hash = hash_public_io(
        proof.folded.clone(),
        proof.i,
        proof.pc,
        proof.latest.z0(),
        proof.latest.public_inputs(),
    );
    if proof.latest.public_inputs()[0] != hash {
        return Err(VerificationError::HashMismatch(
            hash,
            proof.latest.public_inputs()[0],
        ));
    }

    // Ensure PC is within range.
    if proof.pc > proof.folded.len() {
        return Err(VerificationError::PCOutOfRange(
            proof.pc,
            proof.folded.len(),
        ));
    }

    // Ensure the latest instance has no crossterms.
    if proof.latest.has_crossterms() {
        return Err(VerificationError::UnexpectedCrossterms);
    }

    // Ensure all folded instance/witness pairs are satisfied.
    if proof.folded.iter().any(|pair| !pair.is_satisfied()) {
        return Err(VerificationError::UnsatisfiedCircuit);
    }

    // Ensure the latest instance/witness pair is satisfied.
    if !proof.latest.is_satisfied() {
        return Err(VerificationError::UnsatisfiedCircuit);
    }

    Ok(())
}

fn hash_public_io<G: CurveExt, A: Arithmetization<G>, const L: usize>(
    folded: [A; L],
    i: usize,
    pc: usize,
    z0: Vec<G::ScalarExt>,
    inputs: &[G::ScalarExt],
) -> G::ScalarExt {
    // TODO: validate parameters
    let mut poseidon: Poseidon<G::ScalarExt, 5, 4> = Poseidon::new(8, 5);
    poseidon.update(
        &[folded
            .iter()
            .fold(G::ScalarExt::zero(), |acc, pair| acc + pair.params())]
        .into_iter()
        .chain([G::ScalarExt::from(i as u64)])
        .chain([G::ScalarExt::from(pc as u64)])
        .chain(z0)
        .chain(inputs.to_vec())
        .chain(
            [folded
                .iter()
                .fold(G::ScalarExt::zero(), |acc, pair| acc + pair.digest())]
            .into_iter(),
        )
        .collect::<Vec<G::ScalarExt>>(),
    );
    poseidon.squeeze()
}
