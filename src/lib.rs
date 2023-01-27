//! This library implements the SuperNova prover-verifier algorithm, and is generic
//! over any kind of arithmetization, as long as it implements the [`Arithmetization`]
//! and [`FoldedArithmetization`] traits.

#![allow(non_snake_case)]

mod arithmetization;
use arithmetization::*;
mod errors;
use errors::VerificationError;

use core::marker::PhantomData;
use halo2curves::FieldExt;
use poseidon::Poseidon;

/// A SuperNova proof, which keeps track of a variable amount of loose circuits,
/// a most recent instance-witness pair, a program counter and the iteration
/// that the proof is currently at.
pub struct Proof<
    Scalar: FieldExt,
    A: Arithmetization<Scalar>,
    F: FoldedArithmetization<Scalar, A>,
    const L: usize,
> {
    folded: [F; L],
    latest: A,
    pc: usize,
    i: usize,
    _p: PhantomData<Scalar>,
}

impl<
        Scalar: FieldExt,
        A: Arithmetization<Scalar>,
        F: FoldedArithmetization<Scalar, A>,
        const L: usize,
    > Proof<Scalar, A, F, L>
{
    /// Instantiate a SuperNova proof by giving it the set of circuits
    /// it should track.
    pub fn new(folded: [F; L]) -> Self {
        Self {
            folded,
            latest: A::default(),
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
            self.latest.inputs(),
        ));
    }
}

/// Verify a SuperNova proof.
pub fn verify<
    Scalar: FieldExt,
    A: Arithmetization<Scalar>,
    F: FoldedArithmetization<Scalar, A>,
    const L: usize,
>(
    proof: Proof<Scalar, A, F, L>,
) -> Result<(), VerificationError<Scalar>> {
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
        proof.latest.inputs(),
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

fn hash_public_io<
    Scalar: FieldExt,
    A: Arithmetization<Scalar>,
    F: FoldedArithmetization<Scalar, A>,
    const L: usize,
>(
    folded: [F; L],
    i: usize,
    pc: usize,
    z0: Vec<Scalar>,
    inputs: Vec<Scalar>,
) -> Scalar {
    let mut poseidon: Poseidon<Scalar, 5, 4> = Poseidon::new(8, 5);
    poseidon.update(
        [folded
            .iter()
            .fold(Scalar::zero(), |acc, pair| acc + pair.params())]
        .into_iter()
        .chain([Scalar::from(i as u64)])
        .chain([Scalar::from(pc as u64)])
        .chain(z0)
        .chain(inputs)
        .chain(
            [folded
                .iter()
                .fold(Scalar::zero(), |acc, pair| acc + pair.digest())]
            .into_iter(),
        )
        .collect::<Vec<Scalar>>()
        .as_slice(),
    );
    poseidon.squeeze()
}
