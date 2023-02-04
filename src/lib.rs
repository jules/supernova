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
use neptune::{poseidon::PoseidonConstants, Poseidon};
use pasta_curves::arithmetic::CurveExt;
use typenum::U16;

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
        let elements = [self
            .folded
            .iter()
            .fold(G::ScalarExt::zero(), |acc, pair| acc + pair.params())]
        .into_iter()
        .chain([G::ScalarExt::from(self.i as u64)])
        .chain([G::ScalarExt::from(self.pc as u64)])
        .chain(self.latest.z0())
        .chain(self.latest.output().to_vec())
        .chain(
            [self
                .folded
                .iter()
                .fold(G::ScalarExt::zero(), |acc, pair| acc + pair.digest())]
            .into_iter(),
        )
        .collect::<Vec<G::ScalarExt>>();
        self.latest.push_hash(elements);
    }
}

/// Verify a SuperNova proof.
pub fn verify<G: CurveExt, A: Arithmetization<G>, const L: usize>(
    proof: &Proof<G, A, L>,
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
        proof.latest.output(),
    );
    if proof.latest.public_inputs()[proof.latest.public_inputs().len() - 2] != hash {
        return Err(VerificationError::HashMismatch(
            hash,
            proof.latest.public_inputs()[proof.latest.public_inputs().len() - 2],
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

pub(crate) fn hash_public_io<G: CurveExt, A: Arithmetization<G>, const L: usize>(
    folded: [A; L],
    i: usize,
    pc: usize,
    z0: Vec<G::ScalarExt>,
    output: &[G::ScalarExt],
) -> G::ScalarExt {
    // TODO: validate parameters
    let constants = PoseidonConstants::<_, U16>::new();
    let mut poseidon = Poseidon::new(&constants);
    [folded
        .iter()
        .fold(G::ScalarExt::zero(), |acc, pair| acc + pair.params())]
    .into_iter()
    .chain([G::ScalarExt::from(i as u64)])
    .chain([G::ScalarExt::from(pc as u64)])
    .chain(z0)
    .chain(output.to_vec())
    .chain(
        [folded
            .iter()
            .fold(G::ScalarExt::zero(), |acc, pair| acc + pair.digest())]
        .into_iter(),
    )
    .for_each(|el| {
        poseidon.input(el).expect("should not exceed 32 elements");
    });
    poseidon.hash()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetization::Circuit,
        r1cs::{ProvingAssignment, R1CS},
    };
    use bellperson::{gadgets::num::AllocatedNum, SynthesisError};
    use group::ff::PrimeField;
    use pasta_curves::pallas::Point;

    #[derive(Default)]
    struct CubicCircuit<F: PrimeField> {
        _p: PhantomData<F>,
    }

    impl<F: PrimeField> Circuit<F> for CubicCircuit<F> {
        fn synthesize<CS: ConstraintSystem<F>>(
            &self,
            cs: &mut CS,
            z: &[F],
        ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
            // Consider a cubic equation: `x^3 + x + 5 = y`, where `x` and `y` are respectively the input and output.
            let x = AllocatedNum::alloc_input(cs.namespace(|| "x"), || Ok(z[0]))?;
            let x_sq = x.square(cs.namespace(|| "x_sq"))?;
            let x_cu = x_sq.mul(cs.namespace(|| "x_cu"), &x)?;
            let y = AllocatedNum::alloc(cs.namespace(|| "y"), || {
                Ok(x_cu.get_value().unwrap() + x.get_value().unwrap() + F::from(5u64))
            })?;

            cs.enforce(
                || "y = x^3 + x + 5",
                |lc| {
                    lc + x_cu.get_variable()
                        + x.get_variable()
                        + CS::one()
                        + CS::one()
                        + CS::one()
                        + CS::one()
                        + CS::one()
                },
                |lc| lc + CS::one(),
                |lc| lc + y.get_variable(),
            );

            Ok(vec![y])
        }

        fn output(&self, z: &[F]) -> Vec<F> {
            vec![z[0] * z[0] * z[0] + z[0] + F::from(5u64)]
        }
    }

    #[test]
    fn test_single_circuit() {
        let base = CubicCircuit::default();
        let mut cs = ProvingAssignment::default();
        let z0 = vec![<Point as CurveExt>::ScalarExt::zero()];
        cs.set_output(z0.clone());
        let _ = base.synthesize(&mut cs, z0.as_slice()).unwrap();
        // TODO: can we infer generator size
        let generators = create_generators(1000);
        let r1cs = cs.create_circuit(&generators);

        let folded = [r1cs.clone(); 1];
        let mut proof = Proof::<Point, R1CS<Point>, 1>::new(folded, r1cs.clone());
        proof.update(r1cs.clone(), 0);
        verify(&proof).unwrap();
    }

    #[test]
    fn test_multi_circuit() {}
}
