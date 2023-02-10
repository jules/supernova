//! This library implements the SuperNova prover-verifier algorithm, and is generic
//! over any kind of arithmetization, as long as it implements the [`Arithmetization`] trait.

#![allow(non_snake_case)]

pub mod arithmetization;
pub use arithmetization::*;
mod commitment;
pub use commitment::*;
mod errors;
use errors::VerificationError;

use ark_bls12_381::{Fq, G1Affine};
use ark_crypto_primitives::sponge::{
    poseidon::{find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge},
    CryptographicSponge, FieldBasedCryptographicSponge,
};
use ark_ff::{PrimeField, Zero};

/// A SuperNova proof, which keeps track of a variable amount of loose circuits,
/// a most recent instance-witness pair, a program counter and the iteration
/// that the proof is currently at.
pub struct Proof<A: Arithmetization, const L: usize> {
    constants: PoseidonConfig<Fq>,
    generators: Vec<G1Affine>,
    folded: [A; L],
    latest: A,
    pc: usize,
    i: usize,
}

impl<A: Arithmetization, const L: usize> Proof<A, L> {
    /// Instantiate a SuperNova proof by giving it the set of circuits
    /// it should track.
    pub fn new(folded: [A; L], latest: A, generators: Vec<G1Affine>) -> Self {
        // TODO: these parameters might not be optimal/secure for Fq.
        let (ark, mds) =
            find_poseidon_ark_and_mds(Fq::MODULUS.const_num_bits() as u64, 2, 8, 31, 0);
        Self {
            constants: PoseidonConfig::new(8, 31, 17, ark.clone(), mds, 2, ark[0].len()),
            generators,
            folded,
            latest,
            pc: 0,
            i: 0,
        }
    }

    /// Update a SuperNova proof with a new circuit.
    pub fn update(&mut self, pc: usize) {
        // Fold in-circuit to produce new Arithmetization.
        let new_latest = self.folded[self.pc].synthesize(
            self.params(),
            self.latest.witness_commitment(),
            self.latest.hash(),
            self.pc,
            pc,
            self.i,
            &self.constants,
            &self.generators,
        );
        // Fold natively.
        self.folded[self.pc].fold(
            &self.latest,
            &self.constants,
            &self.generators,
            self.params(),
        );
        self.latest = new_latest;
        self.pc = pc;
        self.i += 1;
    }

    fn params(&self) -> Fq {
        self.folded
            .iter()
            .map(|p| p.params(&self.constants))
            .fold(Fq::zero(), |acc, x| acc + x)
    }
}

/// Verify a SuperNova proof.
pub fn verify<A: Arithmetization, const L: usize>(
    proof: &Proof<A, L>,
) -> Result<(), VerificationError<Fq>> {
    // If this is only the first iteration, we can skip the other checks,
    // as no computation has been folded.
    if proof.i == 0 {
        if proof.folded.iter().any(|pair| !pair.has_crossterms()) {
            return Err(VerificationError::ExpectedBaseCase);
        }

        if proof.latest.has_crossterms() {
            return Err(VerificationError::ExpectedBaseCase);
        }

        return Ok(());
    }

    // Check that the public IO of the latest instance includes
    // the correct hash.
    let hash = hash_public_io(
        &proof.constants,
        &proof.folded,
        proof.i,
        proof.pc,
        proof.latest.z0(),
        proof.latest.output(),
    );
    if proof.latest.hash() != hash {
        return Err(VerificationError::HashMismatch(hash, proof.latest.hash()));
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
    if proof
        .folded
        .iter()
        .any(|pair| !pair.is_satisfied(&proof.generators))
    {
        return Err(VerificationError::UnsatisfiedCircuit);
    }

    println!("folded is fine");
    // Ensure the latest instance/witness pair is satisfied.
    if !proof.latest.is_satisfied(&proof.generators) {
        return Err(VerificationError::UnsatisfiedCircuit);
    }

    Ok(())
}

pub(crate) fn hash_public_io<A: Arithmetization, const L: usize>(
    constants: &PoseidonConfig<Fq>,
    folded: &[A; L],
    i: usize,
    pc: usize,
    z0: Vec<Fq>,
    output: &[Fq],
) -> Fq {
    // TODO: validate parameters
    let mut sponge = PoseidonSponge::<Fq>::new(constants);
    sponge.absorb(
        &[folded
            .iter()
            .fold(Fq::zero(), |acc, pair| acc + pair.params(constants))]
        .into_iter()
        .chain([Fq::from(i as u64)])
        .chain([Fq::from(pc as u64)])
        .chain(z0)
        .chain(output.to_vec())
        .chain([folded[pc].hash()])
        .collect::<Vec<Fq>>(),
    );
    sponge.squeeze_native_field_elements(1)[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1cs::{StepCircuit, R1CS};
    use ark_ff::One;
    use ark_r1cs_std::{
        alloc::AllocVar,
        eq::EqGadget,
        fields::{fp::FpVar, FieldVar},
        R1CSVar,
    };
    use ark_relations::r1cs::{ConstraintSystemRef, Result};
    use core::{
        marker::PhantomData,
        ops::{Add, Mul},
    };

    #[derive(Default, Clone)]
    struct CubicCircuit<F: PrimeField> {
        _p: PhantomData<F>,
    }

    impl<F: PrimeField> StepCircuit<F> for CubicCircuit<F> {
        fn generate_constraints(
            &self,
            cs: ConstraintSystemRef<F>,
            z: &[FpVar<F>],
        ) -> Result<Vec<FpVar<F>>> {
            // Consider a cubic equation: `x^3 + x + 5 = y`, where `x` and `y` are respectively the input and output.
            let x = FpVar::<_>::new_input(cs.clone(), || Ok(z[0].value()?))?;
            let x_sq = x.square()?;
            let x_cu = x_sq.mul(&x);
            let y = FpVar::<_>::new_witness(cs.clone(), || {
                Ok(x_cu.value()? + x.value()? + F::from(5u64))
            })?;
            x_cu.add(&x)
                .add(&FpVar::<_>::one())
                .add(&FpVar::<_>::one())
                .add(&FpVar::<_>::one())
                .add(&FpVar::<_>::one())
                .add(&FpVar::<_>::one())
                .enforce_equal(&y)?;

            Ok(vec![y])
        }
    }

    #[test]
    fn test_single_circuit() {
        let generators = create_generators(1000);
        let circuit = CubicCircuit::<Fq>::default();
        let (ark, mds) =
            find_poseidon_ark_and_mds(Fq::MODULUS.const_num_bits() as u64, 2, 8, 31, 0);
        let constants = PoseidonConfig::new(8, 31, 17, ark.clone(), mds, 2, ark[0].len());
        let base = R1CS::new(vec![Fq::one()], circuit, &constants, &generators);
        // TODO: can we infer generator size

        let folded = [base.clone(); 1];
        let mut proof = Proof::<R1CS<CubicCircuit<Fq>>, 1>::new(folded, base, generators);
        proof.update(0);
        verify(&proof).unwrap();

        // Update with a next step
        proof.update(0);
        verify(&proof).unwrap();
    }

    #[test]
    fn test_multi_circuit() {}
}
