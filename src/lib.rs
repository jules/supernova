//! This library implements the SuperNova IVC prover-verifier algorithm, and is generic
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
    prev_pc: usize,
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
            constants: PoseidonConfig {
                full_rounds: 8,
                partial_rounds: 31,
                alpha: 17,
                ark,
                mds,
                rate: 2,
                capacity: 1,
            },
            generators,
            folded,
            latest,
            prev_pc: 0,
            pc: 0,
            i: 1,
        }
    }

    /// Update a SuperNova proof with a new invocation of the augmented step circuit.
    pub fn update<C: Fn(A::ConstraintSystem, &[A::Input]) -> Vec<A::Input>>(
        &mut self,
        pc: usize,
        circuit: C,
    ) {
        // Fold in-circuit to produce new Arithmetization.
        let new_latest = self.folded[self.pc].synthesize(
            self.params(),
            self.folded[self.prev_pc].hash_terms(),
            self.latest.witness_commitment(),
            self.latest.hash(),
            self.pc,
            pc,
            self.i,
            &self.constants,
            &self.generators,
            circuit,
        );
        // Fold natively.
        self.folded[self.pc].fold(
            &self.latest,
            &self.constants,
            &self.generators,
            self.params(),
        );
        self.latest = new_latest;
        self.prev_pc = self.pc;
        self.pc = pc;
        self.i += 1;
    }

    /// Verify a SuperNova proof.
    pub fn verify(&self) -> Result<(), VerificationError<Fq>> {
        // If this is only the first iteration, we can skip the other checks, as no computation has
        // been folded.
        if self.i == 1 {
            if self.folded.iter().any(|pair| pair.has_crossterms()) {
                return Err(VerificationError::ExpectedBaseCase);
            }

            if self.latest.has_crossterms() {
                return Err(VerificationError::ExpectedBaseCase);
            }

            return Ok(());
        }

        // Check that the public IO of the latest instance includes the correct hash.
        let hash = self.hash_public_io();
        if self.latest.hash() != hash {
            return Err(VerificationError::HashMismatch(hash, self.latest.hash()));
        }

        // Ensure PC is within range.
        if self.pc > self.folded.len() {
            return Err(VerificationError::PCOutOfRange(self.pc, self.folded.len()));
        }

        // Ensure the latest instance has no crossterms.
        if self.latest.has_crossterms() {
            return Err(VerificationError::UnexpectedCrossterms);
        }

        // Ensure all folded instance/witness pairs are satisfied.
        if self
            .folded
            .iter()
            .any(|pair| !pair.is_satisfied(&self.generators))
        {
            return Err(VerificationError::UnsatisfiedCircuit);
        }

        // Ensure the latest instance/witness pair is satisfied.
        if !self.latest.is_satisfied(&self.generators) {
            return Err(VerificationError::UnsatisfiedCircuit);
        }

        Ok(())
    }

    // Returns a sum of the parameter hashes of all circuits.
    fn params(&self) -> Fq {
        self.folded
            .iter()
            .map(|p| p.params())
            .fold(Fq::zero(), |acc, x| acc + x)
    }

    // Returns a hash of the 'public IO' for verification purposes. This hash should match the hash
    // created in the augmented step circuit.
    fn hash_public_io(&self) -> Fq {
        let mut sponge = PoseidonSponge::<Fq>::new(&self.constants);
        sponge.absorb(
            &[self
                .folded
                .iter()
                .fold(Fq::zero(), |acc, pair| acc + pair.params())]
            .into_iter()
            .chain([Fq::from(self.i as u64)])
            .chain([Fq::from(self.pc as u64)])
            .chain(self.folded[self.prev_pc].z0())
            .chain(self.folded[self.prev_pc].output().to_vec())
            .chain([
                self.folded[self.prev_pc].witness_commitment().x,
                self.folded[self.prev_pc].witness_commitment().y,
                Fq::from(self.folded[self.prev_pc].witness_commitment().infinity),
            ])
            .chain(self.folded[self.prev_pc].crossterms())
            .chain([self.folded[self.prev_pc].hash()])
            .collect::<Vec<Fq>>(),
        );
        sponge.squeeze_native_field_elements(1)[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1cs::R1CS;
    use ark_ff::One;
    use ark_r1cs_std::{
        alloc::AllocVar,
        eq::EqGadget,
        fields::{fp::FpVar, FieldVar},
        R1CSVar,
    };
    use ark_relations::r1cs::ConstraintSystemRef;
    use core::ops::{Add, Mul};

    fn cubic_circuit(cs: ConstraintSystemRef<Fq>, z: &[FpVar<Fq>]) -> Vec<FpVar<Fq>> {
        // Consider a cubic equation: `x^3 + x + 5 = y`, where `x` and `y` are respectively the
        // input and output.
        let x = FpVar::<_>::new_input(cs.clone(), || Ok(z[0].value().unwrap())).unwrap();
        let x_sq = x.square().unwrap();
        let x_cu = x_sq.mul(&x);
        let y = FpVar::<_>::new_witness(cs.clone(), || {
            Ok(x_cu.value().unwrap() + x.value().unwrap() + Fq::from(5u64))
        })
        .unwrap();
        x_cu.add(&x)
            .add(&FpVar::<_>::one())
            .add(&FpVar::<_>::one())
            .add(&FpVar::<_>::one())
            .add(&FpVar::<_>::one())
            .add(&FpVar::<_>::one())
            .enforce_equal(&y)
            .unwrap();

        vec![y]
    }

    #[test]
    fn test_single_circuit_r1cs() {
        // TODO: can we infer generator size
        let generators = create_generators(30000);
        let (ark, mds) =
            find_poseidon_ark_and_mds(Fq::MODULUS.const_num_bits() as u64, 2, 8, 31, 0);
        let constants = PoseidonConfig {
            full_rounds: 8,
            partial_rounds: 31,
            alpha: 17,
            ark,
            mds,
            rate: 2,
            capacity: 1,
        };
        let (folded, base) = R1CS::new(vec![Fq::one()], &cubic_circuit, &constants, &generators);

        let folded = [folded.clone(); 1];
        let mut proof = Proof::<R1CS, 1>::new(folded, base, generators);
        // Check base case verification.
        proof.verify().unwrap();

        // Fold and verify two steps of computation.
        for _ in 0..2 {
            proof.update(0, &cubic_circuit);
            proof.verify().unwrap();
        }
    }

    fn square_circuit(cs: ConstraintSystemRef<Fq>, z: &[FpVar<Fq>]) -> Vec<FpVar<Fq>> {
        // Consider a square equation: `x^2 + x + 5 = y`, where `x` and `y` are respectively the
        // input and output.
        let x = FpVar::<_>::new_input(cs.clone(), || Ok(z[0].value().unwrap())).unwrap();
        let x_sq = x.square().unwrap();
        let y = FpVar::<_>::new_witness(cs.clone(), || {
            Ok(x_sq.value().unwrap() + x.value().unwrap() + Fq::from(5u64))
        })
        .unwrap();
        x_sq.add(&x)
            .add(&FpVar::<_>::one())
            .add(&FpVar::<_>::one())
            .add(&FpVar::<_>::one())
            .add(&FpVar::<_>::one())
            .add(&FpVar::<_>::one())
            .enforce_equal(&y)
            .unwrap();

        vec![y]
    }

    #[test]
    fn test_multi_circuit_r1cs() {
        let generators = create_generators(30000);
        let (ark, mds) =
            find_poseidon_ark_and_mds(Fq::MODULUS.const_num_bits() as u64, 2, 8, 31, 0);
        let constants = PoseidonConfig {
            full_rounds: 8,
            partial_rounds: 31,
            alpha: 17,
            ark,
            mds,
            rate: 2,
            capacity: 1,
        };
        let (folded1, base) = R1CS::new(vec![Fq::one()], &cubic_circuit, &constants, &generators);
        let (folded2, _) = R1CS::new(vec![Fq::one()], &square_circuit, &constants, &generators);

        let folded: [R1CS; 2] = [folded1, folded2];
        let mut proof = Proof::<R1CS, 2>::new(folded, base, generators);
        // Check base case verification.
        proof.verify().unwrap();

        // Fold and verify two steps of computation for each circuit, in interlocked fashion.
        for _ in 0..2 {
            proof.update(0, &cubic_circuit);
            proof.verify().unwrap();
            proof.update(1, &square_circuit);
            proof.verify().unwrap();
        }
    }
}
