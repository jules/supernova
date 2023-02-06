//! This library implements the SuperNova prover-verifier algorithm, and is generic
//! over any kind of arithmetization, as long as it implements the [`Arithmetization`] trait.

#![allow(non_snake_case)]

pub mod arithmetization;
pub use arithmetization::*;
mod commitment;
pub use commitment::*;
mod errors;
use errors::VerificationError;

use ark_bls12_381::{Fq, Fr, FrConfig, G1Projective};
use ark_crypto_primitives::sponge::{
    poseidon::{
        find_poseidon_ark_and_mds, PoseidonConfig, PoseidonDefaultConfigEntry, PoseidonSponge,
    },
    CryptographicSponge, FieldBasedCryptographicSponge,
};
use ark_ff::{PrimeField, Zero};

const PARAMS_OPT_FOR_CONSTRAINTS: [PoseidonDefaultConfigEntry; 7] = [
    PoseidonDefaultConfigEntry::new(2, 17, 8, 31, 0),
    PoseidonDefaultConfigEntry::new(3, 5, 8, 56, 0),
    PoseidonDefaultConfigEntry::new(4, 5, 8, 56, 0),
    PoseidonDefaultConfigEntry::new(5, 5, 8, 57, 0),
    PoseidonDefaultConfigEntry::new(6, 5, 8, 57, 0),
    PoseidonDefaultConfigEntry::new(7, 5, 8, 57, 0),
    PoseidonDefaultConfigEntry::new(8, 5, 8, 57, 0),
];
const PARAMS_OPT_FOR_WEIGHTS: [PoseidonDefaultConfigEntry; 7] = [
    PoseidonDefaultConfigEntry::new(2, 257, 8, 13, 0),
    PoseidonDefaultConfigEntry::new(3, 257, 8, 13, 0),
    PoseidonDefaultConfigEntry::new(4, 257, 8, 13, 0),
    PoseidonDefaultConfigEntry::new(5, 257, 8, 13, 0),
    PoseidonDefaultConfigEntry::new(6, 257, 8, 13, 0),
    PoseidonDefaultConfigEntry::new(7, 257, 8, 13, 0),
    PoseidonDefaultConfigEntry::new(8, 257, 8, 13, 0),
];

/// A SuperNova proof, which keeps track of a variable amount of loose circuits,
/// a most recent instance-witness pair, a program counter and the iteration
/// that the proof is currently at.
pub struct Proof<A: Arithmetization, const L: usize> {
    constants: PoseidonConfig<Fq>,
    generators: Vec<G1Projective>,
    folded: [A; L],
    latest: A,
    pc: usize,
    i: usize,
}

impl<A: Arithmetization, const L: usize> Proof<A, L> {
    /// Instantiate a SuperNova proof by giving it the set of circuits
    /// it should track.
    pub fn new(folded: [A; L], latest: A, generators: Vec<G1Projective>) -> Self {
        let (ark, mds) =
            find_poseidon_ark_and_mds(Fq::MODULUS.const_num_bits() as u64, 2, 8, 31, 0);
        Self {
            constants: PoseidonConfig::new(8, 31, 17, ark, mds, 2, ark[0].len()),
            generators,
            folded,
            latest,
            pc: 0,
            i: 0,
        }
    }

    /// Update a SuperNova proof with a new circuit.
    pub fn update(&mut self, pc: usize) {
        self.folded[self.pc] += self.latest;
        self.pc = pc;
        self.i += 1;
        // self.latest = self.synthesize(&mut cs);
        // let elements = [self
        //     .folded
        //     .iter()
        //     .fold(G::ScalarExt::zero(), |acc, pair| acc + pair.params())]
        // .into_iter()
        // .chain([G::ScalarExt::from(self.i as u64)])
        // .chain([G::ScalarExt::from(self.pc as u64)])
        // .chain(self.latest.z0())
        // .chain(self.latest.output().to_vec())
        // .chain(
        //     [self
        //         .folded
        //         .iter()
        //         .fold(G::ScalarExt::zero(), |acc, pair| acc + pair.digest())]
        //     .into_iter(),
        // )
        // .collect::<Vec<G::ScalarExt>>();
    }
}

/// Verify a SuperNova proof.
pub fn verify<A: Arithmetization, const L: usize>(
    proof: &Proof<A, L>,
) -> Result<(), VerificationError<Fr>> {
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
        &proof.constants,
        &proof.folded,
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

    println!("folded is fine");
    // Ensure the latest instance/witness pair is satisfied.
    if !proof.latest.is_satisfied() {
        return Err(VerificationError::UnsatisfiedCircuit);
    }

    Ok(())
}

pub(crate) fn hash_public_io<A: Arithmetization, const L: usize>(
    constants: &PoseidonConfig<Fr>,
    folded: &[A; L],
    i: usize,
    pc: usize,
    z0: Vec<Fr>,
    output: &[Fr],
) -> Fr {
    // TODO: validate parameters
    let mut sponge = PoseidonSponge::<Fr>::new(&constants);
    sponge.absorb(
        &[folded
            .iter()
            .fold(Fr::zero(), |acc, pair| acc + pair.params())]
        .into_iter()
        .chain([Fr::from(i as u64)])
        .chain([Fr::from(pc as u64)])
        .chain(z0)
        .chain(output.to_vec())
        .chain(
            [folded
                .iter()
                .fold(Fr::zero(), |acc, pair| acc + pair.digest(constants))]
            .into_iter(),
        )
        .collect::<Vec<Fr>>(),
    );
    sponge.squeeze_native_field_elements(1)[0]
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
    }

    #[test]
    fn test_single_circuit() {
        let base = CubicCircuit::default();
        let mut cs = ProvingAssignment::default();
        let z0 = vec![<Point as CurveExt>::ScalarField::zero()];
        cs.set_output(z0.clone());
        let output = base.synthesize(&mut cs, z0.as_slice()).unwrap();
        // TODO: can we infer generator size
        let generators = create_generators(1000);
        let r1cs = cs.create_circuit(&generators, constants.clone());

        let folded = [r1cs.clone(); 1];
        let mut proof = Proof::<Point, R1CS<Point>, 1>::new(folded, r1cs.clone());
        proof.update(r1cs.clone(), 0);
        verify(&proof).unwrap();

        // Update with a next step
        let mut cs = ProvingAssignment::default();
        let _ = base
            .synthesize(&mut cs, &[output[0].get_value().unwrap()])
            .unwrap();
        let r1cs2 = cs.create_circuit(&generators, constants);
        proof.update(r1cs2, 0);
        verify(&proof).unwrap();
    }

    #[test]
    fn test_multi_circuit() {}
}
