//! A collection of structures generated by the [`ProvingAssignment`] constraint system,
//! used for the SuperNova protocol when instantiated on R1CS circuits.

use super::StepCircuit;
use crate::{commit, Arithmetization};
use ark_bls12_381::{Config as Bls12Config, Fq, Fr, G1Projective};
use ark_crypto_primitives::sponge::{
    poseidon::{
        find_poseidon_ark_and_mds, PoseidonConfig, PoseidonDefaultConfigField, PoseidonSponge,
    },
    CryptographicSponge, FieldBasedCryptographicSponge,
};
use ark_ec::{
    short_weierstrass::{Projective, SWCurveConfig},
    AffineRepr, CurveGroup,
};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::{fp::FpVar, nonnative::NonNativeFieldVar},
    groups::curves::short_weierstrass::bls12::G1Var,
};
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSystemRef, Variable};
use core::ops::{Add, AddAssign};
use itertools::concat;
use rayon::prelude::*;
use serde::Serialize;
use sha3::{Digest, Sha3_256};

#[derive(Serialize)]
pub struct SerializableShape {
    num_vars: usize,
    num_public_inputs: usize,
    A: Vec<Vec<Fq>>,
    B: Vec<Vec<Fq>>,
    C: Vec<Vec<Fq>>,
}

impl From<ConstraintMatrices<Fq>> for SerializableShape {
    fn from(v: ConstraintMatrices<Fq>) -> Self {
        let convert_matrix = |m: &[Vec<(Fq, usize)>]| -> Vec<Vec<Fq>> {
            m.iter()
                .map(|row| row.iter().map(|(coeff, _var)| *coeff).collect::<Vec<Fq>>())
                .collect::<Vec<Vec<Fq>>>()
        };

        Self {
            num_vars: v.num_witness_variables,
            num_public_inputs: v.num_instance_variables,
            A: convert_matrix(&v.a),
            B: convert_matrix(&v.b),
            C: convert_matrix(&v.c),
        }
    }
}

impl SerializableShape {
    fn digest(&self, constants: &PoseidonConfig<Fr>) -> Fr {
        let bytes = bincode::serialize(self).unwrap();

        let mut sponge = PoseidonSponge::<Fr>::new(&constants);
        sponge.absorb(&bytes);
        sponge.squeeze_native_field_elements(1)[0]
    }
}

#[allow(clippy::type_complexity)]
fn multiply_vec(
    a: &[Vec<(Fq, usize)>],
    b: &[Vec<(Fq, usize)>],
    c: &[Vec<(Fq, usize)>],
    z: &[Fr],
) -> (Vec<Fr>, Vec<Fr>, Vec<Fr>) {
    if z.len() != a.len() {
        // TODO: shouldnt panic here
        panic!("mismatched inputs to shape");
    }

    let sparse_matrix_vec_product = |m: &[Vec<(Fq, usize)>], z: &[Fr]| -> Vec<Fr> {
        m.par_iter()
            .map(|row| {
                row.par_iter()
                    .zip(z)
                    .fold(Fr::zero, |acc, ((coeff, val), v)| {
                        acc + Fr::from(coeff.into_bigint().0[0] * (*val as u64)) * v
                    })
                    .reduce(Fr::zero, |acc, val| acc + val)
            })
            .collect::<Vec<Fr>>()
    };

    let (Az, (Bz, Cz)) = rayon::join(
        || sparse_matrix_vec_product(a, z),
        || {
            rayon::join(
                || sparse_matrix_vec_product(b, z),
                || sparse_matrix_vec_product(c, z),
            )
        },
    );

    (Az, Bz, Cz)
}

#[derive(Clone)]
pub struct R1CS<C: StepCircuit<Fq>> {
    pub(crate) generators: Vec<G1Projective>,
    pub(crate) shape: ConstraintMatrices<Fq>,
    pub(crate) comm_witness: G1Projective,
    pub(crate) comm_E: G1Projective,
    pub(crate) comm_T: G1Projective,
    pub(crate) E: Vec<Fr>,
    pub(crate) witness: Vec<Fr>,
    pub(crate) instance: Vec<Fr>,
    pub(crate) u: Fr,
    pub(crate) hash: Fr,
    pub(crate) output: Vec<Fq>,
    pub(crate) circuit: C,
}

impl<C: StepCircuit<Fq>> R1CS<C> {
    fn commit_t(&self, other: &Self) -> (Vec<Fr>, G1Projective) {
        let (az1, bz1, cz1) = multiply_vec(
            &self.shape.a,
            &self.shape.b,
            &self.shape.c,
            &[self.witness.as_slice(), &[self.u], self.instance.as_slice()].concat(),
        );
        let (az2, bz2, cz2) = multiply_vec(
            &self.shape.a,
            &self.shape.b,
            &self.shape.c,
            &[
                other.witness.as_slice(),
                &[other.u],
                other.instance.as_slice(),
            ]
            .concat(),
        );

        let t = az1
            .into_iter()
            .zip(bz2)
            .zip(az2)
            .zip(bz1)
            .zip(cz1)
            .zip(cz2)
            .map(|(((((az1, bz2), az2), bz1), cz1), cz2)| {
                az1 * bz2 + az2 * bz1 - self.u * cz2 - cz1
            })
            .collect::<Vec<Fr>>();
        let comm_T = commit(&self.generators, &t);
        (t.to_vec(), comm_T)
    }

    fn alloc_witnesses(
        &self,
        params: Fr,
        cs: &mut ConstraintSystemRef<Fq>,
        i: usize,
    ) -> (
        NonNativeFieldVar<Fr, Fq>,
        FpVar<Fq>,
        Vec<NonNativeFieldVar<Fr, Fq>>,
        Vec<FpVar<Fq>>,
        G1Var<Bls12Config>,
        G1Var<Bls12Config>,
        NonNativeFieldVar<Fr, Fq>,
        NonNativeFieldVar<Fr, Fq>,
        G1Var<Bls12Config>,
    ) {
        let params = NonNativeFieldVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(params)).unwrap();
        let i = FpVar::<_>::new_witness(cs.clone(), || Ok(Fq::from(i as u64))).unwrap();
        let z0 = self
            .z0()
            .into_iter()
            .map(|v| NonNativeFieldVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(v)).unwrap())
            .collect::<Vec<_>>();
        let output = self
            .output()
            .into_iter()
            .map(|v| FpVar::<_>::new_witness(cs.clone(), || Ok(v)).unwrap())
            .collect::<Vec<_>>();
        let comm_W =
            G1Var::<Bls12Config>::new_witness(cs.clone(), || Ok(self.comm_witness)).unwrap();
        let comm_E = G1Var::<Bls12Config>::new_witness(cs.clone(), || Ok(self.comm_E)).unwrap();
        let u = NonNativeFieldVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(self.u)).unwrap();
        let hash = NonNativeFieldVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(self.hash)).unwrap();
        let comm_T = G1Var::<Bls12Config>::new_witness(cs.clone(), || Ok(self.comm_T)).unwrap();
        (params, i, z0, output, comm_W, comm_E, u, hash, comm_T)
    }
}

impl<C: StepCircuit<Fq>> Arithmetization for R1CS<C> {
    type ConstraintSystem = ConstraintSystemRef<Fq>;

    fn digest(&self, constants: &PoseidonConfig<Fr>) -> Fr {
        let mut sponge = PoseidonSponge::<Fr>::new(&constants);
        sponge.absorb(&self.witness);
        sponge.squeeze_native_field_elements(1)[0]
    }

    fn is_satisfied(&self) -> bool {
        let num_constraints = self.shape.a.len();
        if self.witness.len() != self.shape.num_witness_variables
            || self.E.len() != num_constraints
            || self.instance.len() != self.shape.num_instance_variables
        {
            return false;
        }

        // Verify if az * bz = u*cz + E.
        let z = concat(vec![
            self.witness.clone(),
            vec![self.u],
            self.instance.clone(),
        ]);
        let (az, bz, cz) = multiply_vec(&self.shape.a, &self.shape.b, &self.shape.c, &z);
        if az.len() != num_constraints || bz.len() != num_constraints || cz.len() != num_constraints
        {
            return false;
        }

        if (0..num_constraints).any(|i| az[i] * bz[i] != self.u * cz[i] + self.E[i]) {
            return false;
        }

        // Verify if comm_E and comm_witness are commitments to E and witness.
        let comm_witness = commit(&self.generators, &self.witness);
        let comm_E = commit(&self.generators, &self.E);
        self.comm_witness == comm_witness && self.comm_E == comm_E
    }

    fn is_zero(&self) -> bool {
        self.witness.iter().all(|v| v.is_zero().into())
            && self.instance.iter().all(|v| v.is_zero().into())
    }

    fn public_inputs(&self) -> &[Fr] {
        &self.instance
    }

    fn output(&self) -> &[Fq] {
        &self.output
    }

    fn params(&self) -> Fr {
        Fr::from(self.shape.a.len() as u64) + Fr::from(self.shape.num_witness_variables as u64)
    }

    fn has_crossterms(&self) -> bool {
        self.E.iter().any(|v| (!v.is_zero()).into()) && self.u != Fr::one()
    }

    fn z0(&self) -> Vec<Fr> {
        vec![Fr::zero(); self.shape.num_instance_variables]
    }

    fn synthesize(
        &mut self,
        params: Fr,
        latest_witness: G1Projective,
        latest_hash: Fr,
        pc: usize,
        i: usize,
        cs: &mut Self::ConstraintSystem,
    ) {
        // TODO: program counter should be calculated in circuit, for now it's just supplied by
        // user

        let (params, i, z0, output, comm_W, comm_E, u, hash, T) =
            self.alloc_witnesses(params, cs, i);
        let latest_witness =
            G1Var::<Bls12Config>::new_witness(cs.clone(), || Ok(latest_witness)).unwrap();
        let latest_hash =
            NonNativeFieldVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(latest_hash)).unwrap();

        let output = self
            .circuit
            .generate_constraints(cs.clone(), self.output.as_slice())
            .expect("should be able to synthesize step circuit");

        let new_circuit = cs.create_circuit(&self.generators);

        // Set the new output for later use.
        self.output = output
            .iter()
            .map(|v| match v {
                Variable::Instance(index) => new_circuit.instance[index],
                Variable::Witness(index) => new_circuit.witness[index],
            })
            .collect::<Vec<Fq>>();

        // Fold new circuit into current one.
        *self += new_circuit;
    }
}

impl<C: StepCircuit<Fq>> Add<R1CS<C>> for R1CS<C> {
    type Output = Self;

    fn add(mut self, other: Self) -> Self {
        self += other;
        self
    }
}

impl<C: StepCircuit<Fq>> AddAssign<R1CS<C>> for R1CS<C> {
    fn add_assign(&mut self, other: Self) {
        let (t, comm_T) = self.commit_t(&other);
        let (ark, mds) =
            find_poseidon_ark_and_mds(Fr::MODULUS.const_num_bits() as u64, 2, 8, 31, 0);
        let constants = PoseidonConfig::new(8, 31, 17, ark, mds, 2, ark[0].len());
        let mut sponge = PoseidonSponge::<Fr>::new(&constants);
        sponge.absorb(
            &[SerializableShape::from(self.shape).digest(&constants)]
                .into_iter()
                .chain(self.instance.clone())
                .chain(other.instance.clone())
                .chain(t.clone())
                .collect::<Vec<Fr>>(),
        );
        let r = sponge.squeeze_native_field_elements(1)[0];
        self.witness
            .par_iter_mut()
            .zip(other.witness)
            .for_each(|(w1, w2)| *w1 += w2 * r);
        self.instance
            .par_iter_mut()
            .zip(other.instance)
            .for_each(|(x1, x2)| *x1 += x2 * r);
        self.comm_witness += other.comm_witness * r;
        self.E.par_iter_mut().zip(t).for_each(|(a, b)| *a += r * b);
        self.comm_E += comm_T * r;
        self.u += r;
        self.comm_T = comm_T;
    }
}
