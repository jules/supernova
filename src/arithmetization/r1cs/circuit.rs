//! A collection of structures generated by the [`ProvingAssignment`] constraint system,
//! used for the SuperNova protocol when instantiated on R1CS circuits.

use super::StepCircuit;
use crate::{commit, Arithmetization};
use ark_bls12_381::{Config as Bls12Config, Fq, G1Affine, G1Projective};
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig, PoseidonSponge},
    CryptographicSponge, FieldBasedCryptographicSponge,
};
use ark_ec::AffineRepr;
use ark_ff::{One, PrimeField, Zero};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    groups::{
        curves::short_weierstrass::bls12::{G1AffineVar, G1Var},
        CurveVar,
    },
    select::CondSelectGadget,
    R1CSVar, ToBitsGadget, ToConstraintFieldGadget,
};
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSystem, ConstraintSystemRef};
use ark_serialize::CanonicalSerialize;
use core::ops::{Add, Mul};
use itertools::concat;
use rayon::prelude::*;

#[derive(CanonicalSerialize)]
pub struct SerializableShape {
    num_vars: usize,
    num_public_inputs: usize,
    A: Vec<Vec<Fq>>,
    B: Vec<Vec<Fq>>,
    C: Vec<Vec<Fq>>,
}

impl From<&ConstraintMatrices<Fq>> for SerializableShape {
    fn from(v: &ConstraintMatrices<Fq>) -> Self {
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
    fn digest(&self, constants: &PoseidonConfig<Fq>) -> Fq {
        let mut bytes = vec![];
        self.serialize_compressed(&mut bytes).unwrap();

        let mut sponge = PoseidonSponge::<Fq>::new(constants);
        sponge.absorb(&bytes);
        sponge.squeeze_native_field_elements(1)[0]
    }
}

#[derive(Clone)]
pub struct R1CS<C: StepCircuit<Fq>> {
    pub(crate) shape: ConstraintMatrices<Fq>,
    pub(crate) comm_witness: G1Affine,
    pub(crate) comm_E: G1Affine,
    pub(crate) comm_T: G1Affine,
    pub(crate) E: Vec<Fq>,
    pub(crate) witness: Vec<Fq>,
    pub(crate) instance: Vec<Fq>,
    pub(crate) u: Fq,
    pub(crate) hash: Fq,
    pub(crate) output: Vec<Fq>,
    pub(crate) circuit: C,
}

impl<C: StepCircuit<Fq>> Arithmetization for R1CS<C> {
    type ConstraintSystem = ConstraintSystemRef<Fq>;

    fn hash(&self) -> Fq {
        self.hash
    }

    fn witness_commitment(&self) -> G1Affine {
        self.comm_witness
    }

    fn crossterms(&self) -> Vec<Fq> {
        vec![
            self.comm_E.x,
            self.comm_E.y,
            Fq::from(self.comm_E.infinity),
            self.u,
        ]
    }

    fn is_satisfied(&self, generators: &[G1Affine]) -> bool {
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
        let (az, bz, cz) = r1cs_matrix_vec_product(&self.shape.a, &self.shape.b, &self.shape.c, &z);
        if az.len() != num_constraints || bz.len() != num_constraints || cz.len() != num_constraints
        {
            return false;
        }

        if (0..num_constraints).any(|i| az[i] * bz[i] != self.u * cz[i] + self.E[i]) {
            return false;
        }

        // Verify if comm_E and comm_witness are commitments to E and witness.
        let comm_witness = commit(generators, &self.witness);
        let comm_E = commit(generators, &self.E);
        self.comm_witness == comm_witness && self.comm_E == comm_E
    }

    fn output(&self) -> &[Fq] {
        &self.output
    }

    fn params(&self, constants: &PoseidonConfig<Fq>) -> Fq {
        SerializableShape::from(&self.shape).digest(constants)
    }

    fn has_crossterms(&self) -> bool {
        self.E.iter().any(|v| !v.is_zero()) && self.u != Fq::one()
    }

    fn z0(&self) -> Vec<Fq> {
        vec![Fq::zero(); self.output().len()]
    }

    fn synthesize(
        &mut self,
        params: Fq,
        latest_witness: G1Affine,
        latest_hash: Fq,
        old_pc: usize,
        new_pc: usize,
        i: usize,
        constants: &PoseidonConfig<Fq>,
        generators: &[G1Affine],
    ) -> R1CS<C> {
        // TODO: program counter should be calculated in circuit, for now it's just supplied by
        // user
        let mut cs = ConstraintSystem::<Fq>::new_ref();
        let old_pc = FpVar::<Fq>::new_witness(cs.clone(), || Ok(Fq::from(old_pc as u64))).unwrap();
        let new_pc = FpVar::<Fq>::new_witness(cs.clone(), || Ok(Fq::from(new_pc as u64))).unwrap();

        let params = FpVar::<_>::new_witness(cs.clone(), || Ok(params)).unwrap();
        let i = FpVar::<_>::new_witness(cs.clone(), || Ok(Fq::from(i as u64))).unwrap();
        let z0 = self
            .z0()
            .iter()
            .map(|v| FpVar::<_>::new_witness(cs.clone(), || Ok(v)).unwrap())
            .collect::<Vec<_>>();
        let output = self
            .output()
            .iter()
            .map(|v| FpVar::<_>::new_witness(cs.clone(), || Ok(v)).unwrap())
            .collect::<Vec<_>>();
        let comm_W =
            G1Var::<Bls12Config>::new_witness(cs.clone(), || Ok(self.comm_witness)).unwrap();
        let comm_E = G1Var::<Bls12Config>::new_witness(cs.clone(), || Ok(self.comm_E)).unwrap();
        let u = FpVar::<Fq>::new_witness(cs.clone(), || Ok(self.u)).unwrap();
        let hash = FpVar::<Fq>::new_witness(cs.clone(), || Ok(self.hash)).unwrap();
        let T = G1Var::<Bls12Config>::new_witness(cs.clone(), || Ok(self.comm_T)).unwrap();
        let latest_witness =
            G1Var::<Bls12Config>::new_witness(cs.clone(), || Ok(latest_witness)).unwrap();
        let latest_hash = FpVar::<Fq>::new_witness(cs.clone(), || Ok(latest_hash)).unwrap();

        let zero = FpVar::<_>::new_witness(cs.clone(), || Ok(Fq::zero())).unwrap();
        let is_base_case = FpVar::<_>::is_eq(&i, &zero).unwrap();

        // Synthesize both cases
        // Base case
        let W_base =
            G1Var::<Bls12Config>::new_witness(cs.clone(), || Ok(G1Projective::zero())).unwrap();
        let E_base =
            G1Var::<Bls12Config>::new_witness(cs.clone(), || Ok(G1Projective::zero())).unwrap();
        let u_base = FpVar::<_>::new_witness(cs.clone(), || Ok(Fq::one())).unwrap();
        let hash_base = FpVar::<_>::new_witness(cs.clone(), || Ok(Fq::zero())).unwrap();

        // Non base case
        let non_base_case = FpVar::<_>::is_eq(&hash, &hash_base).unwrap();
        let hash = compute_io_hash(
            constants,
            &mut cs,
            &params,
            &i,
            &old_pc,
            &z0,
            &output,
            &comm_W.to_affine().unwrap(),
            &comm_E.to_affine().unwrap(),
            &u,
            &hash,
        );

        // Fold in circuit
        // Compute r
        let r = compute_r(
            constants,
            &mut cs,
            &params,
            &comm_W.to_affine().unwrap(),
            &comm_E.to_affine().unwrap(),
            &u,
            &hash,
            &latest_witness.to_affine().unwrap(),
            &latest_hash,
            &T.to_affine().unwrap(),
        );

        let rW = latest_witness
            .scalar_mul_le(r.to_bits_le().unwrap().iter())
            .unwrap();
        let W_fold = comm_W.add(&rW);

        let rT = T.scalar_mul_le(r.to_bits_le().unwrap().iter()).unwrap();
        let E_fold = comm_E.add(&rT);

        let u_fold = u.add(&r);

        // Fold IO
        let r_hash = latest_hash.mul(&r);
        let hash_fold = hash.add(&r_hash);

        // Pick new variables
        Boolean::<_>::enforce_not_equal(&is_base_case, &non_base_case).unwrap();

        let W_new =
            G1Var::<Bls12Config>::conditionally_select(&is_base_case, &W_base, &W_fold).unwrap();
        let E_new =
            G1Var::<Bls12Config>::conditionally_select(&is_base_case, &E_base, &E_fold).unwrap();
        let u_new = FpVar::<_>::conditionally_select(&is_base_case, &u_base, &u_fold).unwrap();
        let hash_new =
            FpVar::<_>::conditionally_select(&is_base_case, &hash_base, &hash_fold).unwrap();

        let i_new =
            FpVar::<_>::new_witness(cs.clone(), || Ok(i.value().unwrap() + Fq::one())).unwrap();

        let new_input = output
            .iter()
            .zip(&z0)
            .map(|(v_output, v_0)| {
                FpVar::<_>::conditionally_select(&is_base_case, v_0, v_output).unwrap()
            })
            .collect::<Vec<FpVar<Fq>>>();

        let output = self
            .circuit
            .clone()
            .generate_constraints(cs.clone(), &new_input)
            .expect("should be able to synthesize step circuit");

        // Compute hash and set as output.
        let hash = FpVar::<_>::new_input(cs.clone(), || {
            Ok(compute_io_hash(
                constants,
                &mut cs,
                &params,
                &i_new,
                &new_pc,
                &z0,
                &output,
                &W_new.to_affine().unwrap(),
                &E_new.to_affine().unwrap(),
                &u_new,
                &hash_new,
            )
            .value()
            .unwrap())
        })
        .unwrap();

        cs.finalize();

        // Set the new output for later use.
        self.output = output
            .iter()
            .map(|v| v.value().unwrap())
            .collect::<Vec<Fq>>();

        // Set the new hash for later use.
        self.hash = hash.value().unwrap();
        create_circuit(cs, generators, hash.value().unwrap(), self.circuit.clone())
    }

    fn fold(
        &mut self,
        other: &Self,
        constants: &PoseidonConfig<Fq>,
        generators: &[G1Affine],
        params: Fq,
    ) {
        let (t, comm_T) = self.commit_t(other, generators);
        let mut sponge = PoseidonSponge::<Fq>::new(constants);
        let terms = [params]
            .into_iter()
            .chain([
                self.comm_witness.x,
                self.comm_witness.y,
                Fq::from(self.comm_witness.infinity),
            ])
            .chain([self.comm_E.x, self.comm_E.y, Fq::from(self.comm_E.infinity)])
            .chain([self.u])
            .chain([self.hash])
            .chain([
                other.comm_witness.x,
                other.comm_witness.y,
                Fq::from(other.comm_witness.infinity),
            ])
            .chain([other.hash])
            .chain([comm_T.x, comm_T.y, Fq::from(comm_T.infinity)])
            .collect::<Vec<Fq>>();
        let naming = vec![
            "params",
            "comm_w",
            "comm_w",
            "comm_w",
            "comm_e",
            "comm_e",
            "comm_e",
            "u",
            "hash",
            "latest_witness",
            "latest_witness",
            "latest_witness",
            "latest_hash",
            "comm_t",
            "comm_t",
            "comm_t",
        ];
        println!(
            "COMPUTING R NATIVELY AS {:?}",
            terms
                .iter()
                .zip(naming)
                .map(|(v, name)| format!("{} {:?}", name, v))
                .collect::<Vec<String>>()
        );
        sponge.absorb(&terms);
        let r = sponge.squeeze_native_field_elements(1)[0];
        self.witness
            .par_iter_mut()
            .zip(&other.witness)
            .for_each(|(w1, w2)| *w1 += *w2 * r);
        self.instance
            .par_iter_mut()
            .zip(&other.instance)
            .for_each(|(x1, x2)| *x1 += *x2 * r);
        self.comm_witness =
            (self.comm_witness + other.comm_witness.mul_bigint(r.into_bigint())).into();
        self.E.par_iter_mut().zip(t).for_each(|(a, b)| *a += r * b);
        self.comm_E = (self.comm_E + comm_T.mul_bigint(r.into_bigint())).into();
        self.u += r;
        self.comm_T = comm_T;
        self.hash += other.hash * r;
    }
}

impl<C: StepCircuit<Fq>> R1CS<C> {
    pub fn new(
        z0: Vec<Fq>,
        circuit: C,
        constants: &PoseidonConfig<Fq>,
        generators: &[G1Affine],
    ) -> Self {
        let empty_shape = ConstraintMatrices::<Fq> {
            num_instance_variables: z0.len(),
            num_witness_variables: 0,
            num_constraints: 0,
            a_num_non_zero: 0,
            b_num_non_zero: 0,
            c_num_non_zero: 0,
            a: vec![],
            b: vec![],
            c: vec![],
        };

        let mut r1cs = Self {
            shape: empty_shape,
            comm_witness: G1Affine {
                x: Fq::zero(),
                y: Fq::one(),
                infinity: true,
            },
            comm_E: G1Affine {
                x: Fq::zero(),
                y: Fq::one(),
                infinity: true,
            },
            comm_T: G1Affine {
                x: Fq::zero(),
                y: Fq::one(),
                infinity: true,
            },
            E: vec![],
            witness: vec![],
            instance: vec![],
            u: Fq::one(),
            hash: Fq::zero(),
            output: z0.clone(),
            circuit,
        };

        // TODO: check if we need to set pc
        let circuit = r1cs.synthesize(
            Fq::zero(),
            G1Affine {
                x: Fq::zero(),
                y: Fq::one(),
                infinity: true,
            },
            Fq::zero(),
            0,
            0,
            0,
            constants,
            generators,
        );
        // Reset mutated variables
        r1cs.output = z0;
        r1cs.hash = Fq::zero();
        r1cs.witness = vec![Fq::zero(); circuit.witness.len()];
        r1cs.instance = vec![Fq::zero(); circuit.instance.len()];
        r1cs.shape = circuit.shape;
        r1cs
    }

    fn commit_t(&self, other: &Self, generators: &[G1Affine]) -> (Vec<Fq>, G1Affine) {
        let (az1, bz1, cz1) = r1cs_matrix_vec_product(
            &self.shape.a,
            &self.shape.b,
            &self.shape.c,
            &[self.witness.as_slice(), &[self.u], self.instance.as_slice()].concat(),
        );
        let (az2, bz2, cz2) = r1cs_matrix_vec_product(
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
            .collect::<Vec<Fq>>();
        let comm_T = commit(generators, &t);
        (t.to_vec(), comm_T)
    }
}

fn create_circuit<C: StepCircuit<Fq>>(
    cs: ConstraintSystemRef<Fq>,
    generators: &[G1Affine],
    hash: Fq,
    circuit: C,
) -> R1CS<C> {
    let matrices = cs.to_matrices().unwrap();
    let cs = cs.borrow().unwrap();
    R1CS {
        shape: matrices.clone(),
        comm_witness: commit(generators, &cs.witness_assignment),
        comm_E: G1Affine {
            x: Fq::zero(),
            y: Fq::one(),
            infinity: true,
        },
        comm_T: G1Affine {
            x: Fq::zero(),
            y: Fq::one(),
            infinity: true,
        },
        E: vec![Fq::zero(); matrices.num_constraints],
        witness: cs.witness_assignment.clone(),
        instance: cs.instance_assignment[1..].to_vec(),
        u: Fq::one(),
        hash,
        output: vec![],
        circuit,
    }
}

#[allow(clippy::type_complexity)]
fn r1cs_matrix_vec_product(
    a: &[Vec<(Fq, usize)>],
    b: &[Vec<(Fq, usize)>],
    c: &[Vec<(Fq, usize)>],
    z: &[Fq],
) -> (Vec<Fq>, Vec<Fq>, Vec<Fq>) {
    let sparse_matrix_vec_product = |m: &[Vec<(Fq, usize)>], z: &[Fq]| -> Vec<Fq> {
        m.par_iter()
            .map(|row| {
                row.par_iter()
                    .fold(Fq::zero, |acc, (coeff, val)| acc + coeff * &z[*val])
                    .reduce(Fq::zero, |acc, val| acc + val)
            })
            .collect::<Vec<Fq>>()
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

#[allow(clippy::too_many_arguments)]
fn compute_io_hash(
    constants: &PoseidonConfig<Fq>,
    cs: &mut ConstraintSystemRef<Fq>,
    params: &FpVar<Fq>,
    i: &FpVar<Fq>,
    pc: &FpVar<Fq>,
    z0: &[FpVar<Fq>],
    output: &[FpVar<Fq>],
    comm_W: &G1AffineVar<Bls12Config>,
    comm_E: &G1AffineVar<Bls12Config>,
    u: &FpVar<Fq>,
    hash: &FpVar<Fq>,
) -> FpVar<Fq> {
    let mut sponge = PoseidonSpongeVar::<Fq>::new(cs.clone(), constants);
    // println!(
    //     "HASHING CIRCUIT WITH params {:?} i {:?} pc {:?} z0 {:?} output {:?} comm_w {:?} comm_e {:?} u {:?} hash {:?}",
    //     params.value().unwrap(),
    //     i.value().unwrap(),
    //     pc.value().unwrap(),
    //     z0.iter().map(|v| v.value().unwrap()).collect::<Vec<Fq>>(),
    //     output
    //         .iter()
    //         .map(|v| v.value().unwrap())
    //         .collect::<Vec<Fq>>(),
    //     comm_W
    //         .to_constraint_field()
    //         .unwrap()
    //         .iter()
    //         .map(|v| v.value().unwrap())
    //         .collect::<Vec<Fq>>(),
    //     comm_E
    //         .to_constraint_field()
    //         .unwrap()
    //         .iter()
    //         .map(|v| v.value().unwrap())
    //         .collect::<Vec<Fq>>(),
    //     u.value().unwrap(),
    //     hash.value().unwrap()
    // );
    sponge.absorb(&params).unwrap();
    sponge.absorb(&i).unwrap();
    sponge.absorb(&pc).unwrap();
    z0.iter().for_each(|v| sponge.absorb(v).unwrap());
    output.iter().for_each(|v| sponge.absorb(v).unwrap());
    sponge
        .absorb(&comm_W.to_constraint_field().unwrap())
        .unwrap();
    sponge
        .absorb(&comm_E.to_constraint_field().unwrap())
        .unwrap();
    sponge.absorb(&u).unwrap();
    sponge.absorb(&hash).unwrap();
    sponge.squeeze_field_elements(1).unwrap().remove(0)
}

#[allow(clippy::too_many_arguments)]
fn compute_r(
    constants: &PoseidonConfig<Fq>,
    cs: &mut ConstraintSystemRef<Fq>,
    params: &FpVar<Fq>,
    comm_W: &G1AffineVar<Bls12Config>,
    comm_E: &G1AffineVar<Bls12Config>,
    u: &FpVar<Fq>,
    hash: &FpVar<Fq>,
    latest_witness: &G1AffineVar<Bls12Config>,
    latest_hash: &FpVar<Fq>,
    T: &G1AffineVar<Bls12Config>,
) -> FpVar<Fq> {
    let mut sponge = PoseidonSpongeVar::<Fq>::new(cs.clone(), constants);
    println!(
        "COMPUTING R IN CIRCUIT AS params {:?} comm_w {:?} comm_e {:?} u {:?} hash {:?} latest_witness {:?} latest_hash {:?} comm_t {:?}",
        params.value().unwrap(),
        comm_W
            .to_constraint_field()
            .unwrap()
            .iter()
            .map(|v| v.value().unwrap())
            .collect::<Vec<Fq>>(),
        comm_E
            .to_constraint_field()
            .unwrap()
            .iter()
            .map(|v| v.value().unwrap())
            .collect::<Vec<Fq>>(),
        u.value().unwrap(),
        hash.value().unwrap(),
        latest_witness
            .to_constraint_field()
            .unwrap()
            .iter()
            .map(|v| v.value().unwrap())
            .collect::<Vec<Fq>>(),
        latest_hash.value().unwrap(),
        T.to_constraint_field()
            .unwrap()
            .iter()
            .map(|v| v.value().unwrap())
            .collect::<Vec<Fq>>(),
    );
    sponge.absorb(params).unwrap();
    sponge
        .absorb(&comm_W.to_constraint_field().unwrap())
        .unwrap();
    sponge
        .absorb(&comm_E.to_constraint_field().unwrap())
        .unwrap();
    sponge.absorb(u).unwrap();
    sponge.absorb(hash).unwrap();
    sponge
        .absorb(&latest_witness.to_constraint_field().unwrap())
        .unwrap();
    sponge.absorb(latest_hash).unwrap();
    sponge.absorb(&T.to_constraint_field().unwrap()).unwrap();
    sponge.squeeze_field_elements(1).unwrap().remove(0)
}
