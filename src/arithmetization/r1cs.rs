//! A collection of logic and structures for running the SuperNova protocol
//! with a relaxed committed R1CS arithmetization.

use crate::{commit, Arithmetization};
use ark_bls12_381::{Config, Fq, G1Affine};
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig, PoseidonSponge},
    CryptographicSponge, FieldBasedCryptographicSponge,
};
use ark_ec::AffineRepr;
use ark_ff::{One, PrimeField, UniformRand, Zero};
use ark_r1cs_std::{
    alloc::AllocVar,
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
use rand_core::OsRng;
use rayon::prelude::*;

// A simplification of the inputs used to create a parameter hash of a circuit.
#[derive(CanonicalSerialize)]
struct SerializableShape {
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

/// A representation of the R1CS instance-witness pair. This is essentially a committed relaxed
/// R1CS instance, and defines logic for native and in-circuit folding.
#[derive(Clone)]
pub struct R1CS {
    pub(crate) shape: ConstraintMatrices<Fq>,
    pub(crate) param: Fq,
    pub(crate) comm_witness: G1Affine,
    pub(crate) comm_E: G1Affine,
    pub(crate) comm_T: G1Affine,
    pub(crate) E: Vec<Fq>,
    pub(crate) witness: Vec<Fq>,
    pub(crate) instance: Vec<Fq>,
    pub(crate) u: Fq,
    pub(crate) hash: Fq,
    pub(crate) output: Vec<Fq>,
}

impl Arithmetization for R1CS {
    type ConstraintSystem = ConstraintSystemRef<Fq>;
    type Input = FpVar<Fq>;

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

    fn is_satisfied(&self, _generators: &[G1Affine]) -> bool {
        // Verify if az * bz = u*cz + E.
        let (az, bz, cz) = self.eval_r1cs();

        if (0..self.shape.num_constraints).any(|i| az[i] * bz[i] != self.u * cz[i] + self.E[i]) {
            return false;
        }

        // Verify if comm_E and comm_witness are commitments to E and witness.
        // NOTE: arkworks does not allow the circuit to be satisfied if you attempt scalar mul in
        // circuit with points at infinity, so this can not work currently. needs to probably swap
        // out the crypto backend.
        // let comm_witness = commit(generators, &self.witness);
        // let comm_E = commit(generators, &self.E);
        // self.comm_witness == comm_witness && self.comm_E == comm_E
        true
    }

    fn output(&self) -> &[Fq] {
        &self.output
    }

    fn params(&self) -> Fq {
        self.param
    }

    fn has_crossterms(&self) -> bool {
        self.E.iter().any(|v| !v.is_zero()) || self.u != Fq::one()
    }

    fn z0(&self) -> Vec<Fq> {
        vec![Fq::zero(); self.output().len()]
    }

    fn hash_terms(&self) -> Vec<Fq> {
        self.z0()
            .into_iter()
            .chain(self.output().to_vec())
            .chain([
                self.comm_witness.x,
                self.comm_witness.y,
                Fq::from(self.comm_witness.infinity),
            ])
            .chain([self.comm_E.x, self.comm_E.y, Fq::from(self.comm_E.infinity)])
            .chain([self.u, self.hash])
            .collect::<Vec<Fq>>()
    }

    fn synthesize<C: Fn(Self::ConstraintSystem, &[Self::Input]) -> Vec<Self::Input>>(
        &mut self,
        params: Fq,
        prev_terms: Vec<Fq>,
        latest_witness: G1Affine,
        latest_hash: Fq,
        old_pc: usize,
        new_pc: usize,
        i: usize,
        constants: &PoseidonConfig<Fq>,
        generators: &[G1Affine],
        circuit: C,
    ) -> R1CS {
        // TODO: program counter should be calculated in circuit, for now it's just supplied by
        // user
        let mut cs = ConstraintSystem::<Fq>::new_ref();
        let old_pc = FpVar::<Fq>::new_witness(cs.clone(), || Ok(Fq::from(old_pc as u64))).unwrap();
        let new_pc = FpVar::<Fq>::new_witness(cs.clone(), || Ok(Fq::from(new_pc as u64))).unwrap();

        // Allocate the inputs which are needed to check correctness of the hash in the latest
        // instance-witness pair.
        let params = FpVar::<_>::new_witness(cs.clone(), || Ok(params)).unwrap();
        let i = FpVar::<_>::new_witness(cs.clone(), || Ok(Fq::from(i as u64))).unwrap();
        let prev_terms = prev_terms
            .iter()
            .map(|v| FpVar::<_>::new_witness(cs.clone(), || Ok(v)).unwrap())
            .collect::<Vec<_>>();
        let latest_witness =
            G1Var::<Config>::new_witness(cs.clone(), || Ok(latest_witness)).unwrap();
        let latest_hash = FpVar::<Fq>::new_witness(cs.clone(), || Ok(latest_hash)).unwrap();

        let zero = FpVar::<_>::new_witness(cs.clone(), || Ok(Fq::zero())).unwrap();
        let one = FpVar::<_>::new_witness(cs.clone(), || Ok(Fq::one())).unwrap();
        let is_base_case = FpVar::<_>::is_eq(&i, &zero).unwrap();

        let i_is_one = FpVar::<_>::is_eq(&i, &one).unwrap();
        let params_select = FpVar::<_>::conditionally_select(&i_is_one, &zero, &params).unwrap();

        let io_hash = compute_io_hash(constants, &mut cs, &params_select, &i, &old_pc, &prev_terms);

        let comp_hash = FpVar::<Fq>::conditionally_select(&is_base_case, &zero, &io_hash).unwrap();
        FpVar::<Fq>::enforce_equal(&comp_hash, &latest_hash).unwrap();

        // Compute folding in-circuit.
        let comm_W = G1Var::<Config>::new_witness(cs.clone(), || Ok(self.comm_witness)).unwrap();
        let comm_E = G1Var::<Config>::new_witness(cs.clone(), || Ok(self.comm_E)).unwrap();
        let u = FpVar::<Fq>::new_witness(cs.clone(), || Ok(self.u)).unwrap();
        let hash = FpVar::<Fq>::new_witness(cs.clone(), || Ok(self.hash)).unwrap();
        let T = G1Var::<Config>::new_witness(cs.clone(), || Ok(self.comm_T)).unwrap();

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

        // NOTE: this is unsatisfiable in arkworks with points at infinity.
        let rW = latest_witness
            .scalar_mul_le(r.to_bits_le().unwrap().iter())
            .unwrap();
        let W_fold = comm_W.clone().add(&rW);

        let rT = T.scalar_mul_le(r.to_bits_le().unwrap().iter()).unwrap();
        let E_fold = comm_E.clone().add(&rT);

        let u_fold = u.clone().add(&r);

        let r_hash = latest_hash.clone().mul(&r);
        let hash_fold = hash.add(&r_hash);

        // Pick variables for the new hash input.
        let W_new = G1Var::<Config>::conditionally_select(&is_base_case, &comm_W, &W_fold).unwrap();
        let E_new = G1Var::<Config>::conditionally_select(&is_base_case, &comm_E, &E_fold).unwrap();
        let u_new = FpVar::<_>::conditionally_select(&is_base_case, &u, &u_fold).unwrap();
        let hash_new =
            FpVar::<_>::conditionally_select(&is_base_case, &latest_hash, &hash_fold).unwrap();

        let i_new =
            FpVar::<_>::new_witness(cs.clone(), || Ok(i.value().unwrap() + Fq::one())).unwrap();

        let output = self
            .output()
            .iter()
            .map(|v| FpVar::<_>::new_witness(cs.clone(), || Ok(v)).unwrap())
            .collect::<Vec<_>>();

        // Generate the new output by running the step circuit.
        let z0 = self
            .z0()
            .iter()
            .map(|v| FpVar::<_>::new_witness(cs.clone(), || Ok(v)).unwrap())
            .collect::<Vec<_>>();
        let new_input = output
            .iter()
            .zip(&z0)
            .map(|(v_output, v_0)| {
                FpVar::<_>::conditionally_select(&is_base_case, v_0, v_output).unwrap()
            })
            .collect::<Vec<FpVar<Fq>>>();

        let output = circuit(cs.clone(), &new_input);

        let terms = z0
            .into_iter()
            .chain(output.clone())
            .chain(W_new.to_affine().unwrap().to_constraint_field().unwrap())
            .chain(E_new.to_affine().unwrap().to_constraint_field().unwrap())
            .chain([u_new, hash_new])
            .collect::<Vec<FpVar<_>>>();

        let hash = FpVar::<_>::new_input(cs.clone(), || {
            Ok(
                compute_io_hash(constants, &mut cs, &params, &i_new, &new_pc, &terms)
                    .value()
                    .unwrap(),
            )
        })
        .unwrap();
        cs.finalize();

        // Set the new output for later use.
        self.output = output
            .iter()
            .map(|v| v.value().unwrap())
            .collect::<Vec<Fq>>();

        // Generate a new R1CS instance-witness pair which contains the circuit we've just built.
        let matrices = cs.to_matrices().unwrap();
        let cs = cs.borrow().unwrap();
        // NOTE: we randomise commitments since points at infinity are not casted the same natively
        // and in-circuit, which leads to hash discrepancies.
        R1CS {
            shape: matrices.clone(),
            param: self.param,
            comm_witness: commit(generators, &cs.witness_assignment),
            comm_E: G1Affine::rand(&mut OsRng {}),
            comm_T: G1Affine::rand(&mut OsRng {}),
            E: vec![Fq::zero(); matrices.num_constraints],
            witness: cs.witness_assignment.clone(),
            instance: cs.instance_assignment[1..].to_vec(),
            u: Fq::one(),
            hash: hash.value().unwrap(),
            output: vec![],
        }
    }

    fn fold(
        &mut self,
        other: &Self,
        constants: &PoseidonConfig<Fq>,
        generators: &[G1Affine],
        params: Fq,
    ) {
        let mut sponge = PoseidonSponge::<Fq>::new(constants);
        sponge.absorb(
            &[params]
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
                .chain([self.comm_T.x, self.comm_T.y, Fq::from(self.comm_T.infinity)])
                .collect::<Vec<Fq>>(),
        );
        let r = sponge.squeeze_native_field_elements(1)[0];
        let (t, comm_T) = self.commit_t(other, generators);
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
        self.comm_E = (self.comm_E + self.comm_T.mul_bigint(r.into_bigint())).into();
        self.u += r;
        self.comm_T = comm_T;
        self.hash += other.hash * r;
    }
}

impl R1CS {
    /// Returns a new R1CS instance-witness pair with the given step circuit.
    pub fn new<
        C: Fn(
            <Self as Arithmetization>::ConstraintSystem,
            &[<Self as Arithmetization>::Input],
        ) -> Vec<<Self as Arithmetization>::Input>,
    >(
        z0: Vec<Fq>,
        c: &C,
        constants: &PoseidonConfig<Fq>,
        generators: &[G1Affine],
    ) -> (Self, Self) {
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

        // NOTE: we randomise commitments as points at infinity are not casted the same natively
        // and in-circuit, which leads to hash discrepancies.
        let mut r1cs = Self {
            shape: empty_shape,
            param: Fq::zero(),
            comm_witness: G1Affine::rand(&mut OsRng {}),
            comm_E: G1Affine::rand(&mut OsRng {}),
            comm_T: G1Affine::rand(&mut OsRng {}),
            E: vec![],
            witness: vec![],
            instance: vec![],
            u: Fq::one(),
            hash: Fq::zero(),
            output: z0,
        };

        // TODO: check if we need to set pc
        let mut circuit = r1cs.synthesize(
            Fq::zero(),
            r1cs.hash_terms(),
            G1Affine::rand(&mut OsRng {}),
            Fq::zero(),
            0,
            0,
            0,
            constants,
            generators,
            c,
        );

        // Fix mutated variables.
        r1cs.hash = Fq::zero();
        r1cs.witness = circuit.witness.clone();
        r1cs.instance = circuit.instance.clone();
        r1cs.E = vec![Fq::zero(); circuit.shape.num_constraints];
        let param = SerializableShape::from(&circuit.shape).digest(constants);
        r1cs.param = param;
        circuit.param = param;
        r1cs.shape = circuit.shape.clone();
        (r1cs, circuit)
    }

    // Returns T and the commitment to T, which captures some of the relaxed R1CS crossterms.
    fn commit_t(&self, other: &Self, generators: &[G1Affine]) -> (Vec<Fq>, G1Affine) {
        let (az1, bz1, cz1) = self.eval_r1cs();
        let (az2, bz2, cz2) = other.eval_r1cs();

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
        let mut comm_T = commit(generators, &t);

        // NOTE: During our first fold in the base case, we may generate a commitment point that's at
        // infinity. In this case, we need to ensure that the point isn't at infinity, otherwise
        // the circuit is no longer satisfiable. This is due to some peculiarty, likely in
        // arkworks, that needs to be investigated.
        if comm_T.infinity {
            comm_T = G1Affine::rand(&mut OsRng {});
        }

        (t, comm_T)
    }

    // Evaluates the R1CS by multiplying the instance-witness vector with the coefficient matrices.
    // Returns Az, Bz and Cz, which are used for checking satisfiability of constraint equations.
    #[allow(clippy::type_complexity)]
    fn eval_r1cs(&self) -> (Vec<Fq>, Vec<Fq>, Vec<Fq>) {
        let sparse_matrix_vec_product = |m: &[Vec<(Fq, usize)>], z: &[Fq]| -> Vec<Fq> {
            m.par_iter()
                .map(|row| {
                    row.par_iter()
                        .fold(Fq::zero, |acc, (coeff, val)| acc + coeff * &z[*val])
                        .reduce(Fq::zero, |acc, val| acc + val)
                })
                .collect::<Vec<Fq>>()
        };

        let z = vec![vec![self.u], self.instance.clone(), self.witness.clone()].concat();
        (
            sparse_matrix_vec_product(&self.shape.a, &z),
            sparse_matrix_vec_product(&self.shape.b, &z),
            sparse_matrix_vec_product(&self.shape.c, &z),
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn compute_io_hash(
    constants: &PoseidonConfig<Fq>,
    cs: &mut ConstraintSystemRef<Fq>,
    params: &FpVar<Fq>,
    i: &FpVar<Fq>,
    pc: &FpVar<Fq>,
    prev_terms: &[FpVar<Fq>],
) -> FpVar<Fq> {
    let mut sponge = PoseidonSpongeVar::<Fq>::new(cs.clone(), constants);
    sponge.absorb(&params).unwrap();
    sponge.absorb(&i).unwrap();
    sponge.absorb(&pc).unwrap();
    prev_terms.iter().for_each(|v| sponge.absorb(v).unwrap());
    sponge.squeeze_field_elements(1).unwrap().remove(0)
}

#[allow(clippy::too_many_arguments)]
fn compute_r(
    constants: &PoseidonConfig<Fq>,
    cs: &mut ConstraintSystemRef<Fq>,
    params: &FpVar<Fq>,
    comm_W: &G1AffineVar<Config>,
    comm_E: &G1AffineVar<Config>,
    u: &FpVar<Fq>,
    hash: &FpVar<Fq>,
    latest_witness: &G1AffineVar<Config>,
    latest_hash: &FpVar<Fq>,
    T: &G1AffineVar<Config>,
) -> FpVar<Fq> {
    let mut sponge = PoseidonSpongeVar::<Fq>::new(cs.clone(), constants);
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
