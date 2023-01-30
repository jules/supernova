//! A collection of structures generated by the [`ProvingAssignment`] constraint system,
//! used for the SuperNova protocol when instantiated on R1CS circuits.

use crate::{commit, r1cs::ProvingAssignment, Arithmetization};
use bellperson::{gadgets::num::AllocatedNum, ConstraintSystem};
use core::ops::{Add, AddAssign};
use group::ff::{Field, PrimeField};
use itertools::concat;
use neptune::{circuit2::poseidon_hash_allocated, poseidon::PoseidonConstants, Poseidon};
use pasta_curves::arithmetic::CurveExt;
use rayon::prelude::*;
use serde::Serialize;
use sha3::{Digest, Sha3_256};
use typenum::U4;

#[derive(Clone)]
pub struct CircuitShape<G: CurveExt> {
    pub(crate) num_vars: usize,
    pub(crate) num_public_inputs: usize,
    pub(crate) A: Vec<Vec<G::ScalarExt>>,
    pub(crate) B: Vec<Vec<G::ScalarExt>>,
    pub(crate) C: Vec<Vec<G::ScalarExt>>,
}

#[derive(Serialize)]
pub struct SerializableShape {
    num_vars: usize,
    num_public_inputs: usize,
    A: Vec<Vec<Vec<u8>>>,
    B: Vec<Vec<Vec<u8>>>,
    C: Vec<Vec<Vec<u8>>>,
}

impl<G: CurveExt> CircuitShape<G> {
    fn digest(&self) -> G::ScalarExt {
        let convert_matrix = |m: &[Vec<G::ScalarExt>]| -> Vec<Vec<Vec<u8>>> {
            m.iter()
                .map(|row| {
                    row.iter()
                        .map(|value| {
                            let repr = value.to_repr();
                            let slice = repr.as_ref();
                            let mut bytes = vec![0u8; slice.len()];
                            bytes.copy_from_slice(slice);
                            bytes
                        })
                        .collect::<Vec<Vec<u8>>>()
                })
                .collect::<Vec<Vec<Vec<u8>>>>()
        };

        let serializable = SerializableShape {
            num_vars: self.num_vars,
            num_public_inputs: self.num_public_inputs,
            A: convert_matrix(&self.A),
            B: convert_matrix(&self.B),
            C: convert_matrix(&self.C),
        };

        let bytes = bincode::serialize(&serializable).unwrap();

        let mut hasher = Sha3_256::new();
        hasher.input(&bytes);
        let digest = hasher.result();

        let mut repr = <G::ScalarExt as PrimeField>::Repr::default();
        let len = repr.as_ref().len();
        repr.as_mut().copy_from_slice(&digest[..len]);
        G::ScalarExt::from_repr(repr).unwrap()
    }

    #[allow(clippy::type_complexity)]
    fn multiply_vec(
        &self,
        z: &[G::ScalarExt],
    ) -> (Vec<G::ScalarExt>, Vec<G::ScalarExt>, Vec<G::ScalarExt>) {
        if z.len() != self.num_public_inputs + self.num_vars + 1 {
            // TODO: shouldnt panic here
            panic!("mismatched inputs to shape");
        }

        // computes a product between a sparse matrix `M` and a vector `z`
        // This does not perform any validation of entries in M (e.g., if entries
        // in `M` reference indexes outside the range of `z`).
        // This is safe since we know that `M` is valid
        let sparse_matrix_vec_product =
            |m: &[Vec<G::ScalarExt>], z: &[G::ScalarExt]| -> Vec<G::ScalarExt> {
                m.par_iter()
                    .map(|row| {
                        row.par_iter()
                            .zip(z)
                            .fold(G::ScalarExt::zero, |acc, (val, v)| acc + (*val * v))
                            .reduce(G::ScalarExt::zero, |acc, val| acc + val)
                    })
                    .collect::<Vec<G::ScalarExt>>()
            };

        let (Az, (Bz, Cz)) = rayon::join(
            || sparse_matrix_vec_product(&self.A, z),
            || {
                rayon::join(
                    || sparse_matrix_vec_product(&self.B, z),
                    || sparse_matrix_vec_product(&self.C, z),
                )
            },
        );

        (Az, Bz, Cz)
    }
}

#[derive(Clone)]
pub struct R1CS<G: CurveExt> {
    pub(crate) generators: Vec<G>,
    pub(crate) shape: CircuitShape<G>,
    pub(crate) comm_witness: G,
    pub(crate) comm_E: G,
    pub(crate) E: Vec<G::ScalarExt>,
    pub(crate) witness: Vec<G::ScalarExt>,
    pub(crate) instance: Vec<G::ScalarExt>,
    pub(crate) u: G::ScalarExt,
}

impl<G: CurveExt> R1CS<G> {
    fn commit_t(&self, other: &Self) -> (Vec<G::ScalarExt>, G) {
        let (az1, bz1, cz1) = {
            let z1 = concat(vec![
                self.witness.clone(),
                vec![self.u],
                self.instance.clone(),
            ]);
            self.shape.multiply_vec(&z1)
        };

        let (az2, bz2, cz2) = {
            let z2 = concat(vec![
                other.witness.clone(),
                vec![G::ScalarExt::one()],
                other.instance.clone(),
            ]);
            self.shape.multiply_vec(&z2)
        };

        let az1_times_bz2 = (0..az1.len())
            .into_par_iter()
            .map(|i| az1[i] * bz2[i])
            .collect::<Vec<G::ScalarExt>>();
        let az2_times_bz1 = (0..az2.len())
            .into_par_iter()
            .map(|i| az2[i] * bz1[i])
            .collect::<Vec<G::ScalarExt>>();
        let u1_times_cz2 = (0..cz2.len())
            .into_par_iter()
            .map(|i| self.u * cz2[i])
            .collect::<Vec<G::ScalarExt>>();

        let t = az1_times_bz2
            .par_iter()
            .zip(&az2_times_bz1)
            .zip(&u1_times_cz2)
            .zip(&cz1)
            .map(|(((a, b), c), d)| *a + *b - *c - *d)
            .collect::<Vec<G::ScalarExt>>();

        let comm_T = commit(&self.generators, &t);

        (t, comm_T)
    }
}

impl<G: CurveExt> Arithmetization<G> for R1CS<G> {
    fn digest(&self) -> G::ScalarExt {
        let constants = PoseidonConstants::<_, U4>::new();
        let mut poseidon = Poseidon::new(&constants);
        let bases = vec![
            self.comm_witness.jacobian_coordinates().0,
            self.comm_witness.jacobian_coordinates().1,
            self.comm_witness.jacobian_coordinates().2,
        ];
        poseidon.set_preimage(
            bases
                .into_iter()
                .chain(self.witness.clone().into_iter().map(scalar_to_base::<G>))
                .collect::<Vec<_>>()
                .as_slice(),
        );
        base_to_scalar::<G>(poseidon.hash())
    }

    // TODO
    fn is_satisfied(&self) -> bool {
        false
    }

    fn is_zero(&self) -> bool {
        self.witness.iter().all(|v| v.is_zero().into())
            && self.instance.iter().all(|v| v.is_zero().into())
    }

    fn public_inputs(&self) -> &[G::ScalarExt] {
        &self.instance
    }

    fn params(&self) -> G::ScalarExt {
        G::ScalarExt::from(self.shape.A.len() as u64)
            + G::ScalarExt::from(self.shape.num_vars as u64)
    }

    fn push_hash(&mut self, elements: Vec<G::ScalarExt>) {
        let mut cs = ProvingAssignment::<G>::default();
        let elements = elements
            .iter()
            .enumerate()
            .map(|(i, value)| {
                AllocatedNum::alloc_input(cs.namespace(|| format!("data {}", i)), || Ok(*value))
                    .unwrap()
            })
            .collect::<Vec<AllocatedNum<_>>>();
        let constants = PoseidonConstants::<_, U4>::new();
        poseidon_hash_allocated(cs.namespace(|| "poseidon hash"), elements, &constants)
            .expect("should be able to hash");

        // TODO: ensure generators are okay
        let mut hash_circuit = cs.create_circuit(&self.generators);
        hash_circuit.shape.A.append(&mut self.shape.A);
        hash_circuit.shape.B.append(&mut self.shape.B);
        hash_circuit.shape.C.append(&mut self.shape.C);
        self.shape.num_vars += hash_circuit.shape.num_vars;
        self.shape.num_public_inputs += hash_circuit.shape.num_public_inputs;
        self.shape.A = hash_circuit.shape.A;
        self.shape.B = hash_circuit.shape.B;
        self.shape.C = hash_circuit.shape.C;
        self.comm_witness += hash_circuit.comm_witness;
        self.comm_E += hash_circuit.comm_E;
        hash_circuit.E.append(&mut self.E);
        self.E = hash_circuit.E;
        hash_circuit.witness.append(&mut self.witness);
        self.witness = hash_circuit.witness;
        hash_circuit.instance.append(&mut self.instance);
        self.instance = hash_circuit.instance;
    }

    fn has_crossterms(&self) -> bool {
        self.E.iter().any(|v| (!v.is_zero()).into()) && self.u != G::ScalarExt::one()
    }

    fn z0(&self) -> Vec<G::ScalarExt> {
        vec![G::ScalarExt::zero(); self.shape.num_public_inputs]
    }
}

impl<G: CurveExt> Add<R1CS<G>> for R1CS<G> {
    type Output = Self;

    fn add(mut self, other: Self) -> Self {
        self += other;
        self
    }
}

impl<G: CurveExt> AddAssign<R1CS<G>> for R1CS<G> {
    fn add_assign(&mut self, other: Self) {
        let constants = PoseidonConstants::<_, U4>::new();
        let mut poseidon = Poseidon::new(&constants);
        let (t, comm_T) = self.commit_t(&other);
        poseidon.set_preimage(
            &[self.shape.digest()]
                .into_iter()
                .chain(self.instance.clone())
                .chain(other.instance.clone())
                .chain(t.clone())
                .collect::<Vec<G::ScalarExt>>(),
        );
        let r = poseidon.hash();
        self.instance
            .par_iter_mut()
            .zip(other.instance)
            .for_each(|(x1, x2)| *x1 += x2 * r);
        self.comm_witness += other.comm_witness * r;
        self.E.par_iter_mut().zip(t).for_each(|(a, b)| *a += r * b);
        self.comm_E += comm_T * r;
        self.u += r;
    }
}

fn scalar_to_base<G: CurveExt>(scalar: G::ScalarExt) -> G::Base {
    let repr = scalar.to_repr();
    let mut base_repr = <G::Base as PrimeField>::Repr::default();
    base_repr.as_mut().copy_from_slice(repr.as_ref());
    G::Base::from_repr(base_repr).unwrap()
}

fn base_to_scalar<G: CurveExt>(base: G::Base) -> G::ScalarExt {
    let repr = base.to_repr();
    let mut scalar_repr = <G::ScalarExt as PrimeField>::Repr::default();
    scalar_repr.as_mut().copy_from_slice(repr.as_ref());
    G::ScalarExt::from_repr(scalar_repr).unwrap()
}
