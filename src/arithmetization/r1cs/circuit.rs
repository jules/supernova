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
use typenum::{U12, U6};

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
        // TODO: jank-ass clamping
        repr.as_mut()[0] = 0;
        repr.as_mut()[31] = 0;
        G::ScalarExt::from_repr_vartime(repr).unwrap()
    }

    #[allow(clippy::type_complexity)]
    fn multiply_vec(
        &self,
        z: &[G::ScalarExt],
    ) -> (Vec<G::ScalarExt>, Vec<G::ScalarExt>, Vec<G::ScalarExt>) {
        if z.len() != self.num_vars + self.num_public_inputs + 1 {
            // TODO: shouldnt panic here
            panic!("mismatched inputs to shape");
        }

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
    pub(crate) output: Vec<G::ScalarExt>,
}

impl<G: CurveExt> R1CS<G> {
    fn commit_t(&self, other: &Self) -> (Vec<G::ScalarExt>, G) {
        let (az1, bz1, cz1) = self
            .shape
            .multiply_vec(&[self.witness.as_slice(), &[self.u], self.instance.as_slice()].concat());
        let (az2, bz2, cz2) = self.shape.multiply_vec(
            &[
                other.witness.as_slice(),
                &[other.u],
                other.instance.as_slice(),
            ]
            .concat(),
        );

        let t = az1
            .into_par_iter()
            .zip(bz2)
            .zip(az2)
            .zip(bz1)
            .zip(cz1)
            .zip(cz2)
            .map(|(((((az1, bz2), az2), bz1), cz1), cz2)| {
                az1 * bz2 + az2 * bz1 - self.u * cz2 - cz1
            })
            .collect::<Vec<G::ScalarExt>>();
        let comm_T = commit(&self.generators, &t);
        (t, comm_T)
    }

    fn prepend(&mut self, mut other: Self) {
        other.shape.A.append(&mut self.shape.A);
        other.shape.B.append(&mut self.shape.B);
        other.shape.C.append(&mut self.shape.C);
        self.shape.num_vars += other.shape.num_vars;
        self.shape.num_public_inputs += other.shape.num_public_inputs;
        self.shape.A = other.shape.A;
        self.shape.B = other.shape.B;
        self.shape.C = other.shape.C;
        self.comm_witness += other.comm_witness;
        self.comm_E += other.comm_E;
        other.E.append(&mut self.E);
        self.E = other.E;
        other.witness.append(&mut self.witness);
        self.witness = other.witness;
        other.instance.append(&mut self.instance);
        self.instance = other.instance;
    }
}

impl<G: CurveExt> Arithmetization<G> for R1CS<G> {
    fn digest(&self) -> G::ScalarExt {
        let constants = PoseidonConstants::<_, U6>::new();
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

    fn is_satisfied(&self) -> bool {
        let num_constraints = self.shape.A.len();
        if self.witness.len() != self.shape.num_vars
            || self.E.len() != num_constraints
            || self.instance.len() != self.shape.num_public_inputs
        {
            return false;
        }

        // Verify if az * bz = u*cz + E.
        let z = concat(vec![
            self.witness.clone(),
            vec![self.u],
            self.instance.clone(),
        ]);
        let (az, bz, cz) = self.shape.multiply_vec(&z);
        if az.len() != num_constraints || bz.len() != num_constraints || cz.len() != num_constraints
        {
            return false;
        }

        if (0..num_constraints)
            .map(|i| usize::from(az[i] * bz[i] != self.u * cz[i] + self.E[i]))
            .sum::<usize>()
            != 0
        {
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

    fn public_inputs(&self) -> &[G::ScalarExt] {
        &self.instance
    }

    fn output(&self) -> &[G::ScalarExt] {
        &self.output
    }

    fn params(&self) -> G::ScalarExt {
        G::ScalarExt::from(self.shape.A.len() as u64)
            + G::ScalarExt::from(self.shape.num_vars as u64)
    }

    fn push_hash(&mut self, elements: Vec<G::ScalarExt>) {
        let mut cs = ProvingAssignment::<G>::default();
        println!("{:?}", elements);
        let elements = elements
            .iter()
            .enumerate()
            .map(|(i, value)| {
                AllocatedNum::alloc_input(cs.namespace(|| format!("data {}", i)), || Ok(*value))
                    .unwrap()
            })
            .collect::<Vec<AllocatedNum<_>>>();
        let constants = PoseidonConstants::<_, U12>::new();
        let result =
            poseidon_hash_allocated(cs.namespace(|| "poseidon hash"), elements, &constants)
                .expect("should be able to hash");

        let hash_circuit = cs.create_circuit(&self.generators);
        self.prepend(hash_circuit);
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
        let constants = PoseidonConstants::<_, U6>::new();
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
