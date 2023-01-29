use crate::{commit, Arithmetization, FoldedArithmetization};
use core::ops::{Add, AddAssign};
use group::ff::Field;
use halo2curves::CurveExt;
use itertools::concat;
use poseidon::Poseidon;
use rayon::prelude::*;

#[derive(Clone)]
pub struct CircuitShape<G: CurveExt> {
    pub(crate) num_vars: usize,
    pub(crate) num_public_inputs: usize,
    pub(crate) A: Vec<Vec<G::ScalarExt>>,
    pub(crate) B: Vec<Vec<G::ScalarExt>>,
    pub(crate) C: Vec<Vec<G::ScalarExt>>,
}

impl<G: CurveExt> CircuitShape<G> {
    // TODO
    fn digest(&self) -> G::ScalarExt {
        todo!()
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
        // This does not perform any validation of entries in M (e.g., if entries in `M` reference indexes outside the range of `z`)
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
    // TODO
    fn is_satisfied(&self) -> bool {
        false
    }

    fn is_zero(&self) -> bool {
        self.witness.iter().all(|v| (v.is_zero()).into())
            && self.instance.iter().all(|v| (v.is_zero()).into())
    }

    fn public_inputs(&self) -> &[G::ScalarExt] {
        &self.instance
    }

    fn params(&self) -> G::ScalarExt {
        G::ScalarExt::from(self.shape.A.len() as u64)
            + G::ScalarExt::from(self.shape.num_vars as u64)
    }

    // TODO
    fn push_hash(&mut self, x: G::ScalarExt) {
        todo!()
    }

    fn has_crossterms(&self) -> bool {
        self.E.iter().any(|v| (!v.is_zero()).into()) && self.u != G::ScalarExt::one()
    }

    fn z0(&self) -> Vec<G::ScalarExt> {
        vec![G::ScalarExt::zero(); self.shape.num_public_inputs]
    }
}

impl<G: CurveExt> FoldedArithmetization<G, R1CS<G>> for R1CS<G> {
    // TODO
    fn digest(&self) -> G::ScalarExt {
        todo!()
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
        let mut poseidon: Poseidon<G::ScalarExt, 5, 4> = Poseidon::new(8, 5);
        let (t, comm_T) = self.commit_t(&other);
        poseidon.update(
            &[self.shape.digest()]
                .into_iter()
                .chain(self.instance.clone())
                .chain(other.instance.clone())
                .chain(t.clone())
                .collect::<Vec<G::ScalarExt>>(),
        );
        let r = poseidon.squeeze();
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
