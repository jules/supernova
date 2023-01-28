use crate::{Arithmetization, FoldedArithmetization};
use core::ops::{Add, AddAssign};
use group::ff::Field;
use halo2curves::CurveExt;

#[derive(Clone)]
pub struct CircuitShape<G: CurveExt> {
    pub(crate) num_consts: usize,
    pub(crate) num_vars: usize,
    pub(crate) num_public_inputs: usize,
    pub(crate) A: Vec<Vec<G::ScalarExt>>,
    pub(crate) B: Vec<Vec<G::ScalarExt>>,
    pub(crate) C: Vec<Vec<G::ScalarExt>>,
}

#[derive(Clone)]
pub struct R1CS<G: CurveExt> {
    pub(crate) shape: CircuitShape<G>,
    pub(crate) comm_witness: G,
    pub(crate) comm_E: G,
    pub(crate) instance: Vec<G::ScalarExt>,
    pub(crate) u: G::ScalarExt,
}

impl<G: CurveExt> Arithmetization<G> for R1CS<G> {
    // TODO
    fn is_satisfied(&self) -> bool {
        false
    }

    // TODO
    fn is_zero(&self) -> bool {
        false
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

    // TODO
    fn has_crossterms(&self) -> bool {
        false
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

    // TODO
    fn add(mut self, other: Self) -> Self {
        self += other;
        self
    }
}

impl<G: CurveExt> AddAssign<R1CS<G>> for R1CS<G> {
    // TODO
    fn add_assign(&mut self, other: Self) {
        todo!()
    }
}
