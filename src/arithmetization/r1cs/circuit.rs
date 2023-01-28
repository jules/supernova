use crate::{Arithmetization, FoldedArithmetization};
use core::ops::{Add, AddAssign};
use halo2curves::FieldExt;

#[derive(Clone, Default)]
pub struct R1CS<S: FieldExt> {
    pub(crate) num_consts: usize,
    pub(crate) num_vars: usize,
    pub(crate) num_public_inputs: usize,
    pub(crate) A: Vec<Vec<S>>,
    pub(crate) B: Vec<Vec<S>>,
    pub(crate) C: Vec<Vec<S>>,
    pub(crate) witness: Vec<S>,
    pub(crate) instance: Vec<S>,
}

impl<S: FieldExt> Arithmetization<S> for R1CS<S> {
    // TODO
    fn is_satisfied(&self) -> bool {
        false
    }

    // TODO
    fn is_zero(&self) -> bool {
        false
    }

    fn public_inputs(&self) -> &[S] {
        &self.instance
    }

    fn params(&self) -> S {
        S::from(self.A.len() as u64) + S::from(self.num_vars as u64)
    }

    // TODO
    fn push_hash(&mut self, x: S) {
        todo!()
    }

    // TODO
    fn has_crossterms(&self) -> bool {
        false
    }

    fn z0(&self) -> Vec<S> {
        vec![S::zero(); self.num_public_inputs]
    }

    fn inputs(&self) -> Vec<S> {
        let mut inputs = self.witness.clone();
        inputs.extend(self.instance.clone());
        inputs
    }
}

impl<S: FieldExt> FoldedArithmetization<S, R1CS<S>> for R1CS<S> {
    // TODO
    fn digest(&self) -> S {
        todo!()
    }
}

impl<S: FieldExt> Add<R1CS<S>> for R1CS<S> {
    type Output = Self;

    // TODO
    fn add(mut self, other: Self) -> Self {
        self += other;
        self
    }
}

impl<S: FieldExt> AddAssign<R1CS<S>> for R1CS<S> {
    // TODO
    fn add_assign(&mut self, other: Self) {
        todo!()
    }
}
