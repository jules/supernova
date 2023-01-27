use crate::Arithmetization;
use halo2curves::FieldExt;

#[derive(Clone, Default)]
pub struct R1CS<Scalar: FieldExt> {
    pub(crate) num_consts: usize,
    pub(crate) num_vars: usize,
    pub(crate) num_public_inputs: usize,
    pub(crate) A: Vec<Vec<Scalar>>,
    pub(crate) B: Vec<Vec<Scalar>>,
    pub(crate) C: Vec<Vec<Scalar>>,
}

impl<Scalar: FieldExt> Arithmetization<Scalar> for R1CS<Scalar> {
    // TODO
    fn is_satisfied(&self) -> bool {
        false
    }

    // TODO
    fn is_zero(&self) -> bool {
        false
    }

    // TODO
    fn public_inputs(&self) -> &[Scalar] {
        todo!()
    }

    fn params(&self) -> Scalar {
        Scalar::from(self.A.len() as u64) + Scalar::from(self.num_vars as u64)
    }

    // TODO
    fn push_hash(&mut self, x: Scalar) {
        todo!()
    }

    // TODO
    fn has_crossterms(&self) -> bool {
        false
    }

    fn z0(&self) -> Vec<Scalar> {
        vec![Scalar::zero(); self.num_public_inputs]
    }

    // TODO
    fn inputs(&self) -> Vec<Scalar> {
        todo!()
    }
}
