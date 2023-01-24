pub mod plonk;
pub mod r1cs;

use halo2curves::bn256::Fr;
use std::ops::{Add, AddAssign};

pub trait Arithmetization: Default + Clone {
    fn is_satisfied(&self) -> bool;

    fn is_zero(&self) -> bool;

    fn public_inputs(&self) -> &[Fr];

    fn params(&self) -> Fr;

    fn push_hash(&mut self, x: Fr);

    fn has_crossterms(&self) -> bool;
}

pub trait FoldedArithmetization<A: Arithmetization>:
    Add<A> + AddAssign<A> + Arithmetization
{
    fn digest(&self) -> Fr;
}
