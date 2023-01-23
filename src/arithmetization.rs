pub mod plonk;
pub mod r1cs;

use std::ops::{Add, AddAssign};

pub trait Arithmetization: Default + Clone {
    fn is_satisfied(&self) -> bool;

    fn is_zero(&self) -> bool;
}

pub trait FoldedArithmetization<A: Arithmetization>:
    Add<A> + AddAssign<A> + Arithmetization
{
}
