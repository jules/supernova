pub mod plonk;
pub mod r1cs;

use std::ops::{Add, AddAssign};

pub trait FoldedArithmetization<T>: Add<T> + AddAssign<T> + Default {}
