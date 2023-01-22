mod arithmetization;
use arithmetization::FoldedArithmetization;

pub enum Error {}

pub struct Prover<T, F: FoldedArithmetization<T>> {
    folded: Vec<F>,
    latest: T,
    pc: u16,
}

pub fn verify<T, F: FoldedArithmetization<T>>(
    folded: Vec<F>,
    latest: T,
    pc: u16,
) -> Result<bool, Error> {
    unimplemented!()
}
