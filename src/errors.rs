use ark_ff::Field;
use std::fmt::{Display, Formatter, Result};

/// A list of possible errors that can occur during proof verification.
#[derive(Debug)]
pub enum VerificationError<F: Field> {
    ExpectedBaseCase,
    HashMismatch(F, F),
    PCOutOfRange(usize, usize),
    UnexpectedCrossterms,
    UnsatisfiedCircuit,
}

impl<F: Field> Display for VerificationError<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            VerificationError::ExpectedBaseCase => write!(f, "ERROR: expected base case"),
            VerificationError::HashMismatch(result, expected) => {
                write!(
                    f,
                    "ERROR: hash mismatch\nresult: {result:?}\nexpected: {expected:?}"
                )
            }
            VerificationError::PCOutOfRange(counter, limit) => write!(
                f,
                "ERROR: program counter out of range\ncounter: {counter}\nlimit: {limit}"
            ),
            VerificationError::UnexpectedCrossterms => {
                write!(f, "ERROR: unexpected crossterms in unfolded circuit")
            }
            VerificationError::UnsatisfiedCircuit => write!(f, "ERROR: unsatisfied circuit"),
        }
    }
}
