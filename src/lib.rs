mod arithmetization;
use arithmetization::*;

pub enum Error {}

#[derive(Default, PartialEq, Eq)]
pub struct Proof<A: Arithmetization, F: FoldedArithmetization<A>> {
    folded: Vec<F>,
    latest: A,
    pc: usize,
}

impl<A: Arithmetization, F: FoldedArithmetization<A>> Proof<A, F> {
    /// Reinstantiate a SuperNova proof.
    ///
    /// NOTE: only to be used to continue an already active prover.
    /// If you're starting from scratch, consider using [`Proof::default()`] instead.
    pub fn new(folded: Vec<F>, latest: A, pc: usize) -> Self {
        Self { folded, latest, pc }
    }

    pub fn update(&mut self, next: A, pc: usize) {
        self.folded[self.pc] += self.latest.clone();
        self.latest = next;
        self.pc = pc;
        // TODO: set IO
    }
}

/// Verify a SuperNova proof.
///
/// TODO: error verbosity
pub fn verify<A: Arithmetization, F: FoldedArithmetization<A>>(
    proof: Proof<A, F>,
) -> Result<bool, Error> {
    // TODO: Check that the public IO of the latest instance includes
    // the correct hash.

    // Ensure PC is within range.
    if proof.pc > proof.folded.len() {
        return Ok(false);
    }

    // TODO: Ensure the latest instance has no crossterms.

    // Ensure all folded instance/witness pairs are satisfied.
    if proof.folded.iter().any(|pair| !pair.is_satisfied()) {
        return Ok(false);
    }

    // Ensure the latest instance/witness pair is satisfied.
    if !proof.latest.is_satisfied() {
        return Ok(false);
    }

    todo!();
    Ok(true)
}
