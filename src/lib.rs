mod arithmetization;
use arithmetization::*;

use halo2curves::bn256::Fr;
use poseidon::Poseidon;

pub enum Error {
    HashingError(String),
}

pub struct Proof<A: Arithmetization, F: FoldedArithmetization<A>, const L: usize> {
    folded: [F; L],
    latest: A,
    pc: usize,
    i: usize,
}

impl<A: Arithmetization, F: FoldedArithmetization<A>, const L: usize> Proof<A, F, L> {
    /// Instantiate a SuperNova proof by giving it the set of circuits
    /// it should track..
    pub fn new(folded: [F; L]) -> Self {
        Self {
            folded,
            latest: A::default(),
            pc: 0,
            i: 0,
        }
    }

    /// Update a SuperNova proof with a new instance/witness pair.
    pub fn update(&mut self, next: A, pc: usize) {
        self.folded[self.pc] += self.latest.clone();
        self.latest = next;
        self.pc = pc;
        self.i += 1;
        let mut poseidon: Poseidon<Fr, 5, 4> = Poseidon::new(8, 5);
        poseidon.update(&[
            /*vk,*/ Fr::from(self.i as u64),
            Fr::from(self.pc as u64),
            /*z0, z_{i+1},*/
            self.folded
                .iter()
                .fold(Fr::zero(), |acc, pair| acc + pair.digest()),
        ]);
        let x = poseidon.squeeze();

        // TODO: set IO
    }
}

pub struct Verifier {}

/// Verify a SuperNova proof.
///
/// TODO: error verbosity
pub fn verify<A: Arithmetization, F: FoldedArithmetization<A>, const L: usize>(
    proof: Proof<A, F, L>,
) -> Result<bool, Error> {
    // If this is only the first iteration, we can skip the other checks,
    // as no computation has been folded.
    if proof.i == 0 {
        if proof.folded.iter().any(|pair| !pair.is_zero()) {
            return Ok(false);
        }

        if !proof.latest.is_zero() {
            return Ok(false);
        }

        return Ok(true);
    }

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
