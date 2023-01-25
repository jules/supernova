mod arithmetization;
use arithmetization::*;

use halo2curves::bn256::Fr;
use poseidon::Poseidon;

pub enum Error {
    HashingError(String),
}

/// A SuperNova proof, which keeps track of a variable amount of loose circuits,
/// a most recent instance-witness pair, a program counter and the iteration
/// that the proof is currently at.
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
        poseidon.update(
            [self
                .folded
                .iter()
                .fold(Fr::zero(), |acc, pair| acc + pair.params())]
            .into_iter()
            .chain([Fr::from(self.i as u64)])
            .chain([Fr::from(self.pc as u64)])
            .chain(self.latest.z0())
            /*z_{i+1},*/
            .chain(
                [self
                    .folded
                    .iter()
                    .fold(Fr::zero(), |acc, pair| acc + pair.digest())]
                .into_iter(),
            )
            .collect::<Vec<Fr>>()
            .as_slice(),
        );
        let x = poseidon.squeeze();
        self.latest.push_hash(x);
    }
}

/// Anb instantiation of a SuperNova verifier for a specific set of
/// circuit parameters.
///
/// NOTE: may be redundant, the proof already contains the parameters.
pub struct Verifier<const L: usize> {
    params: [Fr; L],
}

impl<const L: usize> Verifier<L> {
    /// Instantiate a new SuperNova verifier with the given verifier keys.
    pub fn new(params: [Fr; L]) -> Self {
        Self { params }
    }

    /// Verify a SuperNova proof.
    ///
    /// TODO: error verbosity
    pub fn verify<A: Arithmetization, F: FoldedArithmetization<A>, const PL: usize>(
        &self,
        proof: Proof<A, F, PL>,
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

        // Check that the public IO of the latest instance includes
        // the correct hash.
        let mut poseidon: Poseidon<Fr, 5, 4> = Poseidon::new(8, 5);
        poseidon.update(
            [self
                .params
                .iter()
                .fold(Fr::zero(), |acc, params| acc + params)]
            .into_iter()
            .chain([Fr::from(proof.i as u64)])
            .chain([Fr::from(proof.pc as u64)])
            .chain(proof.latest.z0())
            /*z_{i+1},*/
            .chain(
                [proof
                    .folded
                    .iter()
                    .fold(Fr::zero(), |acc, pair| acc + pair.digest())]
                .into_iter(),
            )
            .collect::<Vec<Fr>>()
            .as_slice(),
        );
        if proof.latest.public_inputs()[0] != poseidon.squeeze() {
            return Ok(false);
        }

        // Ensure PC is within range.
        if proof.pc > proof.folded.len() {
            return Ok(false);
        }

        // Ensure the latest instance has no crossterms.
        if proof.latest.has_crossterms() {
            return Ok(false);
        }

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
}
