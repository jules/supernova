//! Implementation of an R1CS constraint system, which generates the coefficient matrices
//! and constructs the instance-witness vector when evaluating a circuit.
//!
//! Circuits are expected to follow methodology used in the bellperson library.
// NOTE: Code taken largely from:
// https://github.com/zkcrypto/bellman/blob/main/src/groth16/prover.rs
//
// This was done mostly (1) because we need to be able to expose the constraint system
// in order to derive SuperNova structures for it, and bellman keeps this constraint system
// internal, as it is accessed through higher-level proving functions, and (2) because we
// shouldn't evaluate the linear combinations like it does in bellman so that we can create
// the circuit shapes needed for the SuperNova protocol.

use super::{CircuitShape, R1CS};
use crate::{commitment::commit, r1cs::multiply_vec};
use bellperson::{ConstraintSystem, Index, LinearCombination, SynthesisError, Variable};
use group::ff::Field;
use itertools::concat;
use pasta_curves::arithmetic::CurveExt;

#[derive(Default)]
pub struct ProvingAssignment<G: CurveExt> {
    a: Vec<LinearCombination<G::ScalarExt>>,
    b: Vec<LinearCombination<G::ScalarExt>>,
    c: Vec<LinearCombination<G::ScalarExt>>,

    input_assignment: Vec<G::ScalarExt>,
    aux_assignment: Vec<G::ScalarExt>,
}

impl<G: CurveExt> ProvingAssignment<G> {
    /// Creates a committed relaxed R1CS circuit out of the given step circuit, which essentially
    /// defines the circuit shape, includes the commitments and prepends the hash validation.
    pub fn create_circuit(&self, generators: &[G]) -> R1CS<G> {
        let eval_matrix = |m: &[LinearCombination<G::ScalarExt>]| -> Vec<Vec<G::ScalarExt>> {
            m.iter()
                .map(|lc| {
                    let mut witnesses = vec![];
                    let mut inputs = vec![];
                    lc.iter()
                        .for_each(|(variable, coeff)| match variable.get_unchecked() {
                            Index::Input(_) => inputs.push(*coeff),
                            Index::Aux(_) => witnesses.push(*coeff),
                        });
                    witnesses.extend(inputs);
                    witnesses
                })
                .collect::<Vec<Vec<G::ScalarExt>>>()
        };

        let A = eval_matrix(&self.a);
        let B = eval_matrix(&self.b);
        let C = eval_matrix(&self.c);
        let output = {
            let (_, _, cz) = multiply_vec::<G>(
                &A,
                &B,
                &C,
                &concat(vec![
                    self.aux_assignment.clone(),
                    vec![G::ScalarExt::one()],
                    self.input_assignment.clone()[1..].to_vec(),
                ]),
            );
            cz[cz.len() - 1]
        };

        R1CS {
            shape: CircuitShape {
                num_vars: self.aux_assignment.len(),
                num_public_inputs: self.input_assignment.len(),
                A,
                B,
                C,
            },
            generators: generators.to_vec(),
            comm_witness: commit(generators, &self.aux_assignment),
            comm_E: G::identity(),
            E: vec![G::ScalarExt::zero(); self.a.len()],
            witness: self.aux_assignment.clone(),
            instance: self.input_assignment.clone()[1..].to_vec(),
            u: G::ScalarExt::one(),
            output,
        }
    }
}

impl<G: CurveExt> ConstraintSystem<G::ScalarExt> for ProvingAssignment<G> {
    type Root = Self;

    fn alloc<F, A, AR>(&mut self, _: A, f: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<G::ScalarExt, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.aux_assignment.push(f()?);

        Ok(Variable::new_unchecked(Index::Aux(
            self.aux_assignment.len() - 1,
        )))
    }

    fn alloc_input<F, A, AR>(&mut self, _: A, f: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<G::ScalarExt, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.input_assignment.push(f()?);

        Ok(Variable::new_unchecked(Index::Input(
            self.input_assignment.len() - 1,
        )))
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<G::ScalarExt>) -> LinearCombination<G::ScalarExt>,
        LB: FnOnce(LinearCombination<G::ScalarExt>) -> LinearCombination<G::ScalarExt>,
        LC: FnOnce(LinearCombination<G::ScalarExt>) -> LinearCombination<G::ScalarExt>,
    {
        let a = a(LinearCombination::zero());
        let b = b(LinearCombination::zero());
        let c = c(LinearCombination::zero());

        self.a.push(a);
        self.b.push(b);
        self.c.push(c);
    }

    fn push_namespace<NR, N>(&mut self, _: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn pop_namespace(&mut self) {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }
}
