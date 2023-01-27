// NOTE: Code taken largely from:
// https://github.com/zkcrypto/bellman/blob/main/src/groth16/prover.rs

use super::R1CS;
use bellman::{ConstraintSystem, Index, LinearCombination, SynthesisError, Variable};
use halo2curves::FieldExt;

pub struct ProvingAssignment<S: FieldExt> {
    // Evaluations of A, B, C polynomials
    a: Vec<LinearCombination<S>>,
    b: Vec<LinearCombination<S>>,
    c: Vec<LinearCombination<S>>,

    // Assignments of variables
    input_assignment: Vec<S>,
    aux_assignment: Vec<S>,
}

impl<S: FieldExt> ProvingAssignment<S> {
    pub fn create_shape(&self) -> R1CS<S> {
        let eval_matrix = |m: &[LinearCombination<S>]| -> Vec<Vec<S>> {
            m.iter()
                .map(|lc| {
                    let mut witnesses = vec![];
                    let mut inputs = vec![];
                    lc.as_ref().iter().for_each(|(variable, coeff)| {
                        match variable.get_unchecked() {
                            Index::Input(_) => inputs.push(*coeff),
                            Index::Aux(_) => witnesses.push(*coeff),
                        }
                    });
                    witnesses.extend(inputs);
                    witnesses
                })
                .collect::<Vec<Vec<S>>>()
        };

        R1CS {
            num_consts: self.a.len(),
            num_vars: self.aux_assignment.len(),
            num_public_inputs: self.input_assignment.len(),
            A: eval_matrix(&self.a),
            B: eval_matrix(&self.b),
            C: eval_matrix(&self.c),
            witness: self.aux_assignment.clone(),
            instance: self.input_assignment.clone()[1..].to_vec(),
        }
    }
}

impl<S: FieldExt> ConstraintSystem<S> for ProvingAssignment<S> {
    type Root = Self;

    fn alloc<F, A, AR>(&mut self, _: A, f: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<S, SynthesisError>,
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
        F: FnOnce() -> Result<S, SynthesisError>,
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
        LA: FnOnce(LinearCombination<S>) -> LinearCombination<S>,
        LB: FnOnce(LinearCombination<S>) -> LinearCombination<S>,
        LC: FnOnce(LinearCombination<S>) -> LinearCombination<S>,
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
