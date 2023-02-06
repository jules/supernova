use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSystemRef, Result, Variable};

pub trait StepCircuit<F: Field> {
    /// Drives generation of new constraints inside `cs`.
    fn generate_constraints(self, cs: ConstraintSystemRef<F>, z: &[F]) -> Result<Vec<Variable>>;
}
