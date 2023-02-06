use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, Result, Variable};

pub trait StepCircuit<F: PrimeField> {
    /// Drives generation of new constraints inside `cs`.
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
        z: &[FpVar<F>],
    ) -> Result<Vec<FpVar<F>>>;
}
