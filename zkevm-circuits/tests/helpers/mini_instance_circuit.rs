use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr,
    plonk::{Circuit, ConstraintSystem, Error},
};

#[derive(Clone, Debug)]
pub struct MiniInstanceConfig {
    pub advice: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
    pub instance: halo2_proofs::plonk::Column<halo2_proofs::plonk::Instance>,
}

#[derive(Clone, Debug, Default)]
pub struct MiniInstanceCircuit {
    pub value: Option<Fr>,
}

impl Circuit<Fr> for MiniInstanceCircuit {
    type Config = MiniInstanceConfig;
    type Params = ();
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { value: None }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let advice = meta.advice_column();
        let instance = meta.instance_column();

        meta.enable_equality(advice);
        meta.enable_equality(instance);

        MiniInstanceConfig { advice, instance }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let assigned_cell = layouter.assign_region(
            || "assign public value",
            |mut region| {
                region.assign_advice(
                    || "a",
                    config.advice,
                    0,
                    || self
                        .value
                        .map(Value::known)
                        .unwrap_or_else(Value::unknown),
                )
            },
        )?;
        layouter.constrain_instance(assigned_cell.cell(), config.instance, 0)
    }
}

pub fn make_instance_circuit(x: Fr) -> (impl Circuit<Fr>, Vec<Vec<Fr>>) {
    (
        MiniInstanceCircuit { value: Some(x) },
        vec![vec![x]],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    #[test]
    fn mini_instance_satisfies_mock_prover() {
        let x = Fr::from(123u64);
        let circuit = MiniInstanceCircuit { value: Some(x) };
        let instances = vec![vec![x]];
        let prover = MockProver::run(18, &circuit, instances).expect("mock prover should not fail");
        prover.assert_satisfied();
    }
}
