//! Integration test that assembles a minimal existing circuit and prepares for a
//! proof generation flow. This keeps the PoC focused on wiring up the Halo2
//! transcript machinery without touching any new circuit logic.

use bus_mapping::circuit_input_builder::ExpEvent;
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use zkevm_circuits::exp_circuit::ExpCircuit;

#[test]
fn frozen_heart_exp_circuit_setup() {
    // Use the smallest exponentiation gadget that already exists in the codebase.
    let event = ExpEvent::default();
    let max_exp_steps = event.steps.len() + 2;
    let circuit = ExpCircuit::<Fr>::new(vec![event], max_exp_steps);

    // The circuit requires the same degree as the rest of the exp-circuit unit
    // tests.  Knowing this value allows downstream code to initialise the halo2
    // parameters and transcripts required for a real proof.
    let k: u32 = 18;

    if std::env::var("FROZEN_HEART_FULL_PROOF").is_ok() {
        use halo2_proofs::{
            halo2curves::bn256::Bn256,
            plonk::{keygen_pk, keygen_vk},
            poly::kzg::commitment::ParamsKZG,
        };
        use rand::rngs::OsRng;

        let mut rng = OsRng;
        let params = ParamsKZG::<Bn256>::setup(k, &mut rng);
        let vk = keygen_vk(&params, &circuit).expect("key generation for vk should succeed");
        let _pk = keygen_pk(&params, vk, &circuit).expect("key generation for pk should succeed");
    }

    // Finally, confirm that the prepared circuit satisfies all constraints so the
    // PoC is ready to plug into transcript experiments.
    let prover = MockProver::run(k, &circuit, vec![]).expect("mock prover should run");
    prover.assert_satisfied_par();
}
