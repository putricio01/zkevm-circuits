mod helpers;

use std::io::Cursor;

use bus_mapping::circuit_input_builder::ExpEvent;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, VerifyingKey},
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::{ProverSHPLONK, VerifierSHPLONK},
        strategy::SingleStrategy,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use helpers::mock_transcript::MockTranscript;
use helpers::params_cache::load_or_build_params_k18;
use rand::rngs::OsRng;
use snark_verifier::loader::native::NativeLoader;
use snark_verifier_sdk::types::PoseidonTranscript;
use zkevm_circuits::exp_circuit::ExpCircuit;

fn sample_exp_circuit() -> ExpCircuit<Fr> {
    let event = ExpEvent::default();
    let max_exp_steps = event.steps.len() + 2;
    ExpCircuit::<Fr>::new(vec![event], max_exp_steps)
}

fn setup_params_and_keys(
    circuit: &ExpCircuit<Fr>,
) -> (
    ParamsKZG<Bn256>,
    VerifyingKey<G1Affine>,
    ProvingKey<G1Affine>,
) {
    //let mut rng = OsRng;
    //let params = ParamsKZG::<Bn256>::setup(18, &mut rng);
    let params = load_or_build_params_k18();
    let vk = keygen_vk(&params, circuit).expect("key generation for vk should succeed");
    let pk = keygen_pk(&params, vk.clone(), circuit).expect("key generation for pk should succeed");
    (params, vk, pk)
}

#[test]
fn poseidon_mock_transcript_records_absorption() {
    let circuit = sample_exp_circuit();
    let (params, vk, pk) = setup_params_and_keys(&circuit);

    let mut transcript =
        MockTranscript::new(PoseidonTranscript::<NativeLoader, Vec<u8>>::new(Vec::new()));

    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[]],
        OsRng,
        &mut transcript,
    )
    .expect("proof generation should not fail");

    let absorbed = transcript.absorbed_messages();
    assert!(
        absorbed.iter().any(|entry| !entry.is_empty()),
        "poseidon transcript should record absorbed bytes"
    );

    let proof = transcript.into_inner().finalize();

    let strategy = SingleStrategy::new(&params);
    let mut verifier_transcript =
        PoseidonTranscript::<NativeLoader, Cursor<Vec<u8>>>::new(Cursor::new(proof.clone()));
    verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
        &params,
        &vk,
        strategy,
        &[&[]],
        &mut verifier_transcript,
    )
    .expect("poseidon proof should verify");
}

#[test]
fn blake2b_mock_transcript_records_absorption() {
    let circuit = sample_exp_circuit();
    let (params, vk, pk) = setup_params_and_keys(&circuit);

    let mut transcript =
        MockTranscript::new(
            Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(Vec::new()),
        );

    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[]],
        OsRng,
        &mut transcript,
    )
    .expect("proof generation should not fail");

    let absorbed = transcript.absorbed_messages();
    assert!(
        absorbed.iter().any(|entry| !entry.is_empty()),
        "blake2b transcript should record absorbed bytes"
    );

    let proof = transcript.into_inner().finalize();

    let strategy = SingleStrategy::new(&params);
    let mut verifier_transcript =
        Blake2bRead::<_, G1Affine, Challenge255<_>>::init(proof.as_slice());
    verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
        &params,
        &vk,
        strategy,
        &[&[]],
        &mut verifier_transcript,
    )
    .expect("blake2b proof should verify");
}
