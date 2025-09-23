//! Extra Frozen Heart regression tests exercising multiple transcript backends.
//!
//! Enable the optional Poseidon transcript coverage with:
//! `cargo test -p zkevm-circuits --test frozen_heart_extra --features poseidon_transcript -- --nocapture`

mod helpers;

use std::{
    collections::BTreeMap,
    env,
    io::Cursor,
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ConstraintSystem, Error,
        ProvingKey, VerifyingKey,
    },
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::{ProverSHPLONK, VerifierSHPLONK},
        strategy::SingleStrategy,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, Keccak256Read, TranscriptReadBuffer,
        TranscriptWriterBuffer,
    },
};
use helpers::{
    mini_instance_circuit::{make_instance_circuit, MiniInstanceCircuit},
    mock_transcript::{MockTranscript, TEvent},
    params_cache::load_or_build_params_k18,
};
use rand::{rngs::StdRng, SeedableRng};

#[cfg(feature = "poseidon_transcript")]
use snark_verifier::loader::native::NativeLoader;
#[cfg(feature = "poseidon_transcript")]
use snark_verifier_sdk::types::{PoseidonTranscript, POSEIDON_SPEC};

fn instance_rows(instances: &[Vec<Fr>]) -> Vec<&[Fr]> {
    instances.iter().map(Vec::as_slice).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SegKind {
    Point,
    Scalar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Seg {
    kind: SegKind,
    off: usize,
    len: usize,
    island_id: usize,
}

fn segment_proof(events: &[TEvent], proof: &[u8]) -> Vec<Seg> {
    let mut segments = Vec::new();
    let mut offset = 0usize;
    let mut island_id = 0usize;

    for event in events {
        match event {
            TEvent::AbsorbPoint(bytes) => {
                let len = bytes.len();
                assert!(
                    offset + len <= proof.len(),
                    "point segment would exceed proof length",
                );
                assert_eq!(
                    &proof[offset..offset + len],
                    bytes.as_slice(),
                    "point bytes diverge from proof slice",
                );
                segments.push(Seg {
                    kind: SegKind::Point,
                    off: offset,
                    len,
                    island_id,
                });
                offset += len;
            }
            TEvent::AbsorbScalar(bytes) => {
                let len = bytes.len();
                assert!(
                    offset + len <= proof.len(),
                    "scalar segment would exceed proof length",
                );
                assert_eq!(
                    &proof[offset..offset + len],
                    bytes.as_slice(),
                    "scalar bytes diverge from proof slice",
                );
                segments.push(Seg {
                    kind: SegKind::Scalar,
                    off: offset,
                    len,
                    island_id,
                });
                offset += len;
            }
            TEvent::SqueezeChallenge(_) => {
                island_id += 1;
            }
        }
    }

    assert_eq!(
        offset,
        proof.len(),
        "segments accounted for {offset} bytes, proof contains {} bytes",
        proof.len()
    );

    segments
}

fn gather_island_ranges(segments: &[Seg]) -> Vec<(usize, usize, usize)> {
    let mut ranges = Vec::new();
    if segments.is_empty() {
        return ranges;
    }

    let mut start = 0usize;
    while start < segments.len() {
        let island = segments[start].island_id;
        let mut end = start;
        while end + 1 < segments.len() && segments[end + 1].island_id == island {
            end += 1;
        }
        ranges.push((island, start, end));
        start = end + 1;
    }

    ranges
}

fn collect_island_indices(segments: &[Seg]) -> BTreeMap<usize, Vec<usize>> {
    let mut map: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (idx, seg) in segments.iter().enumerate() {
        map.entry(seg.island_id).or_default().push(idx);
    }
    map
}

fn log_island_map(label: &str, segments: &[Seg]) {
    println!("{label} island map:");
    let ranges = gather_island_ranges(segments);
    if ranges.is_empty() {
        println!("  (no segments)");
        return;
    }

    for (island, start, end) in ranges {
        let kinds: Vec<String> = segments[start..=end]
            .iter()
            .map(|seg| format!("{:?}(len={})", seg.kind, seg.len))
            .collect();
        println!(
            "  Island {island} -> segments [{start}..={end}]: {}",
            kinds.join(", ")
        );
    }
}

fn extract_challenges(events: &[TEvent]) -> Vec<Vec<u8>> {
    events
        .iter()
        .filter_map(|event| match event {
            TEvent::SqueezeChallenge(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .collect()
}

fn format_challenge_prefix(challenges: &[Vec<u8>], count: usize) -> Vec<String> {
    challenges
        .iter()
        .take(count)
        .map(|challenge| challenge.iter().map(|byte| format!("{:02x}", byte)).collect())
        .collect()
}

fn island_limit_from_env() -> Option<usize> {
    env::var("FH_ISLAND_LIMIT")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|limit| *limit > 0)
}

fn splice_replace_segment(
    flow_a_segments: &[Seg],
    flow_a_proof: &[u8],
    replace_idx: usize,
    flow_b_segments: &[Seg],
    flow_b_proof: &[u8],
    donor_idx: usize,
) -> Vec<u8> {
    let donor = &flow_b_segments[donor_idx];
    let recipient = &flow_a_segments[replace_idx];
    assert_eq!(
        donor.len, recipient.len,
        "segment lengths must match before replacement",
    );
    assert_eq!(
        donor.kind, recipient.kind,
        "segment kinds must match before replacement",
    );

    let mut output = Vec::with_capacity(flow_a_proof.len());
    for (idx, seg) in flow_a_segments.iter().enumerate() {
        let (src_proof, src_seg) = if idx == replace_idx {
            (flow_b_proof, donor)
        } else {
            (flow_a_proof, seg)
        };
        let range = src_seg.off..src_seg.off + src_seg.len;
        output.extend_from_slice(&src_proof[range]);
    }
    assert_eq!(
        output.len(),
        flow_a_proof.len(),
        "spliced proof length must match original proof length",
    );
    output
}

fn splice_replace_island(
    flow_a_segments: &[Seg],
    flow_a_proof: &[u8],
    flow_b_segments: &[Seg],
    flow_b_proof: &[u8],
    island_id: usize,
) -> Vec<u8> {
    let a_indices: Vec<usize> = flow_a_segments
        .iter()
        .enumerate()
        .filter_map(|(idx, seg)| (seg.island_id == island_id).then_some(idx))
        .collect();
    let b_indices: Vec<usize> = flow_b_segments
        .iter()
        .enumerate()
        .filter_map(|(idx, seg)| (seg.island_id == island_id).then_some(idx))
        .collect();

    assert_eq!(
        a_indices.len(),
        b_indices.len(),
        "island {island_id} has mismatched segment counts"
    );
    assert!(!a_indices.is_empty(), "island {island_id} must contain segments");

    let mut mapping = BTreeMap::new();
    for (a_idx, b_idx) in a_indices.iter().zip(b_indices.iter()) {
        let donor = &flow_b_segments[*b_idx];
        let recipient = &flow_a_segments[*a_idx];
        assert_eq!(
            donor.kind, recipient.kind,
            "segment kinds differ in island {island_id}"
        );
        assert_eq!(
            donor.len, recipient.len,
            "segment lengths differ in island {island_id}"
        );
        mapping.insert(*a_idx, *b_idx);
    }

    let mut output = Vec::with_capacity(flow_a_proof.len());
    for (idx, seg) in flow_a_segments.iter().enumerate() {
        if let Some(&b_idx) = mapping.get(&idx) {
            let donor = &flow_b_segments[b_idx];
            let range = donor.off..donor.off + donor.len;
            output.extend_from_slice(&flow_b_proof[range]);
        } else {
            let range = seg.off..seg.off + seg.len;
            output.extend_from_slice(&flow_a_proof[range]);
        }
    }
    assert_eq!(
        output.len(),
        flow_a_proof.len(),
        "spliced proof length must match original proof length",
    );
    output
}

#[derive(Clone, Debug)]
struct TinyConfig {
    advice: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
}

#[derive(Clone, Debug, Default)]
struct TinyCircuit;

impl Circuit<Fr> for TinyCircuit {
    type Config = TinyConfig;
    type Params = ();
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let advice = meta.advice_column();
        meta.enable_equality(advice);
        TinyConfig { advice }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "copy assignment",
            |mut region| {
                let value = Fr::from(5u64);
                let cell0 = region.assign_advice(|| "row 0", config.advice, 0, || Value::known(value))?;
                let cell1 = region.assign_advice(|| "row 1", config.advice, 1, || Value::known(value))?;
                region.constrain_equal(cell0.cell(), cell1.cell())?;
                Ok(())
            },
        )
    }
}

fn sample_tiny_circuit() -> TinyCircuit {
    TinyCircuit::default()
}

fn setup_tiny_params_and_keys(
    circuit: &TinyCircuit,
) -> (
    ParamsKZG<Bn256>,
    VerifyingKey<G1Affine>,
    ProvingKey<G1Affine>,
) {
    let params = load_or_build_params_k18();
    let vk = keygen_vk(&params, circuit).expect("vk generation should succeed");
    let pk = keygen_pk(&params, vk.clone(), circuit).expect("pk generation should succeed");
    (params, vk, pk)
}

fn setup_mini_params_and_keys() -> (
    ParamsKZG<Bn256>,
    VerifyingKey<G1Affine>,
    ProvingKey<G1Affine>,
) {
    let params = load_or_build_params_k18();
    let empty_circuit = MiniInstanceCircuit {
        value: Some(Fr::from(0u64)),
    };
    let vk = keygen_vk(&params, &empty_circuit).expect("vk generation should succeed");
    let pk = keygen_pk(&params, vk.clone(), &empty_circuit).expect("pk generation should succeed");
    (params, vk, pk)
}

fn produce_flow_proof_blake2b(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: TinyCircuit,
    seed: u64,
    label: &str,
) -> (Vec<u8>, Vec<Seg>) {
    let mut transcript = MockTranscript::new(
        Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(Vec::new()),
    );
    let rng = StdRng::seed_from_u64(seed);
    println!("Generating {label} proof (seed = {seed})...");
    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<_>, _, _, _, _>(
        params,
        pk,
        &[circuit],
        &[&[]],
        rng,
        &mut transcript,
    )
    .expect("proof generation should succeed");

    let events = transcript.events();
    let proof = transcript.into_inner().finalize();
    println!(
        "{label} produced {} transcript events and {} proof bytes",
        events.len(),
        proof.len()
    );
    let segments = segment_proof(&events, &proof);
    (proof, segments)
}

#[cfg(feature = "poseidon_transcript")]
fn produce_flow_proof_poseidon(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: TinyCircuit,
    seed: u64,
    label: &str,
) -> (Vec<u8>, Vec<Seg>) {
    let mut transcript = MockTranscript::new(
        PoseidonTranscript::<NativeLoader, _>::from_spec(Vec::new(), POSEIDON_SPEC.clone()),
    );
    let rng = StdRng::seed_from_u64(seed);
    println!("Generating {label} (Poseidon) proof (seed = {seed})...");
    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<_>, _, _, _, _>(
        params,
        pk,
        &[circuit],
        &[&[]],
        rng,
        &mut transcript,
    )
    .expect("proof generation should succeed");

    let events = transcript.events();
    let proof = transcript.into_inner().finalize();
    println!(
        "{label} (Poseidon) produced {} transcript events and {} proof bytes",
        events.len(),
        proof.len()
    );
    let segments = segment_proof(&events, &proof);
    (proof, segments)
}

#[test]
fn fh_public_input_tamper_blake2b() {
    println!("--- Frozen Heart public-input tamper (Blake2b) ---");
    let (params, vk, pk) = setup_mini_params_and_keys();

    let x = Fr::from(12345u64);
    let (circuit, instances) = make_instance_circuit(x);

    let mut prover = Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(Vec::new());
    let rng = StdRng::seed_from_u64(7);
    let instance_rows_vec = instance_rows(&instances);
    let instance_refs: Vec<&[&[Fr]]> = vec![instance_rows_vec.as_slice()];
    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        instance_refs.as_slice(),
        rng,
        &mut prover,
    )
    .expect("proof generation should succeed");

    let proof_bytes = prover.finalize();

    println!("Baseline verification with untampered public input...");
    let baseline_rows_vec = instance_rows(&instances);
    let baseline_refs: Vec<&[&[Fr]]> = vec![baseline_rows_vec.as_slice()];
    let mut baseline_verifier = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(Cursor::new(
        proof_bytes.clone(),
    ));
    let strategy = SingleStrategy::new(&params);
    verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
        &params,
        &vk,
        strategy,
        baseline_refs.as_slice(),
        &mut baseline_verifier,
    )
    .expect("baseline proof must verify");
    println!("Baseline verification succeeded.");

    println!("Attempting verification with tampered public input...");
    let tampered_value = x + Fr::from(1u64);
    let tampered_instances = vec![vec![tampered_value]];
    let tampered_rows_vec = instance_rows(&tampered_instances);
    let tampered_refs: Vec<&[&[Fr]]> = vec![tampered_rows_vec.as_slice()];
    let mut tampered_verifier = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(Cursor::new(
        proof_bytes.clone(),
    ));
    let strategy = SingleStrategy::new(&params);
    let tampered_result = verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
        &params,
        &vk,
        strategy,
        tampered_refs.as_slice(),
        &mut tampered_verifier,
    );

    match tampered_result {
        Ok(_) => {
            println!(
                "Frozen Heart FOUND: proof verified with tampered public input under Blake2b transcript!"
            );
            assert!(false, "tampered public input unexpectedly verified");
        }
        Err(err) => println!("Tampered verification failed as expected: {err}"),
    }
}

#[test]
fn fh_whole_island_swap_blake2b() {
    println!("--- Frozen Heart whole-island swap (Blake2b) ---");
    let setup_circuit = sample_tiny_circuit();
    let (params, vk, pk) = setup_tiny_params_and_keys(&setup_circuit);

    let flow_a_circuit = sample_tiny_circuit();
    let flow_b_circuit = flow_a_circuit.clone();

    let (flow_a_proof, flow_a_segments) = produce_flow_proof_blake2b(
        &params,
        &pk,
        flow_a_circuit,
        42,
        "Flow A",
    );
    let (flow_b_proof, flow_b_segments) = produce_flow_proof_blake2b(
        &params,
        &pk,
        flow_b_circuit,
        43,
        "Flow B",
    );

    log_island_map("Flow A", &flow_a_segments);
    log_island_map("Flow B", &flow_b_segments);

    let mut baseline_verifier = MockTranscript::new(Blake2bRead::<_, G1Affine, Challenge255<_>>::init(
        Cursor::new(flow_a_proof.clone()),
    ));
    let strategy = SingleStrategy::new(&params);
    verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
        &params,
        &vk,
        strategy,
        &[&[]],
        &mut baseline_verifier,
    )
    .expect("baseline Flow A proof must verify");
    let baseline_challenges = extract_challenges(&baseline_verifier.events());
    println!(
        "Baseline verifier observed {} challenge(s)",
        baseline_challenges.len()
    );

    let island_indices_a = collect_island_indices(&flow_a_segments);
    let island_indices_b = collect_island_indices(&flow_b_segments);
    let island_limit = island_limit_from_env();
    if let Some(limit) = island_limit {
        println!("FH_ISLAND_LIMIT = {limit}; will stop after testing this many island(s).");
    }

    let mut checked_islands = 0usize;
    for (island_id, indices_a) in island_indices_a.iter() {
        if *island_id == 0 {
            println!("Skipping island 0 (no FS prefix to preserve).");
            continue;
        }
        if let Some(limit) = island_limit {
            if checked_islands >= limit {
                println!(
                    "Reached FH_ISLAND_LIMIT ({limit}); stopping further island replacement attempts."
                );
                break;
            }
        }

        let Some(indices_b) = island_indices_b.get(island_id) else {
            println!(
                "Flow B missing island {island_id}; skipping whole-island swap attempt."
            );
            continue;
        };

        if indices_a.len() != indices_b.len() {
            println!(
                "Island {island_id} segment count mismatch (Flow A: {}, Flow B: {}); skipping.",
                indices_a.len(),
                indices_b.len()
            );
            continue;
        }

        let mut differing = false;
        for (&a_idx, &b_idx) in indices_a.iter().zip(indices_b.iter()) {
            let seg_a = &flow_a_segments[a_idx];
            let seg_b = &flow_b_segments[b_idx];
            if seg_a.kind != seg_b.kind || seg_a.len != seg_b.len {
                println!(
                    "Segment kind/len mismatch in island {island_id}; skipping."
                );
                differing = false;
                break;
            }
            let range_a = seg_a.off..seg_a.off + seg_a.len;
            let range_b = seg_b.off..seg_b.off + seg_b.len;
            if flow_a_proof[range_a] != flow_b_proof[range_b] {
                differing = true;
            }
        }
        if !differing {
            println!(
                "Island {island_id} segments identical between flows; skipping replacement."
            );
            continue;
        }

        println!("Attempting whole-island replacement for island {island_id}...");
        let spliced = splice_replace_island(
            &flow_a_segments,
            &flow_a_proof,
            &flow_b_segments,
            &flow_b_proof,
            *island_id,
        );

        let mut spliced_verifier = MockTranscript::new(
            Blake2bRead::<_, G1Affine, Challenge255<_>>::init(Cursor::new(spliced.clone())),
        );
        let strategy = SingleStrategy::new(&params);
        let result = verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
            &params,
            &vk,
            strategy,
            &[&[]],
            &mut spliced_verifier,
        );
        let spliced_challenges = extract_challenges(&spliced_verifier.events());

        if baseline_challenges.len() < *island_id {
            println!(
                "  Baseline produced only {} challenges (< island {}); skipping prefix check.",
                baseline_challenges.len(),
                island_id
            );
            continue;
        }
        if spliced_challenges.len() < *island_id {
            println!(
                "  Spliced proof produced only {} challenges (< island {}); skipping prefix check.",
                spliced_challenges.len(),
                island_id
            );
            continue;
        }

        if baseline_challenges[..*island_id] != spliced_challenges[..*island_id] {
            println!(
                "  Fiat-Shamir prefix mismatch for island {island_id}; baseline {:?}, spliced {:?}",
                format_challenge_prefix(&baseline_challenges, *island_id),
                format_challenge_prefix(&spliced_challenges, *island_id)
            );
            continue;
        }

        checked_islands += 1;

        if result.is_ok() {
            println!(
                "Frozen Heart success on whole-island swap for island {island_id}!"
            );
            println!(
                "  Preserved prefix: {:?}",
                format_challenge_prefix(&baseline_challenges, *island_id)
            );
            println!(
                "  Divergent challenges snapshot: baseline {:?} vs spliced {:?}",
                format_challenge_prefix(&baseline_challenges, baseline_challenges.len()),
                format_challenge_prefix(&spliced_challenges, spliced_challenges.len())
            );
            assert!(false, "Frozen Heart success on whole-island swap");
        } else {
            println!(
                "  Spliced proof rejected for island {island_id} as expected."
            );
        }
    }

    if checked_islands == 0 {
        println!("No whole-island swap attempts passed the FS prefix gate; test passes.");
    }
}

#[cfg(feature = "poseidon_transcript")]
#[test]
fn fh_public_input_tamper_poseidon() {
    println!("--- Frozen Heart public-input tamper (Poseidon) ---");
    let (params, vk, pk) = setup_mini_params_and_keys();

    let x = Fr::from(12345u64);
    let (circuit, instances) = make_instance_circuit(x);

    let mut prover =
        PoseidonTranscript::<NativeLoader, _>::from_spec(Vec::new(), POSEIDON_SPEC.clone());
    let rng = StdRng::seed_from_u64(13);
    let instance_rows_vec = instance_rows(&instances);
    let instance_refs: Vec<&[&[Fr]]> = vec![instance_rows_vec.as_slice()];
    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        instance_refs.as_slice(),
        rng,
        &mut prover,
    )
    .expect("proof generation should succeed");

    let proof_bytes = prover.finalize();

    println!("Baseline verification with Poseidon transcript...");
    let baseline_rows_vec = instance_rows(&instances);
    let baseline_refs: Vec<&[&[Fr]]> = vec![baseline_rows_vec.as_slice()];
    let mut baseline_verifier = PoseidonTranscript::<NativeLoader, _>::from_spec(
        Cursor::new(proof_bytes.clone()),
        POSEIDON_SPEC.clone(),
    );
    let strategy = SingleStrategy::new(&params);
    verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
        &params,
        &vk,
        strategy,
        baseline_refs.as_slice(),
        &mut baseline_verifier,
    )
    .expect("baseline Poseidon proof must verify");
    println!("Baseline verification succeeded.");

    println!("Attempting Poseidon verification with tampered public input...");
    let tampered_instances = vec![vec![x + Fr::from(1u64)]];
    let tampered_rows_vec = instance_rows(&tampered_instances);
    let tampered_refs: Vec<&[&[Fr]]> = vec![tampered_rows_vec.as_slice()];
    let mut tampered_verifier = PoseidonTranscript::<NativeLoader, _>::from_spec(
        Cursor::new(proof_bytes.clone()),
        POSEIDON_SPEC.clone(),
    );
    let strategy = SingleStrategy::new(&params);
    let tampered_result = verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
        &params,
        &vk,
        strategy,
        tampered_refs.as_slice(),
        &mut tampered_verifier,
    );

    match tampered_result {
        Ok(_) => {
            println!(
                "FH FOUND (Poseidon): proof verified with tampered public input under Poseidon transcript!"
            );
            assert!(
                false,
                "tampered public input unexpectedly verified under Poseidon transcript"
            );
        }
        Err(err) => println!("Poseidon tamper rejected as expected: {err}"),
    }
}

#[cfg(feature = "poseidon_transcript")]
#[test]
fn fh_whole_island_swap_poseidon() {
    println!("--- Frozen Heart whole-island swap (Poseidon) ---");
    let setup_circuit = sample_tiny_circuit();
    let (params, vk, pk) = setup_tiny_params_and_keys(&setup_circuit);

    let flow_a_circuit = sample_tiny_circuit();
    let flow_b_circuit = flow_a_circuit.clone();

    let (flow_a_proof, flow_a_segments) = produce_flow_proof_poseidon(
        &params,
        &pk,
        flow_a_circuit,
        52,
        "Flow A",
    );
    let (flow_b_proof, flow_b_segments) = produce_flow_proof_poseidon(
        &params,
        &pk,
        flow_b_circuit,
        53,
        "Flow B",
    );

    log_island_map("Flow A (Poseidon)", &flow_a_segments);
    log_island_map("Flow B (Poseidon)", &flow_b_segments);

    let mut baseline_verifier = MockTranscript::new(
        PoseidonTranscript::<NativeLoader, _>::from_spec(
            Cursor::new(flow_a_proof.clone()),
            POSEIDON_SPEC.clone(),
        ),
    );
    let strategy = SingleStrategy::new(&params);
    verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
        &params,
        &vk,
        strategy,
        &[&[]],
        &mut baseline_verifier,
    )
    .expect("baseline Poseidon Flow A proof must verify");
    let baseline_challenges = extract_challenges(&baseline_verifier.events());
    println!(
        "Poseidon baseline verifier observed {} challenge(s)",
        baseline_challenges.len()
    );

    let island_indices_a = collect_island_indices(&flow_a_segments);
    let island_indices_b = collect_island_indices(&flow_b_segments);
    let island_limit = island_limit_from_env();
    if let Some(limit) = island_limit {
        println!("FH_ISLAND_LIMIT = {limit}; Poseidon swaps will stop after this many island(s).");
    }

    let mut checked_islands = 0usize;
    for (island_id, indices_a) in island_indices_a.iter() {
        if *island_id == 0 {
            println!("Skipping island 0 (Poseidon path) because FS prefix is empty.");
            continue;
        }
        if let Some(limit) = island_limit {
            if checked_islands >= limit {
                println!(
                    "Reached FH_ISLAND_LIMIT ({limit}) for Poseidon swaps; stopping early."
                );
                break;
            }
        }

        let Some(indices_b) = island_indices_b.get(island_id) else {
            println!(
                "Poseidon Flow B missing island {island_id}; skipping replacement."
            );
            continue;
        };

        if indices_a.len() != indices_b.len() {
            println!(
                "Poseidon island {island_id} mismatch (Flow A: {}, Flow B: {}); skipping.",
                indices_a.len(),
                indices_b.len()
            );
            continue;
        }

        let mut differing = false;
        for (&a_idx, &b_idx) in indices_a.iter().zip(indices_b.iter()) {
            let seg_a = &flow_a_segments[a_idx];
            let seg_b = &flow_b_segments[b_idx];
            if seg_a.kind != seg_b.kind || seg_a.len != seg_b.len {
                println!(
                    "Poseidon island {island_id} has segment kind/len mismatch; skipping."
                );
                differing = false;
                break;
            }
            let range_a = seg_a.off..seg_a.off + seg_a.len;
            let range_b = seg_b.off..seg_b.off + seg_b.len;
            if flow_a_proof[range_a] != flow_b_proof[range_b] {
                differing = true;
            }
        }
        if !differing {
            println!(
                "Poseidon island {island_id} segments identical; skipping replacement."
            );
            continue;
        }

        println!("Attempting Poseidon whole-island replacement for island {island_id}...");
        let spliced = splice_replace_island(
            &flow_a_segments,
            &flow_a_proof,
            &flow_b_segments,
            &flow_b_proof,
            *island_id,
        );

        let mut spliced_verifier = MockTranscript::new(
            PoseidonTranscript::<NativeLoader, _>::from_spec(
                Cursor::new(spliced.clone()),
                POSEIDON_SPEC.clone(),
            ),
        );
        let strategy = SingleStrategy::new(&params);
        let result = verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
            &params,
            &vk,
            strategy,
            &[&[]],
            &mut spliced_verifier,
        );
        let spliced_challenges = extract_challenges(&spliced_verifier.events());

        if baseline_challenges.len() < *island_id {
            println!(
                "  Poseidon baseline emitted only {} challenges (< island {}); skipping prefix check.",
                baseline_challenges.len(),
                island_id
            );
            continue;
        }
        if spliced_challenges.len() < *island_id {
            println!(
                "  Poseidon spliced proof emitted only {} challenges (< island {}); skipping prefix check.",
                spliced_challenges.len(),
                island_id
            );
            continue;
        }

        if baseline_challenges[..*island_id] != spliced_challenges[..*island_id] {
            println!(
                "  Poseidon FS prefix mismatch for island {island_id}; baseline {:?}, spliced {:?}",
                format_challenge_prefix(&baseline_challenges, *island_id),
                format_challenge_prefix(&spliced_challenges, *island_id)
            );
            continue;
        }

        checked_islands += 1;

        if result.is_ok() {
            println!(
                "FH FOUND (Poseidon): whole-island swap verified for island {island_id}!"
            );
            println!(
                "  Preserved prefix: {:?}",
                format_challenge_prefix(&baseline_challenges, *island_id)
            );
            println!(
                "  Divergent Poseidon challenges: baseline {:?} vs spliced {:?}",
                format_challenge_prefix(&baseline_challenges, baseline_challenges.len()),
                format_challenge_prefix(&spliced_challenges, spliced_challenges.len())
            );
            assert!(false, "Poseidon whole-island swap unexpectedly verified");
        } else {
            println!(
                "  Poseidon spliced proof rejected for island {island_id} as expected."
            );
        }
    }

    if checked_islands == 0 {
        println!(
            "Poseidon whole-island swaps either skipped or rejected before FS prefix check; test passes."
        );
    }
}

#[test]
fn fh_cross_challenge_swap_negative() {
    println!("--- Frozen Heart cross-challenge swap negative check ---");
    let setup_circuit = sample_tiny_circuit();
    let (params, vk, pk) = setup_tiny_params_and_keys(&setup_circuit);

    let flow_a_circuit = sample_tiny_circuit();
    let flow_b_circuit = flow_a_circuit.clone();

    let (flow_a_proof, flow_a_segments) = produce_flow_proof_blake2b(
        &params,
        &pk,
        flow_a_circuit,
        62,
        "Flow A",
    );
    let (flow_b_proof, flow_b_segments) = produce_flow_proof_blake2b(
        &params,
        &pk,
        flow_b_circuit,
        63,
        "Flow B",
    );

    let mut baseline_verifier = MockTranscript::new(Blake2bRead::<_, G1Affine, Challenge255<_>>::init(
        Cursor::new(flow_a_proof.clone()),
    ));
    let strategy = SingleStrategy::new(&params);
    verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
        &params,
        &vk,
        strategy,
        &[&[]],
        &mut baseline_verifier,
    )
    .expect("baseline Flow A proof must verify");
    let baseline_challenges = extract_challenges(&baseline_verifier.events());

    let mut candidate = None;
    for (a_idx, seg_a) in flow_a_segments.iter().enumerate() {
        for (b_idx, seg_b) in flow_b_segments.iter().enumerate() {
            if seg_a.kind == seg_b.kind
                && seg_a.len == seg_b.len
                && seg_a.island_id != seg_b.island_id
                && flow_a_proof[seg_a.off..seg_a.off + seg_a.len]
                    != flow_b_proof[seg_b.off..seg_b.off + seg_b.len]
            {
                candidate = Some((a_idx, b_idx));
                break;
            }
        }
        if candidate.is_some() {
            break;
        }
    }

    let (seg_a_idx, seg_b_idx) = candidate.expect("expected cross-challenge segment pair to exist");
    let seg_a = flow_a_segments[seg_a_idx];
    let seg_b = flow_b_segments[seg_b_idx];
    println!(
        "Replacing Flow A segment {seg_a_idx} (island {}) with Flow B segment {seg_b_idx} (island {})",
        seg_a.island_id, seg_b.island_id
    );

    let spliced = splice_replace_segment(
        &flow_a_segments,
        &flow_a_proof,
        seg_a_idx,
        &flow_b_segments,
        &flow_b_proof,
        seg_b_idx,
    );

    let mut spliced_verifier = MockTranscript::new(
        Blake2bRead::<_, G1Affine, Challenge255<_>>::init(Cursor::new(spliced.clone())),
    );
    let strategy = SingleStrategy::new(&params);
    let result = verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
        &params,
        &vk,
        strategy,
        &[&[]],
        &mut spliced_verifier,
    );
    let spliced_challenges = extract_challenges(&spliced_verifier.events());

    if result.is_ok() {
        println!(
            "Frozen Heart FOUND: cross-challenge segment swap unexpectedly verified!"
        );
        println!(
            "  Baseline challenges: {:?}",
            format_challenge_prefix(&baseline_challenges, baseline_challenges.len())
        );
        println!(
            "  Spliced challenges: {:?}",
            format_challenge_prefix(&spliced_challenges, spliced_challenges.len())
        );
        assert!(false, "cross-challenge swap should always fail");
    } else {
        println!(
            "Cross-challenge swap failed as expected. Baseline prefix {:?}, spliced prefix {:?}",
            format_challenge_prefix(&baseline_challenges, baseline_challenges.len().min(3)),
            format_challenge_prefix(&spliced_challenges, spliced_challenges.len().min(3))
        );
    }
}

#[test]
fn fh_transcript_personalization_mismatch_negative() {
    println!("--- Frozen Heart transcript personalization mismatch ---");
    let setup_circuit = sample_tiny_circuit();
    let (params, vk, pk) = setup_tiny_params_and_keys(&setup_circuit);

    let circuit = sample_tiny_circuit();
    let mut prover = Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(Vec::new());
    let rng = StdRng::seed_from_u64(101);
    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[]],
        rng,
        &mut prover,
    )
    .expect("proof generation should succeed");
    let proof_bytes = prover.finalize();

    println!("Baseline verification with matching Blake2b reader...");
    let mut baseline_verifier = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(Cursor::new(
        proof_bytes.clone(),
    ));
    let strategy = SingleStrategy::new(&params);
    verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
        &params,
        &vk,
        strategy,
        &[&[]],
        &mut baseline_verifier,
    )
    .expect("baseline verification should succeed");
    println!("Baseline verification succeeded; trying mismatched readers...");

    let mut keccak_verifier = Keccak256Read::<_, G1Affine, Challenge255<_>>::init(Cursor::new(
        proof_bytes.clone(),
    ));
    let strategy = SingleStrategy::new(&params);
    let keccak_result = verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
        &params,
        &vk,
        strategy,
        &[&[]],
        &mut keccak_verifier,
    );
    match keccak_result {
        Ok(_) => {
            println!(
                "Frozen Heart FOUND: Blake2b proof verified under Keccak transcript personalization!"
            );
            assert!(false, "Keccak transcript unexpectedly accepted Blake2b proof");
        }
        Err(err) => println!("Keccak transcript mismatch rejected as expected: {err}"),
    }

    #[cfg(feature = "poseidon_transcript")]
    {
        let mut poseidon_verifier = PoseidonTranscript::<NativeLoader, _>::from_spec(
            Cursor::new(proof_bytes.clone()),
            POSEIDON_SPEC.clone(),
        );
        let strategy = SingleStrategy::new(&params);
        let poseidon_result = verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
            &params,
            &vk,
            strategy,
            &[&[]],
            &mut poseidon_verifier,
        );
        match poseidon_result {
            Ok(_) => {
                println!(
                    "Frozen Heart FOUND: Blake2b proof verified under Poseidon transcript!"
                );
                assert!(false, "Poseidon transcript unexpectedly accepted Blake2b proof");
            }
            Err(err) => println!("Poseidon transcript mismatch rejected as expected: {err}"),
        }
    }
}
