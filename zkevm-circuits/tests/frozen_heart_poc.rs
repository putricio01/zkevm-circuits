mod helpers;

use std::{collections::BTreeMap, io::Cursor};

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
use helpers::mock_transcript::{MockTranscript, TEvent};
use rand::{rngs::StdRng, SeedableRng};
use zkevm_circuits::exp_circuit::ExpCircuit;

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
    let mut rng = StdRng::seed_from_u64(42);
    println!("Setting up KZG parameters (k = 18)...");
    //let params = ParamsKZG::<Bn256>::setup(18, &mut rng);
    let params = helpers::params_cache::load_or_build_params_k18();
    println!("Deriving verifying key...");
    let vk = keygen_vk(&params, circuit).expect("vk generation should succeed");
    println!("Deriving proving key...");
    let pk = keygen_pk(&params, vk.clone(), circuit).expect("pk generation should succeed");
    (params, vk, pk)
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
                    "point segment would exceed proof length"
                );
                assert_eq!(
                    &proof[offset..offset + len],
                    bytes.as_slice(),
                    "point bytes diverge from proof slice"
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
                    "scalar segment would exceed proof length"
                );
                assert_eq!(
                    &proof[offset..offset + len],
                    bytes.as_slice(),
                    "scalar bytes diverge from proof slice"
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
    assert_eq!(
        donor.island_id, recipient.island_id,
        "segments must belong to the same island",
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

fn build_cross_flow_candidates(
    flow_a_segments: &[Seg],
    flow_b_segments: &[Seg],
    max_candidates_per_island: usize,
) -> (Vec<(usize, usize)>, BTreeMap<usize, usize>) {
    let mut donors: BTreeMap<(usize, SegKind, usize), Vec<usize>> = BTreeMap::new();
    for (idx, seg) in flow_b_segments.iter().enumerate() {
        donors
            .entry((seg.island_id, seg.kind, seg.len))
            .or_default()
            .push(idx);
    }

    let mut counts: BTreeMap<usize, usize> = BTreeMap::new();
    let mut candidates = Vec::new();

    for (a_idx, seg_a) in flow_a_segments.iter().enumerate() {
        let island = seg_a.island_id;
        let mut current = *counts.get(&island).unwrap_or(&0);
        if current >= max_candidates_per_island {
            continue;
        }

        if let Some(b_indices) = donors.get(&(island, seg_a.kind, seg_a.len)) {
            for &b_idx in b_indices {
                if current >= max_candidates_per_island {
                    break;
                }
                candidates.push((a_idx, b_idx));
                current += 1;
            }
            counts.insert(island, current);
        }
    }

    (candidates, counts)
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

fn candidate_limit_from_env() -> usize {
    std::env::var("POC_B_MAX_CANDIDATES")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|limit| *limit > 0)
        .unwrap_or(1)
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
        .map(|challenge| {
            challenge
                .iter()
                .map(|byte| format!("{:02x}", byte))
                .collect()
        })
        .collect()
}

#[test]
fn frozen_heart_cross_flow_proof_reuse() {
    let setup_circuit = sample_exp_circuit();
    let (params, vk, pk) = setup_params_and_keys(&setup_circuit);

    let flow_a_circuit = sample_exp_circuit();
    let flow_b_circuit = flow_a_circuit.clone();

    let mut flow_a_transcript =
        MockTranscript::new(
            Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(Vec::new()),
        );
    let flow_a_rng = StdRng::seed_from_u64(42);
    println!("Generating Flow A proof (seed = 42)...");
    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<_>, _, _, _, _>(
        &params,
        &pk,
        &[flow_a_circuit],
        &[&[]],
        flow_a_rng,
        &mut flow_a_transcript,
    )
    .expect("flow A proof generation should succeed");

    let flow_a_events = flow_a_transcript.events();
    let flow_a_proof = flow_a_transcript.into_inner().finalize();

    println!(
        "Flow A produced {} transcript events and {} proof bytes",
        flow_a_events.len(),
        flow_a_proof.len()
    );

    let flow_a_segments = segment_proof(&flow_a_events, &flow_a_proof);

    let mut flow_b_transcript =
        MockTranscript::new(
            Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(Vec::new()),
        );
    let flow_b_rng = StdRng::seed_from_u64(43);
    println!("Generating Flow B proof (seed = 43)...");
    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<_>, _, _, _, _>(
        &params,
        &pk,
        &[flow_b_circuit],
        &[&[]],
        flow_b_rng,
        &mut flow_b_transcript,
    )
    .expect("flow B proof generation should succeed");

    let flow_b_events = flow_b_transcript.events();
    let flow_b_proof = flow_b_transcript.into_inner().finalize();

    println!(
        "Flow B produced {} transcript events and {} proof bytes",
        flow_b_events.len(),
        flow_b_proof.len()
    );

    let flow_b_segments = segment_proof(&flow_b_events, &flow_b_proof);

    log_island_map("Flow A", &flow_a_segments);
    log_island_map("Flow B", &flow_b_segments);

    let max_candidates_per_island = candidate_limit_from_env();
    println!(
        "POC_B_MAX_CANDIDATES limit per island: {}",
        max_candidates_per_island
    );

    let (candidates, per_island_counts) = build_cross_flow_candidates(
        &flow_a_segments,
        &flow_b_segments,
        max_candidates_per_island,
    );

    let island_ranges = gather_island_ranges(&flow_a_segments);
    println!(
        "Prepared {} cross-flow candidate pair(s) across {} island(s)",
        candidates.len(),
        island_ranges.len()
    );
    for (island, start, end) in &island_ranges {
        let count = per_island_counts.get(island).copied().unwrap_or(0);
        println!(
            "  Island {} (Flow A segments [{}..={}]) -> {} candidate pair(s)",
            island, start, end, count
        );
    }

    let mut original_verifier = MockTranscript::new(
        Blake2bRead::<_, G1Affine, Challenge255<_>>::init(Cursor::new(flow_a_proof.clone())),
    );
    let strategy = SingleStrategy::new(&params);
    println!("Verifying baseline Flow A proof...");
    verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
        &params,
        &vk,
        strategy,
        &[&[]],
        &mut original_verifier,
    )
    .expect("original flow A proof must verify");

    let baseline_challenges = extract_challenges(&original_verifier.events());
    println!(
        "Baseline verifier observed {} challenge(s)",
        baseline_challenges.len()
    );

    let mut success = false;
    let mut valid_candidates = 0usize;
    let mut skipped_prefix_mismatch = 0usize;

    for (candidate_idx, (seg_a_idx, seg_b_idx)) in candidates.iter().copied().enumerate() {
        let island_id = flow_a_segments[seg_a_idx].island_id;
        println!(
            "Testing candidate #{candidate_idx}: replace Flow A segment {seg_a_idx} with Flow B segment {seg_b_idx} in island {island_id}"
        );

        // ── Guard 1: skip trivial identical swaps ───────────────────────────────
    let a = &flow_a_segments[seg_a_idx];
    let b = &flow_b_segments[seg_b_idx];
    let range_a = a.off..a.off + a.len;
    let range_b = b.off..b.off + b.len;
    if &flow_a_proof[range_a] == &flow_b_proof[range_b] {
        println!("  Candidate #{candidate_idx}: identical bytes (island {island_id}, seg {seg_a_idx}); skipping.");
        continue;
    }

    // (Optional) Guard 2: skip island 0 (no FS prefix to preserve)
    if island_id == 0 {
        println!("  Skipping island 0; FS prefix length is 0 (too easy to preserve).");
        continue;
    }
    // ────────────────────────────────────────────────────────────────────────


        let spliced = splice_replace_segment(
            &flow_a_segments,
            &flow_a_proof,
            seg_a_idx,
            &flow_b_segments,
            &flow_b_proof,
            seg_b_idx,
        );

        let mut verifier = MockTranscript::new(Blake2bRead::<_, G1Affine, Challenge255<_>>::init(
            Cursor::new(spliced.clone()),
        ));
        let strategy = SingleStrategy::new(&params);
        let result = verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
            &params,
            &vk,
            strategy,
            &[&[]],
            &mut verifier,
        );

        let spliced_challenges = extract_challenges(&verifier.events());

        if baseline_challenges.len() < island_id {
            println!(
                "  Baseline challenge count ({}) is smaller than island {}; skipping candidate",
                baseline_challenges.len(),
                island_id
            );
            skipped_prefix_mismatch += 1;
            continue;
        }
        if spliced_challenges.len() < island_id {
            println!(
                "  Spliced proof yielded only {} challenges before island {}; skipping candidate",
                spliced_challenges.len(),
                island_id
            );
            skipped_prefix_mismatch += 1;
            continue;
        }

        if baseline_challenges[..island_id] != spliced_challenges[..island_id] {
            println!(
                "  FS prefix mismatch for island {island_id}; baseline {:?}, spliced {:?}",
                format_challenge_prefix(&baseline_challenges, island_id),
                format_challenge_prefix(&spliced_challenges, island_id)
            );
            skipped_prefix_mismatch += 1;
            continue;
        }

        valid_candidates += 1;

        let snapshot_count = baseline_challenges.len().min(island_id.saturating_add(1));

        if result.is_ok() {
            println!(
                "Frozen Heart success: candidate #{candidate_idx} verified after replacing Flow A segment {seg_a_idx} with Flow B segment {seg_b_idx}"
            );
            println!(
                "  Preserved FS prefix ({} challenge(s)): {:?}",
                island_id,
                format_challenge_prefix(&baseline_challenges, island_id)
            );
            println!(
                "  Divergent challenges up to island {}: baseline {:?} vs spliced {:?}",
                island_id,
                format_challenge_prefix(&baseline_challenges, snapshot_count),
                format_challenge_prefix(&spliced_challenges, snapshot_count)
            );
            success = true;
            assert!(false, "Frozen Heart: cross-flow reuse succeeded");
        } else {
            println!(
                "  Candidate #{candidate_idx} rejected. Challenge snapshot (up to island {}): baseline {:?} vs spliced {:?}",
                island_id,
                format_challenge_prefix(&baseline_challenges, snapshot_count),
                format_challenge_prefix(&spliced_challenges, snapshot_count)
            );
        }
    }

    if !success {
        let total_candidates = candidates.len();
        if valid_candidates > 0 {
            println!(
                "No intra-island reuse observed after trying {valid_candidates} candidate(s); test passes."
            );
        } else if total_candidates == 0 {
            println!("No intra-island candidates available; test passes.");
        } else {
            println!(
                "All {total_candidates} candidate(s) skipped due to FS prefix mismatches ({skipped_prefix_mismatch}); test passes."
            );
        }
    }
}