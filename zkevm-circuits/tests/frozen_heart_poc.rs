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
use helpers::mock_transcript::{MockTranscript, TEvent};
use rand::{rngs::StdRng, SeedableRng};
use zkevm_circuits::exp_circuit::ExpCircuit;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SegKind {
    Point,
    Scalar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Seg {
    kind: SegKind,
    off: usize,
    len: usize,
}

#[derive(Debug, Clone)]
struct PermutationCandidate {
    permutation: Vec<usize>,
    swapped: (usize, usize),
    crosses_challenge: bool,
}
////////////
use std::sync::OnceLock;


static PARAMS_K18: OnceLock<ParamsKZG<Bn256>> = OnceLock::new();

fn params_k18() -> &'static ParamsKZG<Bn256> {
    PARAMS_K18.get_or_init(|| {
        let mut rng = StdRng::from_entropy(); // non-blocking CSPRNG, still “real”
        ParamsKZG::<Bn256>::setup(18, &mut rng)
    })
}
////////////

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
    let params = ParamsKZG::<Bn256>::setup(18, &mut rng);
    let vk = keygen_vk(&params, circuit).expect("vk generation should succeed");
    let pk = keygen_pk(&params, vk.clone(), circuit).expect("pk generation should succeed");
    (params, vk, pk)
}

fn segment_proof(events: &[TEvent], proof: &[u8]) -> Vec<Seg> {
    let mut segments = Vec::new();
    let mut offset = 0usize;

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
                });
                offset += len;
            }
            TEvent::SqueezeChallenge(_) => {}
        }
    }

    assert_eq!(
        offset, proof.len(),
        "segments accounted for {offset} bytes, proof contains {} bytes",
        proof.len()
    );

    segments
}

fn splice_proof_bytes(segs: &[Seg], permutation: &[usize], proof: &[u8]) -> Vec<u8> {
    assert_eq!(
        segs.len(),
        permutation.len(),
        "permutation length must match segment count"
    );
    let mut output = Vec::with_capacity(proof.len());
    for &seg_idx in permutation {
        let seg = &segs[seg_idx];
        let range = seg.off..seg.off + seg.len;
        output.extend_from_slice(&proof[range]);
    }
    output
}

fn collect_absorb_event_indices(events: &[TEvent]) -> Vec<usize> {
    events
        .iter()
        .enumerate()
        .filter_map(|(idx, event)| match event {
            TEvent::AbsorbPoint(_) | TEvent::AbsorbScalar(_) => Some(idx),
            TEvent::SqueezeChallenge(_) => None,
        })
        .collect()
}

fn has_challenge_between(events: &[TEvent], a: usize, b: usize) -> bool {
    let (start, end) = if a <= b { (a, b) } else { (b, a) };
    events[start + 1..end]
        .iter()
        .any(|event| matches!(event, TEvent::SqueezeChallenge(_)))
}

fn build_permutation_candidates(events: &[TEvent], segments: &[Seg]) -> Vec<PermutationCandidate> {
    let absorb_indices = collect_absorb_event_indices(events);
    assert_eq!(
        absorb_indices.len(),
        segments.len(),
        "absorb event count should equal segment count"
    );

    let mut candidates = Vec::new();

    for (i, left) in segments.iter().enumerate() {
        for (j, right) in segments.iter().enumerate().skip(i + 1) {
            if left.kind != right.kind {
                continue;
            }
            let crosses = has_challenge_between(events, absorb_indices[i], absorb_indices[j]);
            if crosses {
                let mut perm: Vec<usize> = (0..segments.len()).collect();
                perm.swap(i, j);
                candidates.push(PermutationCandidate {
                    permutation: perm,
                    swapped: (i, j),
                    crosses_challenge: true,
                });
            }
        }
    }

    if candidates.is_empty() {
        for (i, left) in segments.iter().enumerate() {
            for (j, right) in segments.iter().enumerate().skip(i + 1) {
                if left.kind == right.kind {
                    let mut perm: Vec<usize> = (0..segments.len()).collect();
                    perm.swap(i, j);
                    candidates.push(PermutationCandidate {
                        permutation: perm,
                        swapped: (i, j),
                        crosses_challenge: has_challenge_between(
                            events,
                            absorb_indices[i],
                            absorb_indices[j],
                        ),
                    });
                    return candidates;
                }
            }
        }
    }

    candidates
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

#[test]
fn frozen_heart_cross_flow_proof_reuse() {
    let setup_circuit = sample_exp_circuit();
    let (params, vk, pk) = setup_params_and_keys(&setup_circuit);

    let proof_circuit = sample_exp_circuit();
    let prover_rng = StdRng::seed_from_u64(42);
    let mut prover_transcript = MockTranscript::new(
        Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(Vec::new()),
    );

    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<_>, _, _, _, _>(
        &params,
        &pk,
        &[proof_circuit],
        &[&[]],
        prover_rng,
        &mut prover_transcript,
    )
    .expect("proof generation should succeed");

    let flow_a_events = prover_transcript.events();
    let proof = prover_transcript.into_inner().finalize();

    println!(
        "Flow A produced {} transcript events and {} proof bytes",
        flow_a_events.len(),
        proof.len()
    );

    let segments = segment_proof(&flow_a_events, &proof);
    println!(
        "Segmented proof into {} chunks spanning {} bytes",
        segments.len(),
        proof.len()
    );

    let candidates = build_permutation_candidates(&flow_a_events, &segments);
    println!(
        "Prepared {} permutation candidate(s) for cross-flow splice",
        candidates.len()
    );

    let mut original_verifier = MockTranscript::new(
        Blake2bRead::<_, G1Affine, Challenge255<_>>::init(Cursor::new(proof.clone())),
    );
    let strategy = SingleStrategy::new(&params);
    verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
        &params,
        &vk,
        strategy,
        &[&[]],
        &mut original_verifier,
    )
    .expect("original proof must verify");

    let baseline_challenges = extract_challenges(&original_verifier.events());
    println!(
        "Baseline verifier observed {} challenge(s)",
        baseline_challenges.len()
    );

    let mut success = false;

    for candidate in &candidates {
        let spliced = splice_proof_bytes(&segments, &candidate.permutation, &proof);
        let mut verifier = MockTranscript::new(
            Blake2bRead::<_, G1Affine, Challenge255<_>>::init(Cursor::new(spliced.clone())),
        );
        let strategy = SingleStrategy::new(&params);
        let result = verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
            &params,
            &vk,
            strategy,
            &[&[]],
            &mut verifier,
        );

        let challenges = extract_challenges(&verifier.events());

        if result.is_ok() {
            println!(
                "Permutation {:?} (swap {:?}, crosses challenge = {}) verified successfully",
                candidate.permutation,
                candidate.swapped,
                candidate.crosses_challenge
            );
            println!(
                "Challenge prefix (Flow A vs. Flow B): {:?} vs {:?}",
                format_challenge_prefix(&baseline_challenges, 3),
                format_challenge_prefix(&challenges, 3)
            );
            success = true;
            assert!(false, "Frozen Heart: cross-flow reuse succeeded");
        } else {
            println!(
                "Permutation {:?} (swap {:?}, crosses challenge = {}) rejected. Challenge prefix A vs B: {:?} vs {:?}",
                candidate.permutation,
                candidate.swapped,
                candidate.crosses_challenge,
                format_challenge_prefix(&baseline_challenges, 3),
                format_challenge_prefix(&challenges, 3)
            );
        }
    }

    if !success {
        if candidates.is_empty() {
            println!("No compatible same-type permutations discovered; cross-flow splice skipped");
        } else {
            println!(
                "Attempted {} permutation(s); all resulted in verifier failure",
                candidates.len()
            );
        }
        println!(
            "Baseline challenge prefix: {:?}",
            format_challenge_prefix(&baseline_challenges, 3)
        );
        assert!(true, "Frozen Heart cross-flow reuse not observed");
    }
}