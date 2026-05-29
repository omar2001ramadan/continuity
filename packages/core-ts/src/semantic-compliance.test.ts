import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { canonicalBytes } from "./canonicalize";
import { buildIdentityFromSeed, signMessageEvent } from "./commitments";
import {
  commitmentHashFromParts,
  disclosureConsentV1Hash,
  eventHash,
  hashDomain,
  legacyCommitmentHashFromParts,
  sha256Hex,
  signEd25519,
  signReceipt,
  verifyTSL,
  buildThresholdProof,
  buildSparseMerkleTree,
  checkpointHash,
  proveSparseMerkleInclusion,
  proveSparseMerkleNonMembership,
  verifySparseMerkleProof,
  verifyThresholdProofAsync,
  zkCircuitReleaseManifestHash,
  zkProofUsesRegisteredCircuit,
  filterProofBundleDisclosures,
  type SettlementBackend
} from "./index";
import { InMemoryRelayStore, RelayValidationError } from "./relayStore";
import type { BatchCheckpointV1, DelegationPolicyV2, Hex32 } from "./types";
import {
  buildAgentActionV2,
  buildDelegationPolicyV2,
  computeDriftReportV0,
  computeEvidenceCoverageV0,
  computeGraphFeatureVectorV0,
  computeMetadataFingerprintCommitmentV0,
  computeReferenceScoreV0,
  computeSybilAssessmentV0,
  constructGraphFromEvidenceV0,
  constructGraphFromRawEdgesForTestV0,
  constructGraphV0,
  delegationPolicyV2Hash,
  graphFeatureVectorV1Hash,
  signAgentActionV2,
  signDelegationPolicyV2,
  verifyDelegatedAgentActionV0
} from "./v2";

const aliceSeed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const bobSeed = "0101010101010101010101010101010101010101010101010101010101010101";
const agentSeed = "1111111111111111111111111111111111111111111111111111111111111111";
const relaySeed = "2222222222222222222222222222222222222222222222222222222222222222";
const at = "2026-05-27T12:00:00Z";
const zero = "0x0000000000000000000000000000000000000000000000000000000000000000" as Hex32;

describe("semantic compliance hardening", () => {
  it("rejects non-fixed-point JSON values and domain-separates commitments", () => {
    expect(() => canonicalBytes({ score: 0.5 })).toThrow(/safe integers/);
    expect(() => canonicalBytes({ unsafe: Number.MAX_SAFE_INTEGER + 1 })).toThrow(/safe integers/);

    const signed = signMessageEvent({
      sender: "did:tsl:test:alice",
      signing_key_id: "#key-1",
      seed_hex: aliceSeed,
      message: "hello-tsl",
      timestamp: at,
      nonce: "0x2222222222222222222222222222222222222222222222222222222222222222",
      content_salt: "0x3333333333333333333333333333333333333333333333333333333333333333"
    });
    const canonical = commitmentHashFromParts(eventHash(signed.envelope), signed.envelope.signature);
    const legacy = legacyCommitmentHashFromParts(eventHash(signed.envelope), signed.envelope.signature);
    expect(canonical).toBe(signed.commitment_hash);
    expect(canonical).not.toBe(legacy);
  });

  it("uses exact scoring coverage, calibration, confidence, and adverse-evidence labels", () => {
    const fullCoverage = computeEvidenceCoverageV0({
      subject: "did:tsl:test:alice",
      valid_signed_event_count: 25,
      valid_receipt_count: 10,
      unique_counterparty_count: 5,
      computed_at: at
    });
    const partialCoverage = computeEvidenceCoverageV0({
      subject: "did:tsl:test:alice",
      valid_signed_event_count: 1,
      valid_receipt_count: 1,
      unique_counterparty_count: 1,
      computed_at: at
    });
    expect(fullCoverage.coverage_bps).toBe(10000);
    expect(partialCoverage.coverage_bps).toBe(Math.floor(10000 * (1 / 25) ** 0.25 * (1 / 10) ** 0.35 * (1 / 5) ** 0.4));

    const base = {
      subject: "did:tsl:test:alice",
      issuer: "did:tsl:provider:reference",
      scoring_profile_id: "reference-scoring-conformance",
      model_version: "reference-v0",
      gate_result: {
        schema_valid: true,
        canonicalization_valid: true,
        signature_valid: true,
        key_active: true,
        not_revoked: true,
        included_in_log: true,
        checkpoint_valid: true,
        settlement_satisfied: true,
        delegation_valid: true
      },
      evidence_coverage: fullCoverage,
      confidence_profile: { method: "analytic_profile_v1" as const, min_width_bps: 100, max_width_bps: 100, coverage_weight_bps: 0 },
      domain_policy: {
        type: "tsl.domain_policy.v1" as const,
        domain: "semantic-compliance",
        policy_version: "1.0.0",
        requires_settlement: false,
        requires_delegation_check: false,
        requires_content_opening: false,
        min_coverage_bps: 0,
        max_assessment_age_seconds: 86400,
        false_positive_cost_class: "high",
        false_negative_cost_class: "critical",
        sparse_identity_default: "unknown_caution",
        thresholds: { trusted_bps: 9000, likely_trusted_bps: 7500, medium_bps: 5500, suspicious_bps: 3500, high_risk_bps: 1500 }
      },
      issued_at: at
    };
    expect(computeReferenceScoreV0({ ...base, normalized_features_bps: { trust: 10000 }, weights_bps: { trust: 9000 } }).label).toBe("trusted");
    expect(computeReferenceScoreV0({ ...base, normalized_features_bps: { trust: 10000 }, weights_bps: { trust: 7500 } }).label).toBe("likely_trusted");
    expect(computeReferenceScoreV0({ ...base, evidence_coverage: { ...partialCoverage, coverage_bps: 2000 }, normalized_features_bps: { trust: 10000 }, weights_bps: { trust: 4000 } }).label).toBe("insufficient_evidence");
    expect(computeReferenceScoreV0({ ...base, normalized_features_bps: { trust: 10000 }, weights_bps: { trust: 4000 }, has_adverse_evidence: false }).label).toBe("unknown_caution");
    expect(computeReferenceScoreV0({ ...base, normalized_features_bps: { trust: 10000 }, weights_bps: { trust: 4000 }, has_adverse_evidence: true }).label).toBe("suspicious");
    expect(() =>
      computeReferenceScoreV0({
        ...base,
        normalized_features_bps: { trust: 10000 },
        weights_bps: { trust: 8000 },
        calibration_profile: {
          profile_id: "bad-calibration",
          points: [
            { raw_bps: 0, calibrated_bps: 1000 },
            { raw_bps: 5000, calibrated_bps: 900 },
            { raw_bps: 10000, calibrated_bps: 10000 }
          ]
        }
      })
    ).toThrow(/TSL_CALIBRATION_PROFILE_NON_MONOTONE/);
  });

  it("computes weighted graph geometry in fixed-point units", () => {
    const graph = constructGraphFromRawEdgesForTestV0({
      edges: [
        { src: "did:tsl:a", dst: "did:tsl:b", type: "signed_event", timestamp: at, weight_bps: 6000 },
        { src: "did:tsl:b", dst: "did:tsl:a", type: "reply_receipt", timestamp: at, weight_bps: 3000 },
        { src: "did:tsl:a", dst: "did:tsl:c", type: "completed_transaction", timestamp: at, weight_bps: 1000 }
      ]
    });
    const vector = computeGraphFeatureVectorV0({
      subject: "did:tsl:a",
      graph,
      graph_profile_id: "graph-default-rc4",
      trusted_seeds: ["did:tsl:c"],
      adversarial_seeds: ["did:tsl:b"],
      computed_at: at
    });
    expect(vector.weighted_degree_bps).toBe(10000);
    expect(vector.reciprocity_bps).toBe(6000);
    expect(vector.counterparty_hhi_bps).toBe(8200);
    expect(vector.counterparty_entropy_bps).toBe(4689);
    expect(vector.effective_counterparty_count_milli).toBe(1384);
    expect(vector.seed_escape_bps).toBe(1000);
    expect(vector.adversarial_proximity_bps).toBe(9000);
    expect(vector.community_escape_bps).toBe(0);
    expect(vector.trusted_neighbor_mass_bps).toBe(1000);
    expect(vector.ppr_lite_bps).toBeGreaterThan(0);
  });

  it("constructs protocol graph edges only from verified evidence", async () => {
    const alice = buildIdentityFromSeed({ trust_id: "did:tsl:test:alice", key_id: "#alice", seed_hex: aliceSeed, created_at: "2026-01-01T00:00:00Z" });
    const bob = buildIdentityFromSeed({ trust_id: "did:tsl:test:bob", key_id: "#bob", seed_hex: bobSeed, created_at: "2026-01-01T00:00:00Z" });
    const identities = new Map([alice, bob].map((identity) => [identity.id, identity]));
    const resolver = { resolveTrustID: (trustId: string) => identities.get(trustId) ?? null };
    const signed = signMessageEvent({
      sender: alice.id,
      signing_key_id: "#alice",
      seed_hex: aliceSeed,
      message: "verified graph",
      timestamp: at,
      nonce: "0x8888888888888888888888888888888888888888888888888888888888888888"
    });
    const receipt = signReceipt(
      {
        type: "tsl.receipt_commitment.v1",
        event_commitment: signed.commitment_hash,
        receiver: bob.id,
        signing_key_id: "#bob",
        receipt_class: "replied",
        timestamp: "2026-05-27T12:00:01Z"
      },
      bobSeed
    );
    const graph = await constructGraphFromEvidenceV0({
      events: [signed.envelope],
      receipts: [receipt, { ...receipt, signature: "0x00" }],
      resolver,
      graph_profile: {
        type: "tsl.graph_profile.v2",
        profile_id: "graph-default-rc4",
        edge_weight_profile: "default",
        temporal_decay_profile: "none",
        community_detection: { algorithm: "connected_components", resolution_bps: 10000, min_cluster_size: 1 },
        seed_sets: { trusted_seed_commitment: zero, adversarial_seed_commitment: zero },
        negative_edge_policy: { requires_evidence_commitment: true, requires_appeal_uri: true, max_single_negative_weight_bps: 1500, decay_days: 30 },
        privacy_policy: { raw_counterparty_upload_required: false, allows_pairwise_private_features: true }
      },
      at_time: at,
      event_receivers: { [signed.commitment_hash]: bob.id }
    });
    expect(graph.edges.map((edge) => edge.type)).toEqual(["signed_event", "replied"]);
    expect(graph.edges[0]).toMatchObject({ src: alice.id, dst: bob.id });
    expect(graph.edges[1]).toMatchObject({ src: bob.id, dst: alice.id });
  });

  it("redacts receipts and restricted attestations from proof bundles by default", () => {
    const alice = buildIdentityFromSeed({ trust_id: "did:tsl:test:alice", key_id: "#alice", seed_hex: aliceSeed, created_at: "2026-01-01T00:00:00Z" });
    const bob = buildIdentityFromSeed({ trust_id: "did:tsl:test:bob", key_id: "#bob", seed_hex: bobSeed, created_at: "2026-01-01T00:00:00Z" });
    const signed = signMessageEvent({ sender: alice.id, signing_key_id: "#alice", seed_hex: aliceSeed, message: "bundle", timestamp: at });
    const receipt = signReceipt(
      {
        type: "tsl.receipt_commitment.v1",
        event_commitment: signed.commitment_hash,
        receiver: bob.id,
        signing_key_id: "#bob",
        receipt_class: "received",
        timestamp: at
      },
      bobSeed
    );
    const filtered = filterProofBundleDisclosures({
      type: "tsl.proof_bundle.v1",
      bundle_id: signed.commitment_hash,
      created_at: at,
      identity: alice,
      envelope: signed.envelope,
      proof: { type: "tsl.inclusion_proof.v1", tree_kind: "event", commitment: signed.commitment_hash, leaf_index: 0, leaf_hash: signed.commitment_hash, root: signed.commitment_hash, epoch_start_ms: 0, epoch_duration_ms: 300000, shard: "test", path: [], checkpoint_hash: zero },
      checkpoint: { type: "tsl.batch_checkpoint.v1", epoch_start_ms: 0, epoch_duration_ms: 300000, shard: "test", event_root: signed.commitment_hash, receipt_root: zero, attestation_root: zero, revocation_root: zero, event_count: 1, receipt_count: 0, previous_checkpoint: zero, relay_id: "did:tsl:relay:test", relay_signature: "0x00" },
      receipts: [receipt],
      attestations: [
        { type: "tsl.attestation.v1", issuer: bob.id, subject: alice.id, attestation_class: "known_business", claim_commitment: sha256Hex("public"), visibility: "public", issued_at: at, signature: "0x00" },
        { type: "tsl.attestation.v1", issuer: bob.id, subject: alice.id, attestation_class: "private_claim", claim_commitment: sha256Hex("private"), visibility: "private", issued_at: at, signature: "0x00" }
      ],
      redaction_manifest: { raw_content_included: false, exact_counterparties_included: true, metadata_fields_redacted: [] }
    });
    expect(filtered.receipts).toBeUndefined();
    expect(filtered.attestations?.map((attestation) => attestation.visibility)).toEqual(["public"]);
    expect(filtered.redaction_manifest.exact_counterparties_included).toBe(false);
    expect(filtered.redaction_manifest.metadata_fields_redacted).toContain("exact_counterparties");
    expect(filtered.redaction_manifest.metadata_fields_redacted).toContain("restricted_attestations");
  });

  it("rejects raw-edge protocol graph input and recomputes event-only graph claims", async () => {
    expect(() => constructGraphV0({ edges: [] } as never)).toThrow(/TSL_RAW_EDGE_PROTOCOL_INPUT_REJECTED/);

    const identity = buildIdentityFromSeed({ trust_id: "did:tsl:test:alice", key_id: "#key-1", seed_hex: aliceSeed, created_at: "2026-01-01T00:00:00Z" });
    const signed = signMessageEvent({ sender: identity.id, signing_key_id: "#key-1", seed_hex: aliceSeed, message: "event-only", timestamp: at });
    const graphProfile = {
      type: "tsl.graph_profile.v2" as const,
      profile_id: "graph-default-rc4",
      edge_weight_profile: "default",
      temporal_decay_profile: "none",
      community_detection: { algorithm: "connected_components" as const, resolution_bps: 10000, min_cluster_size: 1 },
      seed_sets: { trusted_seed_commitment: zero, adversarial_seed_commitment: zero },
      negative_edge_policy: { requires_evidence_commitment: true, requires_appeal_uri: true, max_single_negative_weight_bps: 1500, decay_days: 30 },
      privacy_policy: { raw_counterparty_upload_required: false, allows_pairwise_private_features: true }
    };
    const badVectorUnsigned = computeGraphFeatureVectorV0({
      subject: identity.id,
      graph: constructGraphFromRawEdgesForTestV0({ edges: [{ src: identity.id, dst: "did:tsl:test:bob", type: "signed_event", timestamp: at, weight_bps: 5000 }] }),
      graph_profile_id: graphProfile.profile_id,
      graph_profile: graphProfile,
      computed_at: at
    });
    const badVector = { ...badVectorUnsigned, signature: signEd25519(graphFeatureVectorV1Hash(badVectorUnsigned), aliceSeed) };
    const result = await verifyTSL(
      { envelope: signed.envelope, graph_profile: graphProfile, graph_feature_vector: badVector },
      { resolveTrustID: () => identity },
      { require_graph_artifacts: true }
    );
    expect(result.verified).toBe(false);
    expect(result.errors).toContain("TSL_GRAPH_ARTIFACTS_INVALID");
  });

  it("supports deterministic louvain/leiden aliases and PageRank-like seed distance fields", async () => {
    const graph = constructGraphFromRawEdgesForTestV0({
      edges: [
        { src: "did:tsl:a", dst: "did:tsl:b", type: "signed_event", timestamp: at, weight_bps: 8000 },
        { src: "did:tsl:b", dst: "did:tsl:c", type: "signed_event", timestamp: at, weight_bps: 8000 },
        { src: "did:tsl:a", dst: "did:tsl:trusted", type: "signed_event", timestamp: at, weight_bps: 2000 },
        { src: "did:tsl:bad", dst: "did:tsl:a", type: "scam_warning", timestamp: at, weight_bps: 9000 }
      ]
    });
    const baseProfile = {
      type: "tsl.graph_profile.v2" as const,
      profile_id: "graph-louvain-rc4",
      edge_weight_profile: "default",
      temporal_decay_profile: "none",
      community_detection: {
        algorithm: "louvain_modularity_v1" as const,
        resolution_bps: 10000,
        min_cluster_size: 1,
        edge_weight_floor_bps: 1000,
        deterministic_ordering: "node_id_lexicographic" as const,
        max_passes: 8,
        approximation_tolerance_bps: 0
      },
      seed_sets: { trusted_seed_commitment: zero, adversarial_seed_commitment: zero },
      negative_edge_policy: { requires_evidence_commitment: true, requires_appeal_uri: true, max_single_negative_weight_bps: 1500, decay_days: 30 },
      privacy_policy: { raw_counterparty_upload_required: false, allows_pairwise_private_features: true },
      pagerank: { iterations: 10, damping_bps: 8500, personalization: "subject" as const }
    };
    const louvain = computeGraphFeatureVectorV0({
      subject: "did:tsl:a",
      graph,
      graph_profile_id: baseProfile.profile_id,
      graph_profile: baseProfile,
      trusted_seeds: ["did:tsl:trusted"],
      adversarial_seeds: ["did:tsl:bad"],
      computed_at: at
    });
    const leiden = computeGraphFeatureVectorV0({
      subject: "did:tsl:a",
      graph,
      graph_profile_id: "graph-leiden-rc4",
      graph_profile: { ...baseProfile, profile_id: "graph-leiden-rc4", community_detection: { ...baseProfile.community_detection, algorithm: "leiden" } },
      trusted_seeds: ["did:tsl:trusted"],
      adversarial_seeds: ["did:tsl:bad"],
      computed_at: at
    });
    expect(louvain.community_algorithm_id).toBe("louvain_modularity_v1");
    expect(leiden.community_algorithm_id).toBe("leiden_refinement_v1");
    expect(louvain.modularity_bps).toBeGreaterThanOrEqual(0);
    expect(louvain.community_pass_count).toBeGreaterThan(0);
    expect(louvain.trusted_seed_distance_bps).toBe(5000);
    expect(louvain.adversarial_seed_distance_bps).toBe(5000);
    expect(louvain.pagerank_bps).toBeGreaterThan(0);
    expect(louvain.adversarial_proximity_bps).toBeLessThan(9000);
    expect(louvain.recomputation_commitment).toMatch(/^0x[0-9a-f]{64}$/);
    const decayedIdentity = buildIdentityFromSeed({ trust_id: "did:tsl:a", key_id: "#a", seed_hex: aliceSeed, created_at: "2026-01-01T00:00:00Z" });
    const oldEvent = signMessageEvent({ sender: decayedIdentity.id, signing_key_id: "#a", seed_hex: aliceSeed, message: "old", timestamp: "2026-02-26T12:00:00Z" });
    const decayedGraph = await constructGraphFromEvidenceV0({
      events: [oldEvent.envelope],
      resolver: { resolveTrustID: () => decayedIdentity },
      graph_profile: { ...baseProfile, temporal_decay_profile: "default_decay_v2", community_detection: { ...baseProfile.community_detection, algorithm: "louvain" } },
      at_time: at,
      event_receivers: { [oldEvent.commitment_hash]: "did:tsl:b" }
    });
    const decayed = computeGraphFeatureVectorV0({
      subject: "did:tsl:a",
      graph: decayedGraph,
      graph_profile_id: "graph-default-decay",
      graph_profile: { ...baseProfile, temporal_decay_profile: "default_decay_v2", community_detection: { ...baseProfile.community_detection, algorithm: "louvain" } },
      computed_at: at
    });
    expect(decayed.community_algorithm_id).toBe("louvain_modularity_v1");
    expect(decayed.weighted_degree_bps).toBeLessThan(6000);
  });

  it("detects Sybil concentration and dormant drift with deterministic labels", () => {
    const graph = constructGraphFromRawEdgesForTestV0({
      edges: [
        { src: "did:tsl:a", dst: "did:tsl:b", type: "receipt", timestamp: at, created_at: at, issuer: "did:tsl:i", weight_bps: 9000 },
        { src: "did:tsl:b", dst: "did:tsl:a", type: "receipt", timestamp: at, created_at: at, issuer: "did:tsl:i", weight_bps: 9000 },
        { src: "did:tsl:a", dst: "did:tsl:seed", type: "signed_event", timestamp: at, weight_bps: 100 }
      ]
    });
    const sybil = computeSybilAssessmentV0({
      subject: "did:tsl:a",
      graph,
      graph_profile: {
        type: "tsl.graph_profile.v2",
        profile_id: "graph-default-rc4",
        edge_weight_profile: "default",
        temporal_decay_profile: "none",
        community_detection: { algorithm: "connected_components", resolution_bps: 10000, min_cluster_size: 1 },
        seed_sets: { trusted_seed_commitment: zero, adversarial_seed_commitment: zero },
        negative_edge_policy: { requires_evidence_commitment: true, requires_appeal_uri: true, max_single_negative_weight_bps: 1500, decay_days: 30 },
        privacy_policy: { raw_counterparty_upload_required: false, allows_pairwise_private_features: true }
      },
      trusted_seeds: ["did:tsl:seed"],
      computed_at: at
    });
    expect(sybil.risk_label).toBe("high");
    expect(sybil.cluster_concentration_bps).toBeGreaterThan(9000);
    expect(sybil.trusted_escape_bps).toBeGreaterThan(0);
    expect(sybil.receipt_symmetry_bps).toBe(10000);

    const drift = computeDriftReportV0({
      subject: "did:tsl:a",
      feature_history: [
        { timestamp: "2026-04-20T12:00:00Z", verified_event: true, components: { action: 1000, cadence: 900, graph: 1000 } },
        { timestamp: "2026-05-01T12:00:00Z", verified_event: true, components: { action: 1200, cadence: 1100, graph: 1000 } },
        { timestamp: "2026-05-10T12:00:00Z", verified_event: true, components: { action: 1100, cadence: 1000, graph: 900 } },
        { timestamp: "2026-05-27T11:00:00Z", high_value_action: true, components: { action: 9100, cadence: 8200, graph: 2500 } }
      ],
      baseline_window_days: 90,
      observation_window_days: 7,
      dormant_days: 1,
      computed_at: at
    });
    expect(drift.drift_label).toBe("dormant_reactivation");
    expect(drift.action).toBe("step_up");
    expect(drift.drift_score_bps).toBeGreaterThanOrEqual(8000);
    expect(drift.feature_history_commitment).toMatch(/^0x[0-9a-f]{64}$/);
    expect(drift.covariance_profile_commitment).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("requires seed governance openings to match graph profile commitments", async () => {
    const subject = buildIdentityFromSeed({ trust_id: "did:tsl:test:alice", key_id: "#key-1", seed_hex: aliceSeed, created_at: "2026-01-01T00:00:00Z" });
    const governor = buildIdentityFromSeed({ trust_id: "did:tsl:seed-governor:test", key_id: "#gov", seed_hex: relaySeed, created_at: "2026-01-01T00:00:00Z" });
    const signed = signMessageEvent({ sender: subject.id, signing_key_id: "#key-1", seed_hex: aliceSeed, message: "seed-governance", timestamp: at });
    const trustedSeeds = ["did:tsl:trusted:1"];
    const adversarialSeeds = ["did:tsl:adversarial:1"];
    const trustedCommitment = sha256Hex(canonicalBytes(trustedSeeds));
    const adversarialCommitment = sha256Hex(canonicalBytes(adversarialSeeds));
    const unsignedTrusted = {
      type: "tsl.seed_governance_profile.v1" as const,
      profile_id: "trusted-seeds-v1",
      issuer: governor.id,
      review_state: "approved" as const,
      source_class: "auditor_curated" as const,
      seed_class: "trusted" as const,
      seeds: trustedSeeds,
      seed_set_commitment: trustedCommitment,
      governance_policy_commitment: sha256Hex("governance"),
      reviewed_at: at,
      signature: "0x00" as const
    };
    const unsignedAdversarial = { ...unsignedTrusted, profile_id: "adversarial-seeds-v1", seed_class: "adversarial" as const, seeds: adversarialSeeds, seed_set_commitment: adversarialCommitment };
    const stripSignature = (profile: Record<string, unknown>) => {
      const copy = { ...profile } as Record<string, unknown>;
      delete copy.signature;
      return copy;
    };
    const trustedGovernance = { ...unsignedTrusted, signature: signEd25519(sha256Hex(canonicalBytes(stripSignature(unsignedTrusted))), relaySeed) };
    const adversarialGovernance = { ...unsignedAdversarial, signature: signEd25519(sha256Hex(canonicalBytes(stripSignature(unsignedAdversarial))), relaySeed) };
    const graphProfile = {
      type: "tsl.graph_profile.v2" as const,
      profile_id: "graph-seed-governed",
      edge_weight_profile: "default",
      temporal_decay_profile: "none",
      community_detection: { algorithm: "connected_components" as const, resolution_bps: 10000, min_cluster_size: 1 },
      seed_sets: {
        trusted_seed_commitment: trustedCommitment,
        adversarial_seed_commitment: adversarialCommitment,
        trusted_seed_governance_commitment: sha256Hex(canonicalBytes(stripSignature(trustedGovernance))),
        adversarial_seed_governance_commitment: sha256Hex(canonicalBytes(stripSignature(adversarialGovernance)))
      },
      negative_edge_policy: { requires_evidence_commitment: true, requires_appeal_uri: true, max_single_negative_weight_bps: 1500, decay_days: 30 },
      privacy_policy: { raw_counterparty_upload_required: false, allows_pairwise_private_features: true }
    };
    const result = await verifyTSL(
      {
        envelope: signed.envelope,
        graph_profile: graphProfile,
        trusted_seeds: trustedSeeds,
        adversarial_seeds: ["did:tsl:wrong"],
        trusted_seed_governance: trustedGovernance,
        adversarial_seed_governance: adversarialGovernance
      },
      { resolveTrustID: (trustId: string) => (trustId === subject.id ? subject : trustId === governor.id ? governor : null) },
      { require_seed_governance_opening: true }
    );
    expect(result.verified).toBe(false);
    expect(result.errors).toContain("TSL_SEED_GOVERNANCE_OPENING_INVALID");
  });

  it("scopes metadata fingerprints by verifier, epoch, and bucketized metadata only", () => {
    const common = {
      subject: "did:tsl:a",
      metadata: { event_class: "message", timestamp: at, content_length_bytes: 300, platform: "leaky", ip_address: "127.0.0.1" },
      master_key_hex: aliceSeed,
      epoch: "2026-05-27T12:00:00.000Z",
      purpose: "pairwise_verifier" as const,
      bucket_profile: "default",
      salt_hex: "0x4444444444444444444444444444444444444444444444444444444444444444" as Hex32,
      expires_at: "2026-08-27T12:00:00Z"
    };
    const first = computeMetadataFingerprintCommitmentV0({ ...common, verifier_domain: "one.example" });
    const second = computeMetadataFingerprintCommitmentV0({ ...common, verifier_domain: "two.example" });
    expect(first.fingerprint_commitment).not.toBe(second.fingerprint_commitment);
    expect(first.created_at_bucket).toBe("2026-05-27T12:00:00.000Z");
    expect(first.disclosure_policy).toBe("selective");
  });

  it("rejects raw message disclosure without explicit consent", async () => {
    const identity = buildIdentityFromSeed({ trust_id: "did:tsl:test:alice", key_id: "#key-1", seed_hex: aliceSeed, created_at: "2026-01-01T00:00:00Z" });
    const signed = signMessageEvent({
      sender: identity.id,
      signing_key_id: "#key-1",
      seed_hex: aliceSeed,
      message: "private",
      timestamp: at,
      content_salt: "0x9999999999999999999999999999999999999999999999999999999999999999"
    });
    const result = await verifyTSL(
      {
        envelope: signed.envelope,
        message_disclosure: {
          raw_message: "private",
          content_salt: "0x9999999999999999999999999999999999999999999999999999999999999999"
        }
      },
      { resolveTrustID: () => identity }
    );
    expect(result.verified).toBe(false);
    expect(result.errors).toContain("TSL_DISCLOSURE_CONSENT_MISSING");
  });

  it("requires signed disclosure consent bound to verifier and purpose", async () => {
    const identity = buildIdentityFromSeed({ trust_id: "did:tsl:test:alice", key_id: "#key-1", seed_hex: aliceSeed, created_at: "2026-01-01T00:00:00Z" });
    const signed = signMessageEvent({
      sender: identity.id,
      signing_key_id: "#key-1",
      seed_hex: aliceSeed,
      message: "private",
      timestamp: at,
      content_salt: "0x9999999999999999999999999999999999999999999999999999999999999999"
    });
    const unsignedConsent = {
      type: "tsl.disclosure_consent.v1" as const,
      subject: identity.id,
      verifier_or_provider: "did:tsl:verifier:local",
      allowed_field_classes: ["raw_content", "content_salt"],
      forbidden_field_classes: ["ip_address", "user_agent"],
      purpose: "verification_opening",
      issued_at: "2026-05-27T00:00:00Z",
      expires_at: "2026-05-28T00:00:00Z",
      revocation_pointer: "rev:consent:1",
      signature: "0x00" as const
    };
    const consent = { ...unsignedConsent, signature: signEd25519(disclosureConsentV1Hash(unsignedConsent), aliceSeed) };
    const accepted = await verifyTSL(
      {
        envelope: signed.envelope,
        message_disclosure: {
          raw_message: "private",
          content_salt: "0x9999999999999999999999999999999999999999999999999999999999999999"
        },
        disclosure_consents: [consent]
      },
      { resolveTrustID: () => identity },
      { verifier_or_provider: "did:tsl:verifier:local", disclosure_purpose: "verification_opening" }
    );
    expect(accepted.verified).toBe(true);
    expect(accepted.checks.disclosure_consent_valid).toBe(true);

    const wrongPurpose = await verifyTSL(
      {
        envelope: signed.envelope,
        message_disclosure: {
          raw_message: "private",
          content_salt: "0x9999999999999999999999999999999999999999999999999999999999999999"
        },
        disclosure_consents: [consent]
      },
      { resolveTrustID: () => identity },
      { verifier_or_provider: "did:tsl:verifier:local", disclosure_purpose: "scoring_upload" }
    );
    expect(wrongPurpose.verified).toBe(false);
    expect(wrongPurpose.errors).toContain("TSL_DISCLOSURE_CONSENT_MISSING");
  });

  it("rejects hash-only ZK fixtures unless unsafe test mode is explicit", async () => {
    const proof = buildThresholdProof({
      claim: "identity_age_days",
      subject: "did:tsl:test:alice",
      value: 400,
      threshold: 365,
      witness_salt: "0x1212121212121212121212121212121212121212121212121212121212121212",
      issued_at: at
    });
    const previous = process.env.ALLOW_UNSAFE_ZK_HASH_FIXTURES;
    try {
      process.env.ALLOW_UNSAFE_ZK_HASH_FIXTURES = "false";
      await expect(verifyThresholdProofAsync(proof)).resolves.toBe(false);
      process.env.ALLOW_UNSAFE_ZK_HASH_FIXTURES = "true";
      await expect(verifyThresholdProofAsync(proof)).resolves.toBe(true);
    } finally {
      if (previous === undefined) delete process.env.ALLOW_UNSAFE_ZK_HASH_FIXTURES;
      else process.env.ALLOW_UNSAFE_ZK_HASH_FIXTURES = previous;
    }
  });

  it("binds production ZK proofs to active circuit release manifests", () => {
    const manifest = {
      type: "tsl.zk.circuit_release_manifest.v1" as const,
      circuit_id: "identity-age-threshold-v1",
      claim: "identity_age_days" as const,
      version: "1.0.0",
      circuit_hash: sha256Hex("circuit"),
      r1cs_hash: sha256Hex("r1cs"),
      wasm_hash: sha256Hex("wasm"),
      zkey_hash: sha256Hex("zkey"),
      verification_key_id: "identity-age-vkey-v1",
      verification_key_hash: sha256Hex("vkey"),
      ceremony_transcript_hash: sha256Hex("ceremony"),
      auditor: "did:tsl:auditor:test",
      reviewer: "did:tsl:reviewer:test",
      status: "active" as const,
      issued_at: at
    };
    const releaseManifestHash = zkCircuitReleaseManifestHash(manifest);
    const proof = {
      ...buildThresholdProof({
        claim: "identity_age_days",
        subject: "did:tsl:test:alice",
        value: 400,
        threshold: 365,
        witness_salt: "0x1212121212121212121212121212121212121212121212121212121212121212",
        issued_at: at
      }),
      circuit_id: manifest.circuit_id,
      verification_key_id: manifest.verification_key_id,
      release_manifest_hash: releaseManifestHash
    };
    expect(
      zkProofUsesRegisteredCircuit({
        proof,
        manifests: [manifest],
        registry: {
          type: "tsl.zk.verification_key_registry.v1",
          registry_id: "zk-registry-test",
          active_manifest_hashes: [releaseManifestHash],
          revoked_manifest_hashes: [],
          issued_at: at
        }
      })
    ).toBe(true);
    expect(
      zkProofUsesRegisteredCircuit({
        proof: { ...proof, verification_key_id: "wrong" },
        manifests: [manifest],
        registry: {
          type: "tsl.zk.verification_key_registry.v1",
          registry_id: "zk-registry-test",
          active_manifest_hashes: [releaseManifestHash],
          revoked_manifest_hashes: [],
          issued_at: at
        }
      })
    ).toBe(false);
  });

  it("verifies sparse-Merkle inclusion and non-membership by recomputing the root", () => {
    const values = [sha256Hex("revoked-a"), sha256Hex("revoked-b")] as Hex32[];
    const tree = buildSparseMerkleTree(values, { tree_id: "revocation-set-v1", tree_depth: 8 });
    const inclusion = proveSparseMerkleInclusion(values[0], tree, "did:tsl:test:alice", at);
    const absent = proveSparseMerkleNonMembership(sha256Hex("not-revoked") as Hex32, tree, "did:tsl:test:alice", at);
    expect(verifySparseMerkleProof(inclusion, tree.root, tree.profile)).toBe(true);
    expect(verifySparseMerkleProof(absent, tree.root, tree.profile)).toBe(true);
    expect(verifySparseMerkleProof({ ...absent, root: zero, set_root: zero }, tree.root, tree.profile)).toBe(false);
    expect(verifySparseMerkleProof({ ...absent, sibling_path: absent.sibling_path?.slice(1) }, tree.root, tree.profile)).toBe(false);
    expect(verifySparseMerkleProof({ ...absent, leaf_index: ((absent.leaf_index ?? 0) + 1) % 256 }, tree.root, tree.profile)).toBe(false);
  });

  it("binds sparse non-membership proofs to checkpoint revocation roots", async () => {
    const identity = buildIdentityFromSeed({ trust_id: "did:tsl:test:alice", key_id: "#key-1", seed_hex: aliceSeed, created_at: "2026-01-01T00:00:00Z" });
    const relay = buildIdentityFromSeed({ trust_id: "did:tsl:relay:test", key_id: "#relay-checkpoint", seed_hex: relaySeed, created_at: "2026-01-01T00:00:00Z" });
    const signed = signMessageEvent({ sender: identity.id, signing_key_id: "#key-1", seed_hex: aliceSeed, message: "nonmembership", timestamp: at });
    const tree = buildSparseMerkleTree([sha256Hex("revoked-a") as Hex32], { tree_id: "revocation-set-v1", tree_depth: 8 });
    const checkpointBase: BatchCheckpointV1 = {
      type: "tsl.batch_checkpoint.v1",
      epoch_start_ms: Date.parse(at),
      epoch_duration_ms: 300000,
      shard: "test",
      event_root: zero,
      receipt_root: zero,
      attestation_root: zero,
      revocation_root: tree.root,
      event_count: 0,
      receipt_count: 0,
      previous_checkpoint: zero,
      relay_id: relay.id,
      relay_signature: "0x00"
    };
    const checkpoint = { ...checkpointBase, relay_signature: signEd25519(checkpointHash(checkpointBase), relaySeed) };
    expect(checkpointHash({ ...checkpointBase, settlement_backend: "eip155:1", settlement_tx: "0xabc" })).not.toBe(checkpointHash(checkpointBase));
    const absent = proveSparseMerkleNonMembership(sha256Hex("not-revoked") as Hex32, tree, identity.id, at, checkpointHash(checkpoint));
    const accepted = await verifyTSL(
      { envelope: signed.envelope, checkpoint, non_membership_proofs: [absent] },
      { resolveTrustID: (trustId: string) => (trustId === identity.id ? identity : trustId === relay.id ? relay : null) },
      { require_non_membership_proof: true, require_sparse_merkle_revocation_root: true }
    );
    expect(accepted.verified).toBe(true);

    const wrongCheckpointBase = { ...checkpointBase, revocation_root: sha256Hex("other-root") as Hex32 };
    const wrongCheckpoint = { ...wrongCheckpointBase, relay_signature: signEd25519(checkpointHash(wrongCheckpointBase), relaySeed) };
    const rejected = await verifyTSL(
      { envelope: signed.envelope, checkpoint: wrongCheckpoint, non_membership_proofs: [{ ...absent, root_checkpoint: checkpointHash(wrongCheckpoint) }] },
      { resolveTrustID: (trustId: string) => (trustId === identity.id ? identity : trustId === relay.id ? relay : null) },
      { require_non_membership_proof: true, require_sparse_merkle_revocation_root: true }
    );
    expect(rejected.verified).toBe(false);
    expect(rejected.errors).toContain("TSL_NON_MEMBERSHIP_PROOF_INVALID");
  });

  it("verifies relay checkpoint signatures against relay identity keys", async () => {
    const store = new InMemoryRelayStore({
      relay_id: "did:tsl:relay:test",
      relay_signing_seed_hex: relaySeed,
      timestamp_window_ms: Number.MAX_SAFE_INTEGER
    });
    const identity = buildIdentityFromSeed({ trust_id: "did:tsl:test:alice", key_id: "#key-1", seed_hex: aliceSeed, created_at: "2026-01-01T00:00:00Z" });
    store.upsertIdentity(identity);
    const signed = signMessageEvent({ sender: identity.id, signing_key_id: "#key-1", seed_hex: aliceSeed, message: "checkpoint", timestamp: at });
    await store.acceptEvent(signed.envelope);
    const proof = store.proofFor(signed.commitment_hash);
    expect(proof).not.toBeNull();

    const valid = await verifyTSL({ envelope: signed.envelope, ...proof! }, store.resolver, { require_inclusion: true, require_checkpoint: true });
    expect(valid.verified).toBe(true);
    expect(valid.checks.checkpoint_signature_valid).toBe(true);

    const invalid = await verifyTSL(
      { envelope: signed.envelope, proof: proof!.proof, checkpoint: { ...proof!.checkpoint, relay_signature: "0x1234" } },
      store.resolver,
      { require_inclusion: true, require_checkpoint: true }
    );
    expect(invalid.verified).toBe(false);
    expect(invalid.errors).toContain("TSL_CHECKPOINT_SIGNATURE_INVALID");

    const missingRelay = await verifyTSL(
      { envelope: signed.envelope, ...proof! },
      { resolveTrustID: (trustId: string) => (trustId === identity.id ? identity : null) },
      { require_inclusion: true, require_checkpoint: true }
    );
    expect(missingRelay.verified).toBe(false);
    expect(missingRelay.errors).toContain("TSL_CHECKPOINT_SIGNATURE_INVALID");
  });

  it("accepts zero checkpoint signatures only under explicit unsafe fixture mode", async () => {
    const identity = buildIdentityFromSeed({ trust_id: "did:tsl:test:alice", key_id: "#key-1", seed_hex: aliceSeed, created_at: "2026-01-01T00:00:00Z" });
    const store = new InMemoryRelayStore({ timestamp_window_ms: Number.MAX_SAFE_INTEGER });
    store.upsertIdentity(identity);
    const signed = signMessageEvent({ sender: identity.id, signing_key_id: "#key-1", seed_hex: aliceSeed, message: "fixture", timestamp: at });
    await store.acceptEvent(signed.envelope);
    const proof = store.proofFor(signed.commitment_hash)!;
    const zeroSignatureCheckpoint = { ...proof.checkpoint, relay_signature: "0x00" as const };

    const previous = process.env.ALLOW_UNSAFE_CHECKPOINT_SIGNATURE_FIXTURES;
    try {
      process.env.ALLOW_UNSAFE_CHECKPOINT_SIGNATURE_FIXTURES = "false";
      const rejected = await verifyTSL(
        { envelope: signed.envelope, proof: proof.proof, checkpoint: zeroSignatureCheckpoint },
        store.resolver,
        { require_inclusion: true, require_checkpoint: true }
      );
      expect(rejected.verified).toBe(false);
      expect(rejected.errors).toContain("TSL_CHECKPOINT_SIGNATURE_INVALID");

      process.env.ALLOW_UNSAFE_CHECKPOINT_SIGNATURE_FIXTURES = "true";
      const accepted = await verifyTSL(
        { envelope: signed.envelope, proof: proof.proof, checkpoint: zeroSignatureCheckpoint },
        store.resolver,
        { require_inclusion: true, require_checkpoint: true }
      );
      expect(accepted.verified).toBe(true);
      expect(accepted.checks.checkpoint_signature_valid).toBe(true);
    } finally {
      if (previous === undefined) delete process.env.ALLOW_UNSAFE_CHECKPOINT_SIGNATURE_FIXTURES;
      else process.env.ALLOW_UNSAFE_CHECKPOINT_SIGNATURE_FIXTURES = previous;
    }
  });

  it("enforces delegated action issued_at, deny override, constraints, and parameter commitments", () => {
    const principal = buildIdentityFromSeed({ trust_id: "did:tsl:principal", key_id: "#p", seed_hex: aliceSeed, created_at: "2026-01-01T00:00:00Z" });
    const agent = buildIdentityFromSeed({ trust_id: "did:tsl:agent", key_id: "#a", seed_hex: agentSeed, created_at: "2026-01-01T00:00:00Z" });
    const allow = signDelegationPolicyV2(
      buildDelegationPolicyV2({
        principal: principal.id,
        delegate: agent.id,
        effect: "allow",
        actions: ["invoice.pay"],
        resources: ["invoice/*"],
        constraints: { max_value_minor_units: 1000, allowed_tools: ["stripe"], currency: "USD" },
        valid_from: "2026-05-27T00:00:00Z",
        valid_until: "2026-05-28T00:00:00Z",
        revocation_pointer: "rev:allow"
      }),
      aliceSeed
    );
    const params = { value_minor_units: 900, currency: "USD" };
    const action = signAgentActionV2(
      buildAgentActionV2({
        agent: agent.id,
        principal: principal.id,
        action: "invoice.pay",
        resource: "invoice/123",
        tool: "stripe",
        value_minor_units: 900,
        parameters_commitment: hashDomain("tsl.agent.parameters.v1", canonicalBytes(params)),
        delegation_chain_root: sha256Hex(canonicalBytes([delegationPolicyV2Hash(allow)])),
        nonce: "0x5555555555555555555555555555555555555555555555555555555555555555",
        issued_at: at
      }),
      agentSeed
    );
    const public_keys = {
      [principal.id]: principal.verification_methods[0]!.public_key,
      [agent.id]: agent.verification_methods[0]!.public_key
    };
    expect(verifyDelegatedAgentActionV0({ action, delegation_chain: [allow], public_keys, at_time: "2026-05-27T23:59:59Z", parameters: params }).ok).toBe(true);
    expect(verifyDelegatedAgentActionV0({ action, delegation_chain: [allow], public_keys, at_time: "2026-05-29T00:00:00Z", parameters: params }).ok).toBe(true);
    expect(verifyDelegatedAgentActionV0({ action, delegation_chain: [allow], public_keys, revoked_policy_ids: [allow.policy_id], parameters: params }).error_code).toBe("TSL_DELEGATION_REVOKED");

    const { signature: _allowSignature, ...allowUnsigned } = allow;
    const deny: DelegationPolicyV2 = signDelegationPolicyV2({ ...allowUnsigned, policy_id: "0x6666666666666666666666666666666666666666666666666666666666666666", effect: "deny" }, aliceSeed);
    const denyRootAction = signAgentActionV2({ ...action, delegation_chain_root: sha256Hex(canonicalBytes([delegationPolicyV2Hash(allow), delegationPolicyV2Hash(deny)])) }, agentSeed);
    expect(verifyDelegatedAgentActionV0({ action: denyRootAction, delegation_chain: [allow, deny], public_keys, parameters: params }).error_code).toBe("TSL_DELEGATION_SCOPE_VIOLATION");
    expect(verifyDelegatedAgentActionV0({ action, delegation_chain: [allow], public_keys, parameters: { ...params, value_minor_units: 901 } }).error_code).toBe("TSL_DELEGATION_CONSTRAINT_VIOLATION");
  });

  it("freezes checkpointed log segments", async () => {
    const settlement: SettlementBackend = {
      async submitCheckpoint(checkpoint: BatchCheckpointV1) {
        return { ...checkpoint, settlement_backend: "local", settlement_tx: "0xsettled" };
      },
      async verifyCheckpointSettlement() {
        return { settled: true };
      },
      async getCheckpoint() {
        return null;
      }
    };
    const store = new InMemoryRelayStore({ settlement_backend: settlement, timestamp_window_ms: Number.MAX_SAFE_INTEGER });
    const identity = buildIdentityFromSeed({ trust_id: "did:tsl:test:alice", key_id: "#key-1", seed_hex: aliceSeed, created_at: "2026-01-01T00:00:00Z" });
    store.upsertIdentity(identity);
    const first = signMessageEvent({ sender: identity.id, signing_key_id: "#key-1", seed_hex: aliceSeed, message: "first", timestamp: at });
    const accepted = await store.acceptEvent(first.envelope);
    await store.submitCheckpoint(accepted.epoch_start_ms, accepted.shard);
    const second = signMessageEvent({
      sender: identity.id,
      signing_key_id: "#key-1",
      seed_hex: aliceSeed,
      message: "second",
      timestamp: at,
      nonce: "0x7777777777777777777777777777777777777777777777777777777777777777"
    });
    await expect(store.acceptEvent(second.envelope)).rejects.toMatchObject({ code: "TSL_LOG_SEGMENT_CLOSED" } satisfies Partial<RelayValidationError>);
  });

  it("keeps MAINNET conformance blocked until production evidence is approved", () => {
    expect(() => execFileSync("npx", ["tsx", "scripts/conformance.ts", "mainnet"], { cwd: process.cwd(), stdio: "pipe" })).toThrow(
      /MAINNET production-readiness evidence must be approved/
    );
  }, 60000);
});
