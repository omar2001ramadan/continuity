import { describe, expect, it } from "vitest";
import vector from "../../../specs/test-vectors/deterministic-event.json";
import {
  ZERO_HASH,
  buildIdentityFromSeed,
  buildInclusionProof,
  buildReceiptCommitment,
  buildAttestation,
  buildRevocation,
  buildMerkleTree,
  buildTrustAssessment,
  buildThresholdProof,
  buildAgentDelegation,
  buildConsistencyProof,
  buildNonMembershipProof,
  canonicalize,
  checkpointHash,
  deriveEd25519PublicKey,
  InMemoryRelayStore,
  MemoryTrustResolver,
  randomHex32,
  signAttestation,
  signAgentDelegation,
  signAuditFinding,
  signGovernancePolicy,
  signMessageEvent,
  signReceipt,
  signRevocation,
  signDelegationPolicyV2,
  signAgentActionV2,
  delegationPolicyV2Hash,
  signTrustAssessment,
  signTrustAssessmentV2,
  type BatchCheckpointV1,
  type Hex32,
  type SettlementBackend,
  validateSchema,
  computeEvidenceCoverageV0,
  computeReferenceScoreV0,
  computeMetadataFingerprintCommitmentV0,
  constructGraphV0,
  computeGraphFeatureVectorV0,
  computeSybilAssessmentV0,
  computeDriftReportV0,
  buildDelegationPolicyV2,
  buildAgentActionV2,
  verifyDelegatedAgentActionV0,
  canonicalBytes,
  verifyAttestation,
  verifyInclusion,
  verifyReceipt,
  verifyRevocation,
  verifyTrustAssessment,
  verifyThresholdProof,
  verifyAgentDelegation,
  verifyConsistencyProof,
  verifyNonMembershipProof,
  sha256Hex,
  verifyTSL
} from "../src/index";

const seedHex = vector.private_key_seed_hex;
const sender = "did:tsl:test:alice";
const keyId = "#test-key-1";
const timestamp = "2026-05-25T00:01:00Z";
const nonce = "0x2222222222222222222222222222222222222222222222222222222222222222" as Hex32;
const epochStartMs = Date.parse("2026-05-25T00:00:00Z");
const epochDurationMs = 300000;
const shard = "00af";
const agentSeedHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const agent = "did:tsl:test:agent";

function signedVector() {
  return signMessageEvent({
    sender,
    signing_key_id: keyId,
    message: vector.content_message_utf8,
    seed_hex: seedHex,
    timestamp,
    nonce,
    content_salt: vector.content_salt_hex,
    disclosure_policy: "commitment_only"
  });
}

function checkpointFor(commitments: Hex32[]): BatchCheckpointV1 {
  const tree = buildMerkleTree(commitments);
  return {
    type: "tsl.batch_checkpoint.v1",
    epoch_start_ms: epochStartMs,
    epoch_duration_ms: epochDurationMs,
    shard,
    event_root: tree.root,
    receipt_root: ZERO_HASH,
    attestation_root: ZERO_HASH,
    revocation_root: ZERO_HASH,
    event_count: commitments.length,
    receipt_count: 0,
    previous_checkpoint: ZERO_HASH,
    relay_id: "did:tsl:relay:test",
    relay_signature: "0x00"
  };
}

class FakeSettlementBackend implements SettlementBackend {
  private readonly checkpoints = new Map<string, BatchCheckpointV1>();

  async submitCheckpoint(checkpoint: BatchCheckpointV1): Promise<BatchCheckpointV1> {
    const settled = {
      ...checkpoint,
      settlement_backend: "eip155:31337",
      settlement_tx: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    };
    this.checkpoints.set(`${checkpoint.epoch_start_ms}:${checkpoint.shard}`, settled);
    return settled;
  }

  async verifyCheckpointSettlement(checkpoint: BatchCheckpointV1) {
    const stored = this.checkpoints.get(`${checkpoint.epoch_start_ms}:${checkpoint.shard}`);
    if (!stored) return { settled: false, error: "TSL_SETTLEMENT_MISSING" };
    const same =
      stored.epoch_duration_ms === checkpoint.epoch_duration_ms &&
      stored.event_root === checkpoint.event_root &&
      stored.receipt_root === checkpoint.receipt_root &&
      stored.attestation_root === checkpoint.attestation_root &&
      stored.revocation_root === checkpoint.revocation_root &&
      stored.event_count === checkpoint.event_count &&
      stored.receipt_count === checkpoint.receipt_count &&
      stored.previous_checkpoint === checkpoint.previous_checkpoint &&
      stored.relay_id === checkpoint.relay_id;
    return same
      ? { settled: true, settlement_backend: stored.settlement_backend, settlement_tx: stored.settlement_tx }
      : { settled: false, error: "TSL_SETTLEMENT_MISMATCH" };
  }

  async getCheckpoint(epochStartMs: number, shardName: string): Promise<BatchCheckpointV1 | null> {
    return this.checkpoints.get(`${epochStartMs}:${shardName}`) ?? null;
  }
}

class FakeRegistryBackend extends FakeSettlementBackend {
  providerActive = true;
  modelRegistered = true;
  revokedAt = false;

  async isProviderActive(): Promise<boolean> {
    return this.providerActive;
  }

  async isModelRegistered(): Promise<boolean> {
    return this.modelRegistered;
  }

  async isKeyRevokedAt(): Promise<boolean> {
    return this.revokedAt;
  }
}

describe("canonicalization", () => {
  it("produces identical canonical bytes for reordered objects", () => {
    expect(canonicalize({ b: 2, a: 1 })).toBe('{"a":1,"b":2}');
    expect(canonicalize(JSON.parse('{"a":1,"b":2}'))).toBe(canonicalize(JSON.parse('{"b":2,"a":1}')));
  });

  it("rejects non-integer numbers in signed core objects", () => {
    expect(() => canonicalize({ score: 0.82 })).toThrow(/safe integers/);
  });
});

describe("deterministic event vector", () => {
  it("reproduces the spec vector", () => {
    const signed = signedVector();
    const proof = buildInclusionProof({
      commitments: [signed.commitment_hash],
      leaf_index: 0,
      tree_kind: "event",
      epoch_start_ms: epochStartMs,
      epoch_duration_ms: epochDurationMs,
      shard
    });

    expect(deriveEd25519PublicKey(seedHex)).toBe(vector.public_key_hex);
    expect(signed.envelope.content_commitment).toBe(vector.content_commitment_hex);
    expect(signed.canonical_unsigned_event).toBe(vector.canonical_unsigned_event);
    expect(signed.event_hash).toBe(vector.event_hash_hex);
    expect(signed.envelope.signature).toBe(vector.signature_hex);
    expect(signed.commitment_hash).toBe(vector.commitment_hash_hex);
    expect(proof.root).toBe(vector.single_leaf_merkle_root_hex);
  });
});

describe("Merkle proofs", () => {
  it("verifies inclusion proofs and rejects altered leaves", () => {
    const commitments = [
      vector.commitment_hash_hex as Hex32,
      "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as Hex32,
      "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" as Hex32
    ];
    const proof = buildInclusionProof({
      commitments,
      leaf_index: 1,
      tree_kind: "event",
      epoch_start_ms: epochStartMs,
      epoch_duration_ms: epochDurationMs,
      shard
    });

    expect(verifyInclusion(proof)).toBe(true);
    expect(verifyInclusion({ ...proof, commitment: commitments[2] })).toBe(false);
  });

  it("verifies inclusion proofs for every protocol tree kind", () => {
    const commitments = [
      "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as Hex32,
      "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" as Hex32
    ];
    for (const treeKind of ["event", "receipt", "attestation", "revocation"] as const) {
      const proof = buildInclusionProof({
        commitments,
        leaf_index: 0,
        tree_kind: treeKind,
        epoch_start_ms: epochStartMs,
        epoch_duration_ms: epochDurationMs,
        shard
      });
      expect(proof.tree_kind).toBe(treeKind);
      expect(verifyInclusion(proof)).toBe(true);
      expect(verifyInclusion({ ...proof, leaf_hash: commitments[0] })).toBe(false);
    }
  });
});

describe("production proof extensions", () => {
  it("verifies checkpoint consistency chains and rejects broken links", () => {
    const first = checkpointFor(["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as Hex32]);
    const second = {
      ...checkpointFor(["0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" as Hex32]),
      epoch_start_ms: epochStartMs + epochDurationMs,
      previous_checkpoint: checkpointHash(first)
    };
    const proof = buildConsistencyProof([first, second]);
    expect(verifyConsistencyProof(proof)).toBe(true);
    expect(verifyConsistencyProof({ ...proof, chain: [{ ...proof.chain[0] }, { ...proof.chain[1], previous_checkpoint: ZERO_HASH }] })).toBe(false);
  });

  it("verifies revocation-set non-membership proofs and rejects altered neighbors", () => {
    const proof = buildNonMembershipProof({
      subject: sender,
      value_commitment: "0x5555555555555555555555555555555555555555555555555555555555555555" as Hex32,
      set_values: [
        "0x1111111111111111111111111111111111111111111111111111111111111111" as Hex32,
        "0x9999999999999999999999999999999999999999999999999999999999999999" as Hex32
      ],
      issued_at: timestamp
    });
    expect(verifyNonMembershipProof(proof)).toBe(true);
    expect(verifyNonMembershipProof({ ...proof, lower_neighbor: proof.upper_neighbor })).toBe(false);
  });
});

describe("upgraded LaTeX conformance algorithms", () => {
  it("computes reference score v0 with integer floor rounding and insufficient-evidence gates", () => {
    const coverage = computeEvidenceCoverageV0({
      subject: sender,
      required_evidence: ["signature", "receipts"],
      present_evidence: ["signature", "receipts"],
      computed_at: timestamp
    });
    const domainPolicy = {
      type: "tsl.domain_policy.v1" as const,
      domain: "anti_phishing",
      policy_version: "1.0.0",
      requires_settlement: false,
      min_coverage_bps: 7000,
      max_assessment_age_seconds: 86400,
      false_positive_cost_class: "high",
      false_negative_cost_class: "critical",
      sparse_identity_default: "require_step_up",
      thresholds: {
        trusted_bps: 9000,
        likely_trusted_bps: 7500,
        medium_bps: 5500,
        suspicious_bps: 3500,
        high_risk_bps: 1500
      }
    };
    const assessment = computeReferenceScoreV0({
      subject: sender,
      issuer: "did:tsl:provider:continuity-labs",
      scoring_profile_id: "profile-v2",
      model_version: "2.1.0",
      gate_result: { schema_valid: true, signature_valid: true, key_active: true, not_revoked: true },
      evidence_coverage: coverage,
      normalized_features_bps: { a: 9999, b: 3333 },
      weights_bps: { a: 5000, b: 5000 },
      domain_policy: domainPolicy,
      issued_at: timestamp
    });
    expect(assessment.score_bps).toBe(Math.floor((9999 * 5000) / 10000) + Math.floor((3333 * 5000) / 10000));
    expect(assessment.label).toBe("medium_trust");

    const sparse = computeReferenceScoreV0({
      subject: sender,
      issuer: "did:tsl:provider:continuity-labs",
      scoring_profile_id: "profile-v2",
      model_version: "2.1.0",
      gate_result: { schema_valid: true, signature_valid: true, key_active: true, not_revoked: true },
      evidence_coverage: { ...coverage, coverage_bps: 1000 },
      normalized_features_bps: { a: 10000 },
      weights_bps: { a: 10000 },
      domain_policy: domainPolicy,
      issued_at: timestamp
    });
    expect(sparse.label).toBe("insufficient_evidence");
    expect(sparse.score_bps).toBeUndefined();
  });

  it("produces unlinkable metadata fingerprints across verifier domains and epochs", () => {
    const common = {
      subject: sender,
      metadata: { cadence: "daily", hour_bucket: 12 },
      master_key_hex: "0x1212121212121212121212121212121212121212121212121212121212121212",
      purpose: "pairwise_verifier" as const,
      bucket_profile: "hourly-counts-v0",
      salt_hex: "0x3434343434343434343434343434343434343434343434343434343434343434" as Hex32,
      expires_at: "2026-05-26T00:00:00Z"
    };
    const a = computeMetadataFingerprintCommitmentV0({ ...common, verifier_domain: "verifier-a.example", epoch: "2026-05-25T00" });
    const b = computeMetadataFingerprintCommitmentV0({ ...common, verifier_domain: "verifier-b.example", epoch: "2026-05-25T00" });
    const c = computeMetadataFingerprintCommitmentV0({ ...common, verifier_domain: "verifier-a.example", epoch: "2026-05-25T01" });
    expect(a.fingerprint_commitment).not.toBe(b.fingerprint_commitment);
    expect(a.fingerprint_commitment).not.toBe(c.fingerprint_commitment);
    expect(validateSchema("metadataFingerprintCommitmentV1", a).valid).toBe(true);
  });

  it("computes graph, Sybil, and drift artifacts for the deterministic small graph", () => {
    const graphProfile = {
      type: "tsl.graph_profile.v2" as const,
      profile_id: "graph-default-2026-05",
      edge_weight_profile: "default-v0",
      temporal_decay_profile: "none",
      community_detection: { algorithm: "connected_components" as const, resolution_bps: 10000, min_cluster_size: 2 },
      seed_sets: {
        trusted_seed_commitment: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as Hex32,
        adversarial_seed_commitment: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" as Hex32
      },
      negative_edge_policy: {
        requires_evidence_commitment: true,
        requires_appeal_uri: true,
        max_single_negative_weight_bps: 1500,
        decay_days: 30
      },
      privacy_policy: {
        raw_counterparty_upload_required: false,
        allows_pairwise_private_features: true
      }
    };
    const graph = constructGraphV0({
      edges: [
        { src: sender, dst: "did:tsl:test:bob", type: "signed_event", timestamp, weight_bps: 1000 },
        { src: "did:tsl:test:bob", dst: sender, type: "receipt_completed", timestamp, weight_bps: 3000 },
        { src: sender, dst: "did:tsl:test:carol", type: "signed_event", timestamp, weight_bps: 1000 },
        { src: "did:tsl:test:bob", dst: "did:tsl:test:carol", type: "receipt_completed", timestamp, weight_bps: 3000 }
      ]
    });
    const features = computeGraphFeatureVectorV0({
      subject: sender,
      graph,
      graph_profile_id: graphProfile.profile_id,
      trusted_seeds: ["did:tsl:test:bob"],
      computed_at: timestamp
    });
    expect(features.effective_counterparty_count_milli).toBeGreaterThan(0);
    expect(features.counterparty_hhi_bps).toBeGreaterThan(0);
    expect(features.reciprocity_bps).toBe(5000);
    expect(features.seed_escape_bps).toBeGreaterThan(0);

    const sybil = computeSybilAssessmentV0({ subject: sender, graph, graph_profile: graphProfile, trusted_seeds: [], computed_at: timestamp });
    expect(sybil.cluster_id_commitment).toMatch(/^0x[0-9a-f]{64}$/);
    expect(sybil.risk_score_bps).toBeGreaterThan(0);
    expect(sybil.privacy_level).toBe("cluster_commitment_only");
    expect(sybil.cluster_concentration_bps).toBeGreaterThan(0);
    expect(["low", "medium", "elevated", "high", "insufficient_evidence"]).toContain(sybil.risk_label);

    const drift = computeDriftReportV0({
      subject: sender,
      baseline_values_bps: [1000, 1200, 900],
      observation_values_bps: [8200],
      baseline_window_days: 90,
      observation_window_days: 7,
      dormant_days: 120,
      high_value_action: true,
      computed_at: timestamp
    });
    expect(drift.drift_label).toBe("dormant_reactivation");
    expect(drift.action).toBe("step_up");
  });

  it("verifies delegation policy v2 and rejects an outside-scope agent action", () => {
    const controller = "did:tsl:test:controller";
    const delegate = "did:tsl:test:agent";
    const policy = signDelegationPolicyV2(
      buildDelegationPolicyV2({
        policy_id: "0x7878787878787878787878787878787878787878787878787878787878787878" as Hex32,
        principal: controller,
        delegate,
        effect: "allow",
        actions: ["invoice.approve"],
        resources: ["invoice:*"],
        constraints: { max_value_minor_units: 50000 },
        valid_from: timestamp,
        valid_until: "2026-05-26T00:00:00Z",
        revocation_pointer: "did:tsl:test:controller#delegations",
        nonce: "0x7979797979797979797979797979797979797979797979797979797979797979" as Hex32
      }),
      seedHex
    );
    const delegationChainRoot = sha256Hex(canonicalBytes([delegationPolicyV2Hash(policy)]));
    const inside = signAgentActionV2(
      buildAgentActionV2({
        action_id: "0x8989898989898989898989898989898989898989898989898989898989898989" as Hex32,
        agent: delegate,
        principal: controller,
        action: "invoice.approve",
        resource: "invoice:123",
        tool: "invoice_api",
        parameters_commitment: "0x9090909090909090909090909090909090909090909090909090909090909090" as Hex32,
        parameter_disclosure_policy: "selective",
        delegation_chain_root: delegationChainRoot,
        nonce: "0x9191919191919191919191919191919191919191919191919191919191919191" as Hex32,
        value_minor_units: 40000,
        issued_at: "2026-05-25T00:10:00Z"
      }),
      agentSeedHex
    );
    const outside = { ...inside, action: "wire.transfer", signature: inside.signature };
    const public_keys = {
      [controller]: deriveEd25519PublicKey(seedHex),
      [delegate]: deriveEd25519PublicKey(agentSeedHex)
    };

    expect(verifyDelegatedAgentActionV0({ action: inside, delegation_chain: [policy], public_keys, at_time: timestamp }).ok).toBe(true);
    const failed = verifyDelegatedAgentActionV0({ action: signAgentActionV2({ ...inside, action: "wire.transfer" }, agentSeedHex), delegation_chain: [policy], public_keys, at_time: timestamp });
    expect(failed.ok).toBe(false);
    expect(failed.error_code).toBe("TSL_DELEGATION_SCOPE_VIOLATION");
    expect(outside.action).toBe("wire.transfer");
  });
});

describe("signed protocol objects", () => {
  it("verifies receipts, attestations, revocations, and assessments and rejects tampering", () => {
    const publicKey = deriveEd25519PublicKey(seedHex);
    const signed = signedVector();
    const unsignedReceipt = buildReceiptCommitment({
      event_commitment: signed.commitment_hash,
      receiver: sender,
      signing_key_id: keyId,
      receipt_class: "received",
      timestamp
    }).unsignedReceipt;
    const receipt = signReceipt(unsignedReceipt, seedHex);
    expect(verifyReceipt(receipt, publicKey)).toBe(true);
    expect(verifyReceipt({ ...receipt, receipt_class: "disputed" }, publicKey)).toBe(false);

    const unsignedAttestation = buildAttestation({
      issuer: sender,
      subject: sender,
      attestation_class: "trusted_counterparty",
      claim_commitment: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      visibility: "public",
      issued_at: timestamp
    }).unsignedAttestation;
    const attestation = signAttestation(unsignedAttestation, seedHex);
    expect(verifyAttestation(attestation, publicKey)).toBe(true);
    expect(verifyAttestation({ ...attestation, subject: "did:tsl:test:bob" }, publicKey)).toBe(false);

    const revocation = signRevocation(
      buildRevocation({
        trust_id: sender,
        revoked_key: keyId,
        reason_class: "compromise",
        effective_at: "2026-05-25T00:02:00Z"
      }),
      seedHex
    );
    expect(verifyRevocation(revocation, publicKey)).toBe(true);
    expect(verifyRevocation({ ...revocation, reason_class: "device_loss" }, publicKey)).toBe(false);

    const assessment = signTrustAssessment(
      buildTrustAssessment({
        type: "tsl.trust_assessment.v1",
        subject: sender,
        issuer: sender,
        score_bps: 8200,
        label: "likely_trusted",
        model_version: "reference-weighted-v1",
        evidence_commitment: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        issued_at: timestamp,
        expires_at: "2026-06-25T00:01:00Z"
      }),
      seedHex
    );
    expect(verifyTrustAssessment(assessment, publicKey)).toBe(true);
    expect(verifyTrustAssessment({ ...assessment, score_bps: 1 }, publicKey)).toBe(false);
  });

  it("verifies threshold proofs and rejects altered public inputs", () => {
    const proof = buildThresholdProof({
      claim: "identity_age_days",
      subject: sender,
      value: 800,
      threshold: 365,
      witness_salt: "0x1212121212121212121212121212121212121212121212121212121212121212" as Hex32,
      issued_at: timestamp
    });

    expect(validateSchema("zkThresholdProof", proof).valid).toBe(true);
    expect(verifyThresholdProof(proof)).toBe(true);
    expect(verifyThresholdProof({ ...proof, threshold: 900 })).toBe(false);
  });

  it("verifies agent delegations and rejects out-of-scope use", async () => {
    const controllerIdentity = buildIdentityFromSeed({
      trust_id: sender,
      key_id: keyId,
      seed_hex: seedHex,
      created_at: "2026-05-25T00:00:00Z"
    });
    const agentIdentity = buildIdentityFromSeed({
      trust_id: agent,
      key_id: "#agent-key-1",
      seed_hex: agentSeedHex,
      created_at: "2026-05-25T00:00:00Z"
    });
    const delegation = signAgentDelegation(
      buildAgentDelegation({
        controller: sender,
        controller_key_id: keyId,
        agent,
        agent_key_id: "#agent-key-1",
        scope: ["invoice.approve", "tool.search"],
        expires_at: "2026-05-26T00:00:00Z",
        issued_at: timestamp,
        nonce: randomHex32()
      }),
      seedHex,
      agentSeedHex
    );
    const resolver = new MemoryTrustResolver([controllerIdentity, agentIdentity]);

    expect(validateSchema("agentDelegation", delegation).valid).toBe(true);
    await expect(verifyAgentDelegation(delegation, resolver, "invoice.approve", timestamp)).resolves.toBe(true);
    await expect(verifyAgentDelegation(delegation, resolver, "wire.transfer", timestamp)).resolves.toBe(false);
    await expect(verifyAgentDelegation(delegation, resolver, "invoice.approve", "2026-05-27T00:00:00Z")).resolves.toBe(false);
  });
});

describe("pure verifier", () => {
  it("verifies a complete offline bundle without requiring settlement", async () => {
    const identity = buildIdentityFromSeed({
      trust_id: sender,
      key_id: keyId,
      seed_hex: seedHex,
      created_at: "2026-05-25T00:00:00Z"
    });
    const signed = signedVector();
    const checkpoint = checkpointFor([signed.commitment_hash]);
    const proof = buildInclusionProof({
      commitments: [signed.commitment_hash],
      leaf_index: 0,
      tree_kind: "event",
      epoch_start_ms: epochStartMs,
      epoch_duration_ms: epochDurationMs,
      shard,
      checkpoint_hash: checkpointHash(checkpoint)
    });

    const result = await verifyTSL(
      {
        envelope: signed.envelope,
        proof,
        checkpoint,
        message_disclosure: {
          raw_message: vector.content_message_utf8,
          content_salt: vector.content_salt_hex
        }
      },
      new MemoryTrustResolver([identity]),
      { require_inclusion: true, require_checkpoint: true, require_settlement: false }
    );

    expect(result.verified).toBe(true);
    expect(result.errors).toEqual([]);
    expect(result.checks.content_commitment_matches).toBe(true);
  });

  it("requires real settlement backend confirmation when settlement is required", async () => {
    const identity = buildIdentityFromSeed({
      trust_id: sender,
      key_id: keyId,
      seed_hex: seedHex,
      created_at: "2026-05-25T00:00:00Z"
    });
    const signed = signedVector();
    const checkpoint = checkpointFor([signed.commitment_hash]);
    const proof = buildInclusionProof({
      commitments: [signed.commitment_hash],
      leaf_index: 0,
      tree_kind: "event",
      epoch_start_ms: epochStartMs,
      epoch_duration_ms: epochDurationMs,
      shard,
      checkpoint_hash: checkpointHash(checkpoint)
    });
    const settlement = new FakeSettlementBackend();
    const resolver = new MemoryTrustResolver([identity]);

    const before = await verifyTSL(
      { envelope: signed.envelope, proof, checkpoint },
      resolver,
      { require_inclusion: true, require_checkpoint: true, require_settlement: true },
      settlement
    );
    expect(before.verified).toBe(false);
    expect(before.errors).toContain("TSL_SETTLEMENT_MISSING");

    const settledCheckpoint = await settlement.submitCheckpoint(checkpoint);
    const after = await verifyTSL(
      { envelope: signed.envelope, proof, checkpoint: settledCheckpoint },
      resolver,
      { require_inclusion: true, require_checkpoint: true, require_settlement: true },
      settlement
    );
    expect(after.verified).toBe(true);
    expect(after.checks.checkpoint_settled).toBe(true);
  });

  it("rejects altered checkpoints even when a settlement tx field is present", async () => {
    const identity = buildIdentityFromSeed({
      trust_id: sender,
      key_id: keyId,
      seed_hex: seedHex,
      created_at: "2026-05-25T00:00:00Z"
    });
    const signed = signedVector();
    const checkpoint = checkpointFor([signed.commitment_hash]);
    const proof = buildInclusionProof({
      commitments: [signed.commitment_hash],
      leaf_index: 0,
      tree_kind: "event",
      epoch_start_ms: epochStartMs,
      epoch_duration_ms: epochDurationMs,
      shard,
      checkpoint_hash: checkpointHash(checkpoint)
    });
    const settlement = new FakeSettlementBackend();
    await settlement.submitCheckpoint(checkpoint);

    const altered = {
      ...checkpoint,
      event_root: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as Hex32,
      settlement_backend: "eip155:31337",
      settlement_tx: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    };
    const result = await verifyTSL(
      { envelope: signed.envelope, proof, checkpoint: altered },
      new MemoryTrustResolver([identity]),
      { require_inclusion: true, require_checkpoint: true, require_settlement: true },
      settlement
    );

    expect(result.verified).toBe(false);
    expect(result.checks.checkpoint_matches_proof).toBe(false);
    expect(result.checks.checkpoint_settled).toBe(false);
  });

  it("rejects altered proof roots despite a settled checkpoint", async () => {
    const identity = buildIdentityFromSeed({
      trust_id: sender,
      key_id: keyId,
      seed_hex: seedHex,
      created_at: "2026-05-25T00:00:00Z"
    });
    const signed = signedVector();
    const checkpoint = checkpointFor([signed.commitment_hash]);
    const proof = buildInclusionProof({
      commitments: [signed.commitment_hash],
      leaf_index: 0,
      tree_kind: "event",
      epoch_start_ms: epochStartMs,
      epoch_duration_ms: epochDurationMs,
      shard,
      checkpoint_hash: checkpointHash(checkpoint)
    });
    const settlement = new FakeSettlementBackend();
    const settledCheckpoint = await settlement.submitCheckpoint(checkpoint);
    const alteredProof = {
      ...proof,
      root: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as Hex32
    };

    const result = await verifyTSL(
      { envelope: signed.envelope, proof: alteredProof, checkpoint: settledCheckpoint },
      new MemoryTrustResolver([identity]),
      { require_inclusion: true, require_checkpoint: true, require_settlement: true },
      settlement
    );

    expect(result.verified).toBe(false);
    expect(result.checks.included_in_log).toBe(false);
    expect(result.checks.checkpoint_matches_proof).toBe(false);
    expect(result.checks.checkpoint_settled).toBe(true);
  });

  it("separates cryptographic validity from disclosed content mismatch", async () => {
    const identity = buildIdentityFromSeed({
      trust_id: sender,
      key_id: keyId,
      seed_hex: seedHex,
      created_at: "2026-05-25T00:00:00Z"
    });
    const signed = signedVector();

    const result = await verifyTSL(
      {
        envelope: signed.envelope,
        message_disclosure: {
          raw_message: "tampered",
          content_salt: vector.content_salt_hex
        }
      },
      new MemoryTrustResolver([identity])
    );

    expect(result.checks.signature_valid).toBe(true);
    expect(result.checks.content_commitment_matches).toBe(false);
    expect(result.verified).toBe(false);
    expect(result.errors).toContain("TSL_CONTENT_COMMITMENT_MISMATCH");
  });

  it("enforces signed revocation effective-time precedence", async () => {
    const identity = buildIdentityFromSeed({
      trust_id: sender,
      key_id: keyId,
      seed_hex: seedHex,
      created_at: "2026-05-25T00:00:00Z"
    });
    const revocation = signRevocation(
      buildRevocation({
        trust_id: sender,
        revoked_key: keyId,
        reason_class: "compromise",
        effective_at: "2026-05-25T00:02:00Z"
      }),
      seedHex
    );
    const before = signedVector();
    const after = signMessageEvent({
      sender,
      signing_key_id: keyId,
      seed_hex: seedHex,
      message: vector.content_message_utf8,
      timestamp: "2026-05-25T00:03:00Z",
      nonce: "0x3333333333333333333333333333333333333333333333333333333333333333" as Hex32,
      content_salt: vector.content_salt_hex,
      disclosure_policy: "commitment_only"
    });
    const resolver = new MemoryTrustResolver([identity]);

    const beforeResult = await verifyTSL({ envelope: before.envelope, revocations: [revocation] }, resolver);
    expect(beforeResult.verified).toBe(true);
    expect(beforeResult.checks.revocation_state_valid).toBe(true);

    const afterResult = await verifyTSL({ envelope: after.envelope, revocations: [revocation] }, resolver);
    expect(afterResult.verified).toBe(false);
    expect(afterResult.errors).toContain("TSL_KEY_REVOKED");
    expect(afterResult.checks.not_revoked).toBe(false);
  });

  it("enforces chain revocation policy when requested", async () => {
    const identity = buildIdentityFromSeed({
      trust_id: sender,
      key_id: keyId,
      seed_hex: seedHex,
      created_at: "2026-05-25T00:00:00Z"
    });
    const signed = signedVector();
    const backend = new FakeRegistryBackend();
    backend.revokedAt = true;

    const result = await verifyTSL(
      { envelope: signed.envelope },
      new MemoryTrustResolver([identity]),
      { require_chain_revocation: true },
      backend
    );

    expect(result.verified).toBe(false);
    expect(result.checks.chain_revocation_checked).toBe(true);
    expect(result.errors).toContain("TSL_KEY_REVOKED");
  });

  it("validates assessment provider/model policy and assessment evidence", async () => {
    const identity = buildIdentityFromSeed({
      trust_id: sender,
      key_id: keyId,
      seed_hex: seedHex,
      created_at: "2026-05-25T00:00:00Z"
    });
    const signed = signedVector();
    const assessment = signTrustAssessment(
      buildTrustAssessment({
        type: "tsl.trust_assessment.v1",
        subject: sender,
        issuer: sender,
        score_bps: 8200,
        label: "likely_trusted",
        model_version: "reference-weighted-v1",
        evidence_commitment: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        features_disclosed: ["crypto_validity", "reciprocity"],
        explanation: ["Reference assessment signed by test provider"],
        issued_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 60_000).toISOString()
      }),
      seedHex
    );
    const backend = new FakeRegistryBackend();

    const passing = await verifyTSL(
      { envelope: signed.envelope, assessment },
      new MemoryTrustResolver([identity]),
      { require_provider_registry: true, accepted_scoring_providers: [sender], max_assessment_age_ms: 60_000 },
      backend
    );
    expect(passing.verified).toBe(true);
    expect(passing.checks.provider_active).toBe(true);
    expect(passing.checks.model_registered).toBe(true);
    expect(passing.risk_label).toBe("likely_trusted");

    backend.modelRegistered = false;
    const failing = await verifyTSL(
      { envelope: signed.envelope, assessment },
      new MemoryTrustResolver([identity]),
      { require_provider_registry: true, accepted_scoring_providers: [sender], max_assessment_age_ms: 60_000 },
      backend
    );
    expect(failing.verified).toBe(false);
    expect(failing.errors).toContain("TSL_MODEL_NOT_REGISTERED");
  });

  it("enforces optional threshold proof requirements", async () => {
    const identity = buildIdentityFromSeed({
      trust_id: sender,
      key_id: keyId,
      seed_hex: seedHex,
      created_at: "2026-05-25T00:00:00Z"
    });
    const signed = signedVector();
    const proof = buildThresholdProof({
      claim: "identity_age_days",
      subject: sender,
      value: 800,
      threshold: 365,
      witness_salt: "0x3434343434343434343434343434343434343434343434343434343434343434" as Hex32,
      issued_at: timestamp
    });

    const passing = await verifyTSL(
      { envelope: signed.envelope, zk_proofs: [proof] },
      new MemoryTrustResolver([identity]),
      { require_zk_claims: ["identity_age_days"] }
    );
    expect(passing.verified).toBe(true);
    expect(passing.checks.zk_valid).toBe(true);

    const failing = await verifyTSL(
      { envelope: signed.envelope, zk_proofs: [proof] },
      new MemoryTrustResolver([identity]),
      { require_zk_claims: ["reciprocal_receipt_count"] }
    );
    expect(failing.verified).toBe(false);
    expect(failing.errors).toContain("TSL_ZK_CLAIM_MISSING");
  });

  it("enforces agent scope and signed audit consistency when required", async () => {
    const controllerIdentity = buildIdentityFromSeed({
      trust_id: sender,
      key_id: keyId,
      seed_hex: seedHex,
      created_at: "2026-05-25T00:00:00Z"
    });
    const agentIdentity = buildIdentityFromSeed({
      trust_id: agent,
      key_id: "#agent-key-1",
      seed_hex: agentSeedHex,
      created_at: "2026-05-25T00:00:00Z"
    });
    const agentEvent = signMessageEvent({
      sender: agent,
      signing_key_id: "#agent-key-1",
      seed_hex: agentSeedHex,
      message: "approve-invoice",
      timestamp,
      nonce: "0x4444444444444444444444444444444444444444444444444444444444444444" as Hex32,
      content_salt: vector.content_salt_hex,
      disclosure_policy: "commitment_only",
      event_class: "agent_call"
    });
    const delegation = signAgentDelegation(
      buildAgentDelegation({
        controller: sender,
        controller_key_id: keyId,
        agent,
        agent_key_id: "#agent-key-1",
        scope: ["invoice.approve"],
        expires_at: "2026-05-26T00:00:00Z",
        issued_at: timestamp,
        nonce: "0x5555555555555555555555555555555555555555555555555555555555555555" as Hex32
      }),
      seedHex,
      agentSeedHex
    );
    const auditFinding = signAuditFinding(
      {
        type: "tsl.audit.finding.v1",
        auditor: sender,
        finding_class: "checkpoint_valid",
        severity: "info",
        evidence_commitment: "0x5656565656565656565656565656565656565656565656565656565656565656" as Hex32,
        issued_at: timestamp
      },
      seedHex
    );

    const passing = await verifyTSL(
      { envelope: agentEvent.envelope, delegations: [delegation], audit_findings: [auditFinding] },
      new MemoryTrustResolver([controllerIdentity, agentIdentity]),
      { require_agent_scope: "invoice.approve", require_audit_consistency: true, accepted_auditors: [sender] }
    );
    expect(passing.verified).toBe(true);
    expect(passing.checks.agent_scope_valid).toBe(true);
    expect(passing.checks.audit_consistency_valid).toBe(true);

    const failing = await verifyTSL(
      { envelope: agentEvent.envelope, delegations: [delegation], audit_findings: [auditFinding] },
      new MemoryTrustResolver([controllerIdentity, agentIdentity]),
      { require_agent_scope: "wire.transfer", require_audit_consistency: true, accepted_auditors: [sender] }
    );
    expect(failing.verified).toBe(false);
    expect(failing.errors).toContain("TSL_AGENT_SCOPE_INVALID");
  });
});

describe("schema and relay compliance", () => {
  it("rejects unknown fields in core objects", () => {
    const signed = signedVector();
    const validation = validateSchema("event", { ...signed.envelope, platform: "gmail" });
    expect(validation.valid).toBe(false);
    expect(validation.errors.join("\n")).toMatch(/additional properties/);
  });

  it("rejects duplicate sender/key/nonce submissions", async () => {
    const identity = buildIdentityFromSeed({
      trust_id: sender,
      key_id: keyId,
      seed_hex: seedHex,
      created_at: "2026-05-25T00:00:00Z"
    });
    const store = new InMemoryRelayStore({ timestamp_window_ms: Number.MAX_SAFE_INTEGER });
    store.upsertIdentity(identity);
    const signed = signedVector();

    await expect(store.acceptEvent(signed.envelope)).resolves.toMatchObject({
      commitment_hash: vector.commitment_hash_hex
    });
    await expect(store.acceptEvent(signed.envelope)).rejects.toMatchObject({
      code: "TSL_NONCE_REPLAY"
    });
  });
});
