import fs from "node:fs";
import path from "node:path";
import {
  buildIdentityFromSeed,
  buildMerkleTree,
  checkpointHash,
  computeEvidenceCoverageV0,
  computeReferenceScoreV0,
  createPostgresRepositoryFromEnv,
  hashDomain,
  sha256Hex,
  shardForTrustID,
  signCheckpointWithSeed,
  signMessageEvent,
  signTrustAssessmentV2,
  verifyTSL,
  ZERO_HASH,
  type BatchCheckpointV1,
  type DomainPolicyV1,
  type Hex32
} from "../packages/core-ts/src/index";

const evidencePath = path.join("evidence", "integration", "postgres-readiness-smoke.json");
const seedHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const relaySeedHex = "2222222222222222222222222222222222222222222222222222222222222222";
const providerSeedHex = process.env.TSL_SCORING_PROVIDER_SEED_HEX ?? "1111111111111111111111111111111111111111111111111111111111111111";

function requireDatabase(): void {
  if (!process.env.TSL_TEST_DATABASE_URL) {
    throw new Error("TSL_TEST_DATABASE_URL is required for the Postgres mainnet-readiness smoke");
  }
  process.env.TSL_DATABASE_URL = process.env.TSL_TEST_DATABASE_URL;
}

function writeEvidence(payload: unknown): void {
  fs.mkdirSync(path.dirname(evidencePath), { recursive: true });
  fs.writeFileSync(evidencePath, `${JSON.stringify(payload, null, 2)}\n`);
}

async function main(): Promise<void> {
  requireDatabase();
  const repo = createPostgresRepositoryFromEnv();
  if (!repo) throw new Error("Postgres repository was not created");
  const runId = `mainnet-smoke-${Date.now()}`;
  const now = new Date().toISOString();
  const trustId = `did:tsl:mainnet-smoke:${runId}`;
  const provider = "did:tsl:provider:mainnet-smoke";
  try {
    await repo.migrate();
    const identity = buildIdentityFromSeed({ trust_id: trustId, key_id: "#key-1", seed_hex: seedHex, created_at: now });
    const relayIdentity = buildIdentityFromSeed({
      trust_id: "did:tsl:relay:mainnet-smoke",
      key_id: "#relay-checkpoint",
      seed_hex: relaySeedHex,
      created_at: "2026-01-01T00:00:00Z"
    });
    await repo.upsertIdentity(identity);
    await repo.upsertIdentity(relayIdentity);

    const signed = signMessageEvent({
      sender: trustId,
      signing_key_id: "#key-1",
      seed_hex: seedHex,
      message: "mainnet-readiness-postgres-smoke",
      timestamp: now,
      nonce: sha256Hex(new TextEncoder().encode(`${runId}:nonce`))
    });
    const epochDurationMs = 300000;
    const epochStartMs = Math.floor(Date.parse(now) / epochDurationMs) * epochDurationMs;
    const shard = shardForTrustID(trustId);
    const commitment = await repo.insertEvent(signed.envelope, "did:tsl:relay:mainnet-smoke", epochStartMs, epochDurationMs);
    const eventRoot = buildMerkleTree([commitment]).root;
    const checkpoint: BatchCheckpointV1 = signCheckpointWithSeed({
      type: "tsl.batch_checkpoint.v1",
      epoch_start_ms: epochStartMs,
      epoch_duration_ms: epochDurationMs,
      shard,
      event_root: eventRoot,
      receipt_root: ZERO_HASH,
      attestation_root: ZERO_HASH,
      revocation_root: ZERO_HASH,
      event_count: 1,
      receipt_count: 0,
      previous_checkpoint: ZERO_HASH,
      relay_id: "did:tsl:relay:mainnet-smoke",
      relay_signature: "0x00"
    }, relaySeedHex);
    const checkpoint_hash = await repo.insertCheckpoint(checkpoint, "pending");
    const bundle = await repo.buildProofBundleForEvent(commitment);
    if (!bundle) throw new Error("Postgres proof bundle was not built");

    const verification = await verifyTSL(
      {
        envelope: signed.envelope,
        proof: bundle.proof as never,
        checkpoint: bundle.checkpoint as never
      },
      { resolveTrustID: async (id: string) => id === relayIdentity.id ? relayIdentity : id === identity.id ? identity : null },
      { require_inclusion: true, require_checkpoint: true }
    );
    if (!verification.verified) throw new Error(`Offline verification failed: ${verification.errors.join(",")}`);

    const coverage = computeEvidenceCoverageV0({
      subject: trustId,
      valid_signed_event_count: 1,
      valid_receipt_count: 0,
      unique_counterparty_count: 0,
      computed_at: now
    });
    await repo.upsertEvidenceCoverageV1(coverage);

    const zeroCommitment = hashDomain("tsl.mainnet.smoke.zero", new Uint8Array());
    const scoringProfile = {
      type: "tsl.scoring_profile.v2" as const,
      profile_id: `${provider}/profile/${runId}`,
      provider,
      domain: "local_verifier",
      model_family: "transparent_weighted_logistic",
      model_version: "1.0.0",
      feature_registry_commitment: zeroCommitment,
      normalization_profile_commitment: zeroCommitment,
      weight_profile_commitment: zeroCommitment,
      calibration_profile_commitment: zeroCommitment,
      threshold_policy_commitment: zeroCommitment,
      privacy_policy_commitment: zeroCommitment,
      evaluation_report_commitment: zeroCommitment,
      issued_at: now,
      valid_after: now,
      expires_at: new Date(Date.parse(now) + 86400000).toISOString(),
      signature: "0x00"
    };
    await repo.upsertScoringProfileV2(scoringProfile);
    await repo.upsertModelCardV2({
      type: "tsl.model_card.v2",
      model_id: `${provider}/model/${runId}`,
      provider,
      model_version: "1.0.0",
      supported_domains: ["local_verifier"],
      feature_registry_commitment: zeroCommitment,
      evaluation_report_commitment: zeroCommitment,
      privacy_report_commitment: zeroCommitment,
      metrics: { auroc_bps: 9000, auprc_bps: 8500, ece_bps: 300, p95_latency_ms: 100 },
      limitations: ["mainnet-readiness smoke only"],
      issued_at: now,
      signature: "0x00"
    });
    await repo.upsertEvaluationReportV1({
      type: "tsl.evaluation_report.v1",
      report_id: `${provider}/eval/${runId}`,
      model_id: `${provider}/model/${runId}`,
      domain: "local_verifier",
      dataset_commitments: [zeroCommitment],
      metrics: { auroc_bps: 9000, auprc_bps: 8500, ece_bps: 300, coverage_bps: 5000, p95_latency_ms: 100 },
      promotion_gate_result: "research_only",
      red_team_result: "not_run",
      issued_at: now,
      signature: "0x00"
    });

    const domainPolicy: DomainPolicyV1 = {
      type: "tsl.domain_policy.v1",
      domain: "local_verifier",
      policy_version: "mainnet-smoke",
      requires_settlement: false,
      min_coverage_bps: 0,
      max_assessment_age_seconds: 3600,
      false_positive_cost_class: "medium",
      false_negative_cost_class: "medium",
      sparse_identity_default: "unknown_caution",
      thresholds: { trusted_bps: 9000, likely_trusted_bps: 7500, medium_bps: 5500, suspicious_bps: 3500, high_risk_bps: 1500 }
    };
    const unsignedAssessment = computeReferenceScoreV0({
      subject: trustId,
      issuer: provider,
      scoring_profile_id: scoringProfile.profile_id,
      model_version: "1.0.0",
      gate_result: {
        schema_valid: verification.checks.schema_valid,
        canonicalization_valid: verification.checks.schema_valid,
        signature_valid: verification.checks.signature_valid,
        key_active: verification.checks.key_active,
        not_revoked: verification.checks.not_revoked,
        included_in_log: verification.checks.included_in_log,
        checkpoint_valid: verification.checks.checkpoint_valid
      },
      evidence_coverage: coverage,
      normalized_features_bps: { crypto_validity: 10000, evidence_coverage: coverage.coverage_bps },
      weights_bps: { crypto_validity: 6000, evidence_coverage: 4000 },
      domain_policy: domainPolicy,
      issued_at: now
    });
    const assessment = signTrustAssessmentV2(unsignedAssessment, providerSeedHex);
    await repo.insertTrustAssessmentV2(assessment);

    writeEvidence({
      type: "tsl.integration_evidence.postgres_readiness_smoke.v1",
      status: "passed",
      run_id: runId,
      generated_at: new Date().toISOString(),
      database: "TSL_TEST_DATABASE_URL",
      trust_id: trustId,
      commitment,
      checkpoint_hash,
      bundle_id: bundle.bundle_id,
      verification: { verified: verification.verified, checks: verification.checks },
      persisted: {
        scoring_profile_id: scoringProfile.profile_id,
        coverage_bps: coverage.coverage_bps,
        assessment_id: assessment.assessment_id
      }
    });
    process.stdout.write(`${JSON.stringify({ ok: true, evidence: evidencePath, run_id: runId }, null, 2)}\n`);
  } finally {
    await repo.close();
  }
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
  process.exitCode = 1;
});
