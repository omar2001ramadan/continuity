import "../../../scripts/load-env.cjs";
import express from "express";
import {
  createPostgresRepositoryFromEnv,
  randomHex32,
  referenceFeatureExtractor,
  referenceScoreBps,
  scoreInputFromFeatureVector,
  labelForScore,
  signTrustAssessmentObject,
  type VerifiedAttestationSummary,
  type VerifiedEventSummary,
  type VerifiedReceiptSummary,
  type TrustAssessmentUnsignedV1
} from "../../../packages/core-ts/src/index";

export function createScoringProvider() {
  const repo = createPostgresRepositoryFromEnv();
  const app = express();
  app.use(express.json({ limit: "1mb" }));
  app.get("/health", (_req, res) => res.json({ ok: true, service: "tsl-scoring-provider" }));

  app.get("/v1/scoring-profiles/:profileId", (_req, res) => {
    res.status(404).json({ error: { code: "TSL_SCORING_PROFILE_MISSING", message: "Scoring profile storage is not configured for this provider" } });
  });

  app.get("/v1/model-cards/:modelId", (_req, res) => {
    res.status(404).json({ error: { code: "TSL_MODEL_NOT_REGISTERED", message: "Model card storage is not configured for this provider" } });
  });

  app.post("/v1/assessments/v2", (_req, res) => {
    res.status(501).json({ error: { code: "TSL_TRUST_ASSESSMENT_V2_MISSING", message: "TrustAssessmentV2 generation requires a configured scoring profile and domain policy" } });
  });

  app.post("/v1/assessments", async (req, res) => {
    try {
      const subject = String(req.body.subject);
      const issuer = String(req.body.issuer ?? process.env.TSL_SCORING_PROVIDER_ID ?? "did:tsl:provider:local");
      const featureVector = await referenceFeatureExtractor.extract({
        subject,
        identity_created_at: req.body.identity_created_at,
        active_key_created_at: req.body.active_key_created_at,
        verifiedEvents: (req.body.verified_events ?? []) as VerifiedEventSummary[],
        verifiedReceipts: (req.body.verified_receipts ?? []) as VerifiedReceiptSummary[],
        attestations: (req.body.attestations ?? []) as VerifiedAttestationSummary[],
        revocationState: req.body.revocation_state ?? { revoked: false, revocation_count: 0 },
        localContext: req.body.local_context
      });
      const overrideInput =
        req.body.crypto_validity_bps !== undefined
          ? {
              crypto_validity_bps: Number(req.body.crypto_validity_bps ?? 10000),
              identity_age_bps: Number(req.body.identity_age_bps ?? 5000),
              reciprocity_bps: Number(req.body.reciprocity_bps ?? 0),
              trusted_neighbor_ratio_bps: Number(req.body.trusted_neighbor_ratio_bps ?? 0),
              receipt_quality_bps: Number(req.body.receipt_quality_bps ?? 0),
              attestation_quality_bps: Number(req.body.attestation_quality_bps ?? 0),
              temporal_consistency_bps: Number(req.body.temporal_consistency_bps ?? 5000),
              local_relationship_bps: Number(req.body.local_relationship_bps ?? 0)
            }
          : scoreInputFromFeatureVector(featureVector);
      const score_bps = referenceScoreBps(overrideInput);
      const disclosedFeatures = req.body.features_disclosed ?? [
        "crypto_validity",
        "identity_age",
        "reciprocity",
        "receipt_quality",
        "attestation_quality",
        "temporal_consistency",
        "trusted_neighbor_ratio",
        "cluster_concentration",
        "dormant_reactivation",
        "outbound_burst",
        "sybil_risk",
        "issuer_quality"
      ];
      const explanation = req.body.explanation ?? [
        "Reference weighted score computed from verified event, receipt, attestation, revocation, and local context summaries",
        `Unique counterparties: ${featureVector.unique_counterparty_count}`,
        `Reciprocal receipts: ${featureVector.reciprocal_receipt_count}`,
        `Sybil risk bps: ${featureVector.sybil_risk_bps}`
      ];
      const now = new Date();
      const expires = new Date(now.getTime() + Number(req.body.ttl_ms ?? 30 * 24 * 60 * 60 * 1000));
      const unsigned: TrustAssessmentUnsignedV1 = {
        type: "tsl.trust_assessment.v1",
        subject,
        issuer,
        score_bps,
        label: labelForScore(score_bps) as TrustAssessmentUnsignedV1["label"],
        model_version: String(req.body.model_version ?? "reference-weighted-v1"),
        evidence_commitment: req.body.evidence_commitment ?? randomHex32(),
        features_disclosed: disclosedFeatures,
        explanation,
        issued_at: now.toISOString(),
        expires_at: expires.toISOString()
      };
      if (!process.env.TSL_SCORING_PROVIDER_SEED_HEX) {
        res.status(400).json({ error: { code: "TSL_PROVIDER_KEY_MISSING", message: "TSL_SCORING_PROVIDER_SEED_HEX is required" } });
        return;
      }
      const signed = signTrustAssessmentObject({ ...unsigned, seed_hex: process.env.TSL_SCORING_PROVIDER_SEED_HEX });
      await repo?.insertTrustAssessment(signed.assessment);
      res.json({ status: "accepted", feature_vector: featureVector, ...signed });
    } catch (error) {
      res.status(400).json({ error: { code: "TSL_ASSESSMENT_FAILED", message: error instanceof Error ? error.message : String(error) } });
    }
  });

  return app;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT ?? 8084);
  createScoringProvider().listen(port, () => process.stdout.write(`tsl scoring-provider listening on http://localhost:${port}\n`));
}
