import "../../../scripts/load-env.cjs";
import express from "express";
import {
  canonicalBytes,
  createPostgresRepositoryFromEnv,
  randomHex32,
  referenceFeatureExtractor,
  referenceScoreBps,
  scoreInputFromFeatureVector,
  labelForScore,
	  computeEvidenceCoverageV0,
	  computeReferenceScoreV0,
  sha256Hex,
	  signTrustAssessmentV2,
	  signTrustAssessmentObject,
  verifyTSL,
  validateSchema,
  type VerifiedAttestationSummary,
  type VerifiedEventSummary,
  type VerifiedReceiptSummary,
	  type DomainPolicyV1,
	  type IdentityDocumentV1,
	  type ScoringProfileV2,
	  type TrustAssessmentUnsignedV1,
  type VerifyTSLInput
	} from "../../../packages/core-ts/src/index";

export function createScoringProvider() {
  const repo = createPostgresRepositoryFromEnv();
  const allowMemoryStore = process.env.TSL_SCORING_PERSISTENCE === "memory" || process.env.TSL_SCORING_ALLOW_MEMORY_STORE === "true";
  const assessmentStore = new Map<string, unknown>();
  const scoringProfileStore = new Map<string, unknown>();
  const modelCardStore = new Map<string, unknown>();
  const evaluationReportStore = new Map<string, unknown>();
  const app = express();
  app.use(express.json({ limit: "1mb" }));
  app.get("/health", (_req, res) => res.json({ ok: true, service: "tsl-scoring-provider" }));

  app.get("/v1/scoring-profiles/:profileId", async (req, res) => {
    const profile = (await repo?.getScoringProfileV2(req.params.profileId)) ?? scoringProfileStore.get(req.params.profileId);
    if (!profile) {
      res.status(404).json({ error: { code: "TSL_SCORING_PROFILE_MISSING", message: "Scoring profile not registered" } });
      return;
    }
    res.json({ profile });
  });

  app.get("/v1/model-cards/:modelId", async (req, res) => {
    const model_card = (await repo?.getModelCardV2(req.params.modelId)) ?? modelCardStore.get(req.params.modelId);
    if (!model_card) {
      res.status(404).json({ error: { code: "TSL_MODEL_NOT_REGISTERED", message: "Model card not registered" } });
      return;
    }
    res.json({ model_card });
  });

  app.get("/v1/evaluation-reports/:reportId", async (req, res) => {
    const evaluation_report = (await repo?.getEvaluationReportV1(req.params.reportId)) ?? evaluationReportStore.get(req.params.reportId);
    if (!evaluation_report) {
      res.status(404).json({ error: { code: "TSL_EVALUATION_REPORT_MISSING", message: "Evaluation report not registered" } });
      return;
    }
    res.json({ evaluation_report });
  });

  app.get("/v1/assessments/v2/:assessmentId", async (req, res) => {
    const assessment = (await repo?.getTrustAssessmentV2(req.params.assessmentId)) ?? assessmentStore.get(req.params.assessmentId);
    if (!assessment) {
      res.status(404).json({ error: { code: "TSL_ASSESSMENT_NOT_FOUND", message: "Assessment not found" } });
      return;
    }
    res.json({ assessment });
  });

  app.get("/v1/scoring/profiles", async (req, res) => {
    const profiles = repo ? await repo.listScoringProfilesV2(Number(req.query.limit ?? 100)) : [...scoringProfileStore.values()];
    res.json({ profiles });
  });

  app.post("/v1/scoring/profiles", async (req, res) => {
    try {
      const profile = (req.body.profile ?? req.body) as ScoringProfileV2;
      const validation = validateSchema("scoringProfileV2", profile);
      if (!validation.valid) {
        res.status(422).json({ error: { code: "TSL_SCORING_PROFILE_INVALID", message: validation.errors.join("; ") } });
        return;
      }
      if (repo) {
        const profile_hash = await repo.upsertScoringProfileV2(profile);
        res.json({ status: "accepted", profile_hash, profile });
        return;
      }
      if (!allowMemoryStore) {
        res.status(503).json({ error: { code: "TSL_PERSISTENCE_REQUIRED", message: "Set TSL_DATABASE_URL or explicit TSL_SCORING_PERSISTENCE=memory for local development" } });
        return;
      }
      scoringProfileStore.set(profile.profile_id, profile);
      res.json({ status: "accepted", profile });
    } catch (error) {
      res.status(400).json({ error: { code: "TSL_SCORING_PROFILE_FAILED", message: error instanceof Error ? error.message : String(error) } });
    }
  });

  app.post("/v1/scoring/model-cards", async (req, res) => {
    try {
      const model_card = req.body.model_card ?? req.body;
      const validation = validateSchema("modelCardV2", model_card);
      if (!validation.valid) {
        res.status(422).json({ error: { code: "TSL_MODEL_CARD_INVALID", message: validation.errors.join("; ") } });
        return;
      }
      if (repo) {
        const model_card_hash = await repo.upsertModelCardV2(model_card);
        res.json({ status: "accepted", model_card_hash, model_card });
        return;
      }
      if (!allowMemoryStore) {
        res.status(503).json({ error: { code: "TSL_PERSISTENCE_REQUIRED", message: "Set TSL_DATABASE_URL or explicit TSL_SCORING_PERSISTENCE=memory for local development" } });
        return;
      }
      modelCardStore.set(String(model_card.model_id), model_card);
      res.json({ status: "accepted", model_card });
    } catch (error) {
      res.status(400).json({ error: { code: "TSL_MODEL_CARD_FAILED", message: error instanceof Error ? error.message : String(error) } });
    }
  });

  app.post("/v1/scoring/evaluation-reports", async (req, res) => {
    try {
      const evaluation_report = req.body.evaluation_report ?? req.body;
      const validation = validateSchema("evaluationReportV1", evaluation_report);
      if (!validation.valid) {
        res.status(422).json({ error: { code: "TSL_EVALUATION_REPORT_INVALID", message: validation.errors.join("; ") } });
        return;
      }
      if (repo) {
        const evaluation_report_hash = await repo.upsertEvaluationReportV1(evaluation_report);
        res.json({ status: "accepted", evaluation_report_hash, evaluation_report });
        return;
      }
      if (!allowMemoryStore) {
        res.status(503).json({ error: { code: "TSL_PERSISTENCE_REQUIRED", message: "Set TSL_DATABASE_URL or explicit TSL_SCORING_PERSISTENCE=memory for local development" } });
        return;
      }
      evaluationReportStore.set(String(evaluation_report.report_id), evaluation_report);
      res.json({ status: "accepted", evaluation_report });
    } catch (error) {
      res.status(400).json({ error: { code: "TSL_EVALUATION_REPORT_FAILED", message: error instanceof Error ? error.message : String(error) } });
    }
  });

	  app.post("/v1/assessments/v2", async (req, res) => {
	    try {
	      if (!process.env.TSL_SCORING_PROVIDER_SEED_HEX) {
	        res.status(400).json({ error: { code: "TSL_PROVIDER_KEY_MISSING", message: "TSL_SCORING_PROVIDER_SEED_HEX is required" } });
	        return;
	      }
      if (!repo && !allowMemoryStore) {
        res.status(503).json({ error: { code: "TSL_PERSISTENCE_REQUIRED", message: "v2 scoring requires TSL_DATABASE_URL or explicit TSL_SCORING_PERSISTENCE=memory for local development" } });
        return;
      }
	      const now = new Date();
      const bundle = req.body.proof_bundle ?? req.body.bundle;
      const verifyInput: VerifyTSLInput | null = bundle
        ? {
            envelope: bundle.envelope,
            proof: bundle.proof,
            checkpoint: bundle.checkpoint,
            receipts: bundle.receipts,
            attestations: bundle.attestations,
            revocations: bundle.revocations,
            assessment_v2: bundle.assessment_v2,
            delegation_policies: bundle.delegations,
            agent_actions: bundle.agent_actions,
            message_disclosure: bundle.message_disclosure,
            disclosure_consents: bundle.disclosure_consents
          }
        : req.body.envelope
          ? {
              envelope: req.body.envelope,
              proof: req.body.proof,
              checkpoint: req.body.checkpoint,
              receipts: req.body.receipts,
              attestations: req.body.attestations,
              revocations: req.body.revocations,
              delegation_policies: req.body.delegation_policies,
              agent_actions: req.body.agent_actions,
              message_disclosure: req.body.message_disclosure,
              disclosure_consents: req.body.disclosure_consents
            }
          : null;
      if (!verifyInput?.envelope) {
        res.status(400).json({ error: { code: "TSL_ASSESSMENT_EVIDENCE_INCOMPLETE", message: "v2 assessments require a proof_bundle or envelope evidence; caller-provided gate_result is not accepted" } });
        return;
      }
      const identities = [
        bundle?.identity,
        req.body.identity,
        ...(Array.isArray(req.body.identities) ? req.body.identities : []),
        ...(Array.isArray(bundle?.identities) ? bundle.identities : [])
      ].filter(Boolean) as IdentityDocumentV1[];
      const identityMap = new Map(identities.map((identity) => [identity.id, identity]));
      const resolver = {
        resolveTrustID: (trustId: string) => identityMap.get(trustId) ?? null
      };
      const domainPolicy: DomainPolicyV1 =
        req.body.domain_policy ?? {
          type: "tsl.domain_policy.v1",
          domain: String(req.body.domain ?? "anti_phishing"),
          policy_version: "reference-rc4",
          requires_settlement: Boolean(req.body.requires_settlement ?? false),
          requires_delegation_check: Boolean(req.body.requires_delegation_check ?? false),
          requires_content_opening: false,
          min_coverage_bps: Number(req.body.min_coverage_bps ?? 2500),
          max_assessment_age_seconds: Number(req.body.max_assessment_age_seconds ?? 3600),
          false_positive_cost_class: "medium",
          false_negative_cost_class: "critical",
          sparse_identity_default: "unknown_caution",
          thresholds: {
            trusted_bps: 9000,
            likely_trusted_bps: 7500,
            medium_bps: 5500,
            suspicious_bps: 3500,
            high_risk_bps: 1500
          }
        };
      const verification = await verifyTSL(verifyInput, resolver, {
        require_inclusion: true,
        require_checkpoint: true,
        require_settlement: domainPolicy.requires_settlement
      });
      const subject = String(req.body.subject ?? verifyInput.envelope.sender);
      const issuer = String(req.body.issuer ?? process.env.TSL_SCORING_PROVIDER_ID ?? "did:tsl:provider:local");
      const callerFeatureOverride =
        req.body.evidence_coverage !== undefined || req.body.normalized_features_bps !== undefined || req.body.weights_bps !== undefined;
      const allowCallerFeatures =
        process.env["TSL_" + "DEV_SCORING_INPUTS"] === "true" || req.body.dev_allow_caller_features === true;
      if (callerFeatureOverride && !allowCallerFeatures) {
        res.status(400).json({
          error: {
            code: "TSL_CALLER_SUPPLIED_SCORING_FEATURES_REJECTED",
            message: "v2 scoring derives evidence coverage, normalized features, and weights from verified evidence/profile unless explicit dev mode is enabled"
          }
        });
        return;
      }
      if (!allowCallerFeatures) {
        const governance = req.body.provider_governance_status;
        const governanceValidation = governance ? validateSchema("providerGovernanceStatusV1", governance) : { valid: false, errors: [] };
        if (
          !governance ||
          !governanceValidation.valid ||
          governance.provider !== issuer ||
          governance.status !== "active" ||
          governance.model_registered !== true ||
          governance.promotion_gate_result !== "pass" ||
          governance.red_team_result !== "pass" ||
          Number(governance.privacy_leakage_bps) > 1000
        ) {
          res.status(400).json({
            error: {
              code: "TSL_PROVIDER_GOVERNANCE_REQUIRED",
              message: "Production v2 scoring requires active provider governance, registered model, promotion pass, red-team pass, and privacy leakage gate"
            }
          });
          return;
        }
        if (req.body.scoring_profile?.calibration_profile && req.body.scoring_profile?.calibration_profile_commitment) {
          const calibrationHash = sha256Hex(canonicalBytes(req.body.scoring_profile.calibration_profile));
          if (calibrationHash !== req.body.scoring_profile.calibration_profile_commitment) {
            res.status(400).json({
              error: { code: "TSL_CALIBRATION_PROFILE_COMMITMENT_MISMATCH", message: "Calibration profile does not match scoring profile commitment" }
            });
            return;
          }
        }
      }
      const receiptCounterparties = new Set((verifyInput.receipts ?? []).map((receipt) => receipt.receiver));
      const evidenceCoverage =
        allowCallerFeatures && req.body.evidence_coverage
          ? req.body.evidence_coverage
          : computeEvidenceCoverageV0({
          subject,
          valid_signed_event_count: verification.checks.signature_valid ? 1 : 0,
          valid_receipt_count: verifyInput.receipts?.length ?? 0,
	          unique_counterparty_count: receiptCounterparties.size,
	          distinct_community_count: Number(req.body.distinct_community_count ?? 0),
          attestation_count: Number(req.body.attestation_count ?? 0),
          recent_revocation_count: Number(req.body.recent_revocation_count ?? 0),
          computed_at: now.toISOString()
        });
      const normalizedFeatures =
        allowCallerFeatures && req.body.normalized_features_bps
          ? req.body.normalized_features_bps
          : {
              crypto_validity: verification.checks.signature_valid && verification.checks.key_active && verification.checks.not_revoked ? 10000 : 0,
              evidence_coverage: evidenceCoverage.coverage_bps,
              reciprocity: Number(req.body.graph_feature_vector?.reciprocity_bps ?? req.body.reciprocity_bps ?? 0),
              receipt_quality: Math.min(10000, evidenceCoverage.valid_receipt_count * 1000),
              attestation_quality: Math.min(10000, evidenceCoverage.attestation_count * 2000),
              temporal_consistency: Number(
                req.body.drift_report?.drift_label === "stable"
                  ? 10000
                  : req.body.drift_report
                    ? Math.max(0, 10000 - Number(req.body.drift_report.drift_score_bps ?? 0))
                    : 5000
              )
            };
      const weights =
        allowCallerFeatures && req.body.weights_bps
          ? req.body.weights_bps
          : {
              crypto_validity: 2500,
              evidence_coverage: 2500,
              reciprocity: 1500,
              receipt_quality: 1500,
              attestation_quality: 1000,
              temporal_consistency: 1000
            };
      const unsigned = computeReferenceScoreV0({
        subject,
        issuer,
        scoring_profile_id: String(req.body.scoring_profile_id ?? "did:tsl:provider:local/profile/reference-rc4"),
        model_version: String(req.body.model_version ?? "reference-rc4.0.0"),
        gate_result: {
          schema_valid: verification.checks.schema_valid,
          canonicalization_valid: verification.checks.schema_valid,
          signature_valid: verification.checks.signature_valid,
          key_active: verification.checks.key_active,
          not_revoked: verification.checks.not_revoked,
          included_in_log: verification.checks.included_in_log,
          checkpoint_valid: verification.checks.checkpoint_valid,
          settlement_satisfied: domainPolicy.requires_settlement ? verification.checks.checkpoint_settled === true : true,
          delegation_valid: domainPolicy.requires_delegation_check ? verification.checks.delegated_action_valid === true : true
        },
        evidence_coverage: evidenceCoverage,
        normalized_features_bps: normalizedFeatures,
        weights_bps: weights,
        calibration_profile: req.body.scoring_profile?.calibration_profile,
        confidence_profile: req.body.scoring_profile?.confidence_profile,
        has_adverse_evidence: Boolean(
            req.body.has_adverse_evidence === true || req.body.sybil_assessment?.risk_label === "high" || req.body.drift_report?.drift_label === "severe"
          ),
        domain_policy: domainPolicy,
        issued_at: now.toISOString()
      });
      const assessment = signTrustAssessmentV2(unsigned, process.env.TSL_SCORING_PROVIDER_SEED_HEX);
      if (repo) {
        if (req.body.scoring_profile?.profile_id) await repo.upsertScoringProfileV2(req.body.scoring_profile);
        if (req.body.model_card?.model_id) await repo.upsertModelCardV2(req.body.model_card);
        if (req.body.evaluation_report?.report_id) await repo.upsertEvaluationReportV1(req.body.evaluation_report);
        await repo.upsertEvidenceCoverageV1(evidenceCoverage);
        await repo.insertTrustAssessmentV2(assessment);
      } else if (allowMemoryStore) {
        assessmentStore.set(assessment.assessment_id, assessment);
        if (req.body.scoring_profile?.profile_id) scoringProfileStore.set(req.body.scoring_profile.profile_id, req.body.scoring_profile);
        if (req.body.model_card?.model_id) modelCardStore.set(req.body.model_card.model_id, req.body.model_card);
        if (req.body.evaluation_report?.report_id) evaluationReportStore.set(req.body.evaluation_report.report_id, req.body.evaluation_report);
      }
      res.json({ status: "accepted", assessment });
    } catch (error) {
      res.status(400).json({ error: { code: "TSL_ASSESSMENT_FAILED", message: error instanceof Error ? error.message : String(error) } });
    }
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
