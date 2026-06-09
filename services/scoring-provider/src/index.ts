import "../../../scripts/load-env.cjs";
import express from "express";
import { rateLimit } from "express-rate-limit";
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
			  extractReferenceFeatureVectorV0,
			  eventHash,
			  receiptHash,
			  attestationHash,
		  sha256Hex,
  scoringProfileV2Hash,
	  signTrustAssessmentV2,
	  signTrustAssessmentObject,
  verifyEd25519,
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

function objectHash(object: unknown): string {
  return sha256Hex(canonicalBytes(object));
}

function unsignedObjectHash(object: unknown): string {
  if (!object || typeof object !== "object") return objectHash(object);
  const unsigned = { ...(object as Record<string, unknown>) };
  delete unsigned.signature;
  return objectHash(unsigned);
}

function schemaValidOrErrors(schemaKey: Parameters<typeof validateSchema>[0], object: unknown): string[] {
  const validation = validateSchema(schemaKey, object);
  return validation.valid ? [] : validation.errors;
}

function signedByIdentity(input: {
  identity: IdentityDocumentV1 | undefined;
  issuedAt: string;
  hash: string;
  signature?: string;
}): boolean {
  const key = input.identity?.verification_methods.find((method) => method.type === "ed25519" && method.status === "active" && Date.parse(method.created_at) <= Date.parse(input.issuedAt));
  return Boolean(key && input.signature && verifyEd25519(key.public_key, input.hash as `0x${string}`, input.signature as `0x${string}`));
}

function identityFromRegistrationBody(body: Record<string, unknown>, provider?: string): IdentityDocumentV1 | undefined {
  const identities = [
    body.identity,
    ...(Array.isArray(body.identities) ? body.identities : [])
  ].filter(Boolean) as IdentityDocumentV1[];
  return identities.find((identity) => identity.id === provider) ?? identities[0];
}

function devRegistrationMode(): boolean {
  return process.env.TSL_DEV_SCORING_REGISTRATIONS === "true" || process.env["TSL_" + "DEV_SCORING_INPUTS"] === "true";
}

function registrationSignatureValid(input: {
  body: Record<string, unknown>;
  provider?: string;
  issuedAt?: string;
  hash: string;
  signature?: string;
}): boolean {
  return signedByIdentity({
    identity: identityFromRegistrationBody(input.body, input.provider),
    issuedAt: input.issuedAt ?? new Date(0).toISOString(),
    hash: input.hash,
    signature: input.signature
  });
}

function scoringVerificationArtifacts(source: Record<string, unknown> | undefined): Partial<VerifyTSLInput> {
  if (!source) return {};
  return {
    ...(source.graph_profile ? { graph_profile: source.graph_profile as VerifyTSLInput["graph_profile"] } : {}),
    ...(source.graph_feature_vector ? { graph_feature_vector: source.graph_feature_vector as VerifyTSLInput["graph_feature_vector"] } : {}),
    ...(source.trusted_seeds ? { trusted_seeds: source.trusted_seeds as VerifyTSLInput["trusted_seeds"] } : {}),
    ...(source.adversarial_seeds ? { adversarial_seeds: source.adversarial_seeds as VerifyTSLInput["adversarial_seeds"] } : {}),
    ...(source.trusted_seed_governance ? { trusted_seed_governance: source.trusted_seed_governance as VerifyTSLInput["trusted_seed_governance"] } : {}),
    ...(source.adversarial_seed_governance ? { adversarial_seed_governance: source.adversarial_seed_governance as VerifyTSLInput["adversarial_seed_governance"] } : {}),
    ...(source.event_receivers ? { event_receivers: source.event_receivers as VerifyTSLInput["event_receivers"] } : {}),
    ...(source.receipt_disputes ? { receipt_disputes: source.receipt_disputes as VerifyTSLInput["receipt_disputes"] } : {}),
    ...(source.attestations_v2 ? { attestations_v2: source.attestations_v2 as VerifyTSLInput["attestations_v2"] } : {}),
    ...(source.sybil_assessment ? { sybil_assessment: source.sybil_assessment as VerifyTSLInput["sybil_assessment"] } : {}),
    ...(source.sybil_profile ? { sybil_profile: source.sybil_profile as VerifyTSLInput["sybil_profile"] } : {}),
    ...(source.drift_report ? { drift_report: source.drift_report as VerifyTSLInput["drift_report"] } : {}),
    ...(source.drift_feature_history ? { drift_feature_history: source.drift_feature_history as VerifyTSLInput["drift_feature_history"] } : {}),
    ...(source.drift_cohort_baseline_components ? { drift_cohort_baseline_components: source.drift_cohort_baseline_components as VerifyTSLInput["drift_cohort_baseline_components"] } : {})
  };
}

function normalizeFeaturesFromProfiles(input: {
  featureRegistry: { feature_ids: string[] };
  normalizationProfile: {
    feature_ranges_bps: Record<string, { min_bps: number; max_bps: number; missing_bps: number }>;
    feature_methods?: Record<string, "bounded" | "log_percentile" | "asinh" | "risk_penalty">;
    asinh_scales_bps?: Record<string, number>;
    percentiles_bps?: Record<string, { p05_bps: number; p50_bps: number; p95_bps: number }>;
  };
  weightProfile: { weights_bps: Record<string, number>; feature_directions?: Record<string, "positive" | "penalty"> };
  rawFeatures: Record<string, number | undefined>;
}): { normalized: Record<string, number>; weights: Record<string, number>; errors: string[] } {
  const normalized: Record<string, number> = {};
  const weights: Record<string, number> = {};
  const errors: string[] = [];
  for (const featureId of [...input.featureRegistry.feature_ids].sort()) {
    const range = input.normalizationProfile.feature_ranges_bps[featureId];
    const weight = input.weightProfile.weights_bps[featureId];
    if (!range) {
      errors.push(`TSL_NORMALIZATION_RANGE_MISSING:${featureId}`);
      continue;
    }
    if (typeof weight !== "number") {
      errors.push(`TSL_WEIGHT_MISSING:${featureId}`);
      continue;
    }
    const raw = input.rawFeatures[featureId];
    const value = typeof raw === "number" ? raw : range.missing_bps;
    const method = input.normalizationProfile.feature_methods?.[featureId] ?? "bounded";
    const span = Math.max(1, range.max_bps - range.min_bps);
    const bounded = Math.max(0, Math.min(10000, Math.floor(((value - range.min_bps) * 10000) / span)));
    const percentiles = input.normalizationProfile.percentiles_bps?.[featureId];
    const normalizedValue =
      method === "log_percentile" && percentiles
        ? Math.max(
            0,
            Math.min(
              10000,
              Math.floor(
                ((Math.log1p(Math.max(0, value)) - Math.log1p(percentiles.p05_bps)) * 10000) /
                  Math.max(1, Math.log1p(percentiles.p95_bps) - Math.log1p(percentiles.p05_bps))
              )
            )
          )
        : method === "asinh"
          ? Math.max(0, Math.min(10000, Math.floor((Math.asinh(value / Math.max(1, input.normalizationProfile.asinh_scales_bps?.[featureId] ?? 1000)) / Math.asinh(10000 / Math.max(1, input.normalizationProfile.asinh_scales_bps?.[featureId] ?? 1000))) * 10000)))
          : method === "risk_penalty"
            ? 10000 - bounded
            : bounded;
    normalized[featureId] = input.weightProfile.feature_directions?.[featureId] === "penalty" && method !== "risk_penalty" ? 10000 - normalizedValue : normalizedValue;
    weights[featureId] = Math.max(0, Math.min(10000, Math.trunc(weight)));
  }
  return { normalized, weights, errors };
}

export function createScoringProvider() {
  const repo = createPostgresRepositoryFromEnv();
  const allowMemoryStore = process.env.TSL_SCORING_PERSISTENCE === "memory" || process.env.TSL_SCORING_ALLOW_MEMORY_STORE === "true";
  const assessmentStore = new Map<string, unknown>();
  const scoringProfileStore = new Map<string, unknown>();
  const modelCardStore = new Map<string, unknown>();
  const evaluationReportStore = new Map<string, unknown>();
  const graphArtifactStore = new Map<string, unknown>();
  const metadataFingerprintStore = new Map<string, unknown>();
  const app = express();
  app.use(express.json({ limit: "1mb" }));
  app.use(rateLimit({
    windowMs: Number(process.env.TSL_HTTP_RATE_LIMIT_WINDOW_MS ?? 60_000),
    limit: Number(process.env.TSL_HTTP_RATE_LIMIT_MAX ?? 1000),
    standardHeaders: true,
    legacyHeaders: false
  }));
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
      if (
        !devRegistrationMode() &&
        !registrationSignatureValid({
          body: req.body,
          provider: profile.provider,
          issuedAt: profile.issued_at,
          hash: scoringProfileV2Hash(profile),
          signature: profile.signature
        })
      ) {
        res.status(401).json({ error: { code: "TSL_SCORING_GOVERNANCE_INVALID", message: "Scoring profile registration requires a provider-signed profile and matching provider identity" } });
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
      if (
        !devRegistrationMode() &&
        !registrationSignatureValid({
          body: req.body,
          provider: model_card.provider,
          issuedAt: model_card.issued_at,
          hash: unsignedObjectHash(model_card),
          signature: model_card.signature
        })
      ) {
        res.status(401).json({ error: { code: "TSL_SCORING_GOVERNANCE_INVALID", message: "Model card registration requires a provider signature and matching provider identity" } });
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
      if (
        !devRegistrationMode() &&
        !registrationSignatureValid({
          body: req.body,
          provider: String(req.body.provider ?? process.env.TSL_SCORING_PROVIDER_ID ?? ""),
          issuedAt: evaluation_report.issued_at,
          hash: unsignedObjectHash(evaluation_report),
          signature: evaluation_report.signature
        })
      ) {
        res.status(401).json({ error: { code: "TSL_SCORING_GOVERNANCE_INVALID", message: "Evaluation report registration requires a provider signature and matching provider identity" } });
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

  app.post("/v1/graph/features", async (req, res) => {
    const graphProfile = req.body.graph_profile;
    const graphFeatureVector = req.body.graph_feature_vector;
    const sybilAssessment = req.body.sybil_assessment;
    const driftReport = req.body.drift_report;
    const errors = [
      ...(graphProfile ? schemaValidOrErrors("graphProfileV2", graphProfile) : []),
      ...(graphFeatureVector ? schemaValidOrErrors("graphFeatureVectorV1", graphFeatureVector) : []),
      ...(sybilAssessment ? schemaValidOrErrors("sybilAssessmentV1", sybilAssessment) : []),
      ...(driftReport ? schemaValidOrErrors("driftReportV1", driftReport) : [])
    ];
    if (errors.length || (!graphFeatureVector && !sybilAssessment && !driftReport)) {
      res.status(422).json({ error: { code: "TSL_GRAPH_ARTIFACTS_INVALID", message: errors.join("; ") || "At least one graph, Sybil, or drift artifact is required" } });
      return;
    }
    if (process.env.TSL_DEV_GRAPH_ARTIFACTS !== "true") {
      const bundle = req.body.proof_bundle;
      const identities = [
        bundle?.identity,
        req.body.identity,
        ...(Array.isArray(req.body.identities) ? req.body.identities : []),
        ...(Array.isArray(bundle?.identities) ? bundle.identities : [])
      ].filter(Boolean) as IdentityDocumentV1[];
      const identityMap = new Map(identities.map((identity) => [identity.id, identity]));
      const verifyInput: VerifyTSLInput | null = (bundle ?? req.body.envelope)
        ? {
            proof_bundle: bundle,
            envelope: req.body.envelope ?? bundle?.envelope,
            proof: req.body.proof ?? bundle?.proof,
            checkpoint: req.body.checkpoint ?? bundle?.checkpoint,
            redaction_manifest: req.body.redaction_manifest ?? bundle?.redaction_manifest,
            receipts: req.body.receipts ?? bundle?.receipts,
            attestations: req.body.attestations ?? bundle?.attestations,
            attestations_v2: req.body.attestations_v2 ?? bundle?.attestations_v2,
            receipt_disputes: req.body.receipt_disputes ?? bundle?.receipt_disputes,
            graph_profile: graphProfile,
            graph_feature_vector: graphFeatureVector,
            sybil_assessment: sybilAssessment,
            sybil_profile: req.body.sybil_profile,
            drift_report: driftReport,
            drift_feature_history: req.body.drift_feature_history,
            trusted_seeds: req.body.trusted_seeds,
            adversarial_seeds: req.body.adversarial_seeds,
            trusted_seed_governance: req.body.trusted_seed_governance,
            adversarial_seed_governance: req.body.adversarial_seed_governance,
            event_receivers: req.body.event_receivers,
            disclosure_consents: req.body.disclosure_consents ?? bundle?.disclosure_consents
          }
        : null;
      if (!verifyInput?.envelope || !identities.length) {
        res.status(422).json({ error: { code: "TSL_GRAPH_ARTIFACT_REQUIRED", message: "Production graph artifact submission requires evidence and resolver identities for recomputation" } });
        return;
      }
      const verification = await verifyTSL(
        verifyInput,
        { resolveTrustID: (trustId: string) => identityMap.get(trustId) ?? null },
        {
          require_graph_artifacts: true,
          require_research_graph_algorithm: req.body.require_research_graph_algorithm === true,
          require_seed_governance_opening: req.body.require_seed_governance_opening === true,
          require_full_covariance_drift: Boolean(driftReport),
          require_sybil_provider_issuer: Boolean(sybilAssessment)
        }
      );
      if (!verification.verified) {
        res.status(422).json({ error: { code: "TSL_GRAPH_ARTIFACTS_INVALID", message: verification.errors.join("; "), checks: verification.checks } });
        return;
      }
    }
    const artifactId = String(
      graphFeatureVector?.feature_commitment ??
        graphFeatureVector?.recomputation_commitment ??
        sybilAssessment?.evidence_commitment ??
        driftReport?.feature_history_commitment ??
        objectHash(req.body)
    );
    graphArtifactStore.set(artifactId, req.body);
    res.json({ status: "accepted", artifact_id: artifactId });
  });

  app.post("/v1/metadata-fingerprints", (req, res) => {
    const fingerprint = req.body.metadata_fingerprint ?? req.body;
    const validation = validateSchema("metadataFingerprintCommitmentV1", fingerprint);
    if (!validation.valid) {
      res.status(422).json({ error: { code: "TSL_METADATA_FINGERPRINT_INVALID", message: validation.errors.join("; ") } });
      return;
    }
    const commitment = String(fingerprint.fingerprint_commitment ?? objectHash(fingerprint));
    metadataFingerprintStore.set(commitment, fingerprint);
    res.json({ status: "accepted", fingerprint_commitment: commitment });
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
      const scoringArtifacts = scoringVerificationArtifacts(req.body);
      const bundledScoringArtifacts = scoringVerificationArtifacts(bundle);
      const verifyInput: VerifyTSLInput | null = bundle
        ? {
            proof_bundle: bundle,
            envelope: bundle.envelope,
            proof: bundle.proof,
            checkpoint: bundle.checkpoint,
            settlement_evidence: bundle.settlement_evidence,
            redaction_manifest: bundle.redaction_manifest,
            receipts: bundle.receipts,
            attestations: bundle.attestations,
            revocations: bundle.revocations,
            assessment_v2: bundle.assessment_v2,
            delegation_policies: bundle.delegations,
            agent_actions: bundle.agent_actions,
            message_disclosure: bundle.message_disclosure,
            disclosure_consents: bundle.disclosure_consents,
            ...bundledScoringArtifacts,
            ...scoringArtifacts
          }
        : req.body.envelope
          ? {
              envelope: req.body.envelope,
              proof: req.body.proof,
              checkpoint: req.body.checkpoint,
              settlement_evidence: req.body.settlement_evidence,
              redaction_manifest: req.body.redaction_manifest,
              receipts: req.body.receipts,
              attestations: req.body.attestations,
              revocations: req.body.revocations,
              delegation_policies: req.body.delegation_policies,
              agent_actions: req.body.agent_actions,
              message_disclosure: req.body.message_disclosure,
              disclosure_consents: req.body.disclosure_consents,
              ...scoringArtifacts
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
      const subject = String(req.body.subject ?? verifyInput.envelope.sender);
      const issuer = String(req.body.issuer ?? process.env.TSL_SCORING_PROVIDER_ID ?? "did:tsl:provider:local");
      const requestedGraphArtifact = Boolean(req.body.graph_feature_vector || req.body.sybil_assessment || req.body.drift_report || bundle?.graph_feature_vector || bundle?.sybil_assessment || bundle?.drift_report);
      if (
        requestedGraphArtifact &&
        (!verifyInput.graph_feature_vector && !verifyInput.sybil_assessment && !verifyInput.drift_report)
      ) {
        res.status(422).json({
          error: {
            code: "TSL_SCORING_EVIDENCE_VERIFICATION_FAILED",
            message: "Graph, Sybil, and drift artifacts supplied to scoring must be present inside the same verifyTSL input used for evidence verification"
          }
        });
        return;
      }
      const verification = await verifyTSL(verifyInput, resolver, {
        require_inclusion: true,
        require_checkpoint: true,
        require_settlement: domainPolicy.requires_settlement,
        verifier_or_provider: issuer,
        disclosure_purpose: "scoring_assessment",
        require_graph_artifacts: requestedGraphArtifact,
        require_sybil_provider_issuer: Boolean(verifyInput.sybil_assessment),
        require_behavioral_sybil_tiers: true,
        require_seed_governance_opening: Boolean(verifyInput.trusted_seed_governance || verifyInput.adversarial_seed_governance),
        require_core_drift_formula: Boolean(verifyInput.drift_report),
        require_full_covariance_drift: Boolean(verifyInput.drift_report)
      });
      if (!verification.verified) {
        const privateBoundaryErrors = new Set([
          "TSL_DISCLOSURE_CONSENT_REQUIRED",
          "TSL_RECEIPT_INVALID",
          "TSL_RECEIPT_INCLUSION_INVALID",
          "TSL_ATTESTATION_INVALID",
          "TSL_REDACTION_MANIFEST_INVALID"
        ]);
        const privateBoundaryFailed = verification.errors.some((error) => privateBoundaryErrors.has(error));
        if (!privateBoundaryFailed) {
          const evidenceCoverage = computeEvidenceCoverageV0({
            subject,
            valid_signed_event_count: verification.checks.signature_valid ? 1 : 0,
            valid_receipt_count: 0,
            unique_counterparty_count: 0,
            computed_at: now.toISOString()
          });
          const unsignedFailure = computeReferenceScoreV0({
            subject,
            issuer,
            scoring_profile_id: String(req.body.scoring_profile?.profile_id ?? req.body.scoring_profile_id ?? "did:tsl:provider:local/profile/reference-rc4"),
            model_version: String(req.body.scoring_profile?.model_version ?? req.body.model_version ?? "reference-rc4.0.0"),
            gate_result: {
              schema_valid: verification.checks.schema_valid,
              canonicalization_valid: verification.checks.schema_valid,
              signature_valid: verification.checks.signature_valid,
              key_active: verification.checks.key_active,
              not_revoked: verification.checks.not_revoked,
              included_in_log: verification.checks.included_in_log,
              checkpoint_valid: verification.checks.checkpoint_matches_proof,
              settlement_satisfied: domainPolicy.requires_settlement ? verification.checks.checkpoint_settled === true : true,
              delegation_valid: domainPolicy.requires_delegation_check ? verification.checks.delegated_action_valid === true : true
            },
            evidence_coverage: evidenceCoverage,
            normalized_features_bps: {},
            weights_bps: {},
            has_adverse_evidence: false,
            domain_policy: domainPolicy,
            issued_at: now.toISOString()
          });
          const failureAssessment = signTrustAssessmentV2(unsignedFailure, process.env.TSL_SCORING_PROVIDER_SEED_HEX);
          if (repo) await repo.insertTrustAssessmentV2(failureAssessment);
          else if (allowMemoryStore) assessmentStore.set(failureAssessment.assessment_id, failureAssessment);
          res.status(200).json({ status: "accepted", assessment: failureAssessment, verification_errors: verification.errors });
          return;
        }
        res.status(422).json({
          error: {
            code: "TSL_SCORING_EVIDENCE_VERIFICATION_FAILED",
            message: "v2 scoring requires verified evidence before private receipts, disclosures, or counterparties can be used for feature extraction",
            verification_errors: verification.errors,
            checks: verification.checks
          }
        });
        return;
      }
      const callerFeatureOverride =
        req.body.evidence_coverage !== undefined || req.body.normalized_features_bps !== undefined || req.body.weights_bps !== undefined;
      const allowCallerFeatures = process.env["TSL_" + "DEV_SCORING_INPUTS"] === "true";
      if (callerFeatureOverride && !allowCallerFeatures) {
        res.status(400).json({
          error: {
            code: "TSL_CALLER_SUPPLIED_SCORING_FEATURES_REJECTED",
            message: "v2 scoring derives evidence coverage, normalized features, and weights from verified evidence/profile unless explicit dev mode is enabled"
          }
        });
        return;
      }
      const callerDerivedFeatureFields = [
        "distinct_community_count",
        "attestation_count",
        "recent_revocation_count",
        "cadence_intervals_ms"
      ].filter((field) => req.body[field] !== undefined);
      if (!allowCallerFeatures && callerDerivedFeatureFields.length) {
        res.status(400).json({
          error: {
            code: "TSL_CALLER_SUPPLIED_SCORING_FEATURES_REJECTED",
            message: `Production v2 scoring does not accept caller-derived feature counts outside verified evidence/profile inputs: ${callerDerivedFeatureFields.join(", ")}`
          }
        });
        return;
      }
      if (!allowCallerFeatures && req.body.local_relationship_bps !== undefined) {
        res.status(400).json({
          error: {
            code: "TSL_DISCLOSURE_CONSENT_REQUIRED",
            message: "local_relationship is verifier-local private context and cannot be uploaded to production scoring without a dedicated consented local feature artifact"
          }
        });
        return;
      }
      if (!allowCallerFeatures) {
        const governance = req.body.provider_governance_status;
        const governanceValidation = governance ? validateSchema("providerGovernanceStatusV1", governance) : { valid: false, errors: [] };
        const scoringProfile = req.body.scoring_profile;
        const featureRegistry = req.body.feature_registry;
        const normalizationProfile = req.body.normalization_profile;
        const weightProfile = req.body.weight_profile;
        const calibrationProfile = req.body.calibration_profile;
        const confidenceProfile = req.body.confidence_profile;
        const profileErrors = [
          ...schemaValidOrErrors("scoringProfileV2", scoringProfile),
          ...schemaValidOrErrors("featureRegistryV1", featureRegistry),
          ...schemaValidOrErrors("normalizationProfileV1", normalizationProfile),
          ...schemaValidOrErrors("weightProfileV1", weightProfile),
          ...schemaValidOrErrors("calibrationProfileV1", calibrationProfile),
          ...schemaValidOrErrors("confidenceProfileV1", confidenceProfile)
        ];
        const providerIdentity = identityMap.get(issuer);
        const governanceSignatureValid = signedByIdentity({
          identity: providerIdentity,
          issuedAt: String(governance?.issued_at ?? scoringProfile?.issued_at ?? now.toISOString()),
          hash: governance ? unsignedObjectHash(governance) : "",
          signature: governance?.signature
        });
        const profileCommitmentsValid =
          scoringProfile &&
          featureRegistry &&
          normalizationProfile &&
          weightProfile &&
          calibrationProfile &&
          confidenceProfile &&
          scoringProfile.provider === issuer &&
          scoringProfile.feature_registry_commitment === objectHash(featureRegistry) &&
          scoringProfile.normalization_profile_commitment === objectHash(normalizationProfile) &&
          scoringProfile.weight_profile_commitment === objectHash(weightProfile) &&
          scoringProfile.calibration_profile_commitment === objectHash(calibrationProfile) &&
          scoringProfile.threshold_policy_commitment === objectHash(domainPolicy) &&
          scoringProfile.evaluation_report_commitment === objectHash(req.body.evaluation_report) &&
          Boolean(req.body.privacy_report_commitment ?? req.body.privacy_report) &&
          Boolean(req.body.training_data_commitment) &&
          Boolean(scoringProfile.appeal_policy_uri ?? req.body.appeal_policy_uri);
        const profileSignaturesValid =
          scoringProfile &&
          signedByIdentity({ identity: providerIdentity, issuedAt: scoringProfile.issued_at, hash: scoringProfileV2Hash(scoringProfile), signature: scoringProfile.signature }) &&
          [featureRegistry, normalizationProfile, weightProfile, calibrationProfile, confidenceProfile].every((artifact) =>
            signedByIdentity({ identity: providerIdentity, issuedAt: artifact.issued_at, hash: unsignedObjectHash(artifact), signature: artifact.signature })
          );
        if (
          !governance ||
          !governanceValidation.valid ||
          governance.provider !== issuer ||
          governance.status !== "active" ||
          governance.model_registered !== true ||
          governance.promotion_gate_result !== "pass" ||
          governance.red_team_result !== "pass" ||
          !governanceSignatureValid ||
          Number(governance.privacy_leakage_bps) > 1000
        ) {
          res.status(400).json({
            error: {
              code: "TSL_SCORING_GOVERNANCE_INVALID",
              message: "Production v2 scoring requires active provider governance, registered model, promotion pass, red-team pass, and privacy leakage gate"
            }
          });
          return;
        }
        if (profileErrors.length || !profileCommitmentsValid || !profileSignaturesValid) {
          res.status(400).json({
            error: {
              code: "TSL_PROFILE_DERIVED_SCORING_REQUIRED",
              message: `Production scoring requires signed profile sub-artifacts and commitments matching scoring_profile.v2${profileErrors.length ? `: ${profileErrors.join("; ")}` : ""}`
            }
          });
          return;
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
              distinct_community_count: 0,
              attestation_count: (verifyInput.attestations?.length ?? 0) + (verifyInput.attestations_v2?.length ?? 0),
              recent_revocation_count: verifyInput.revocations?.length ?? 0,
              computed_at: now.toISOString()
            });
      const rawFeatureValues = {
        ...extractReferenceFeatureVectorV0({
          subject,
          identity: identityMap.get(subject),
          envelope: verifyInput.envelope,
          receipts: verifyInput.receipts,
          attestations: verifyInput.attestations,
          attestations_v2: verifyInput.attestations_v2,
          graph_feature_vector: verifyInput.graph_feature_vector,
          sybil_assessment: verifyInput.sybil_assessment,
          drift_report: verifyInput.drift_report,
          verification_checks: verification.checks,
          valid_signed_event_count: verification.checks.signature_valid ? 1 : 0,
          clustered_receipt_count: new Set((verifyInput.receipts ?? []).map((receipt) => receipt.metadata_commitment ?? receipt.receiver)).size,
          cadence_intervals_ms: allowCallerFeatures && Array.isArray(req.body.cadence_intervals_ms) ? req.body.cadence_intervals_ms.map(Number) : undefined,
          local_relationship_bps: allowCallerFeatures && req.body.local_relationship_bps !== undefined ? Number(req.body.local_relationship_bps) : undefined,
          local_relationship_disclosed: allowCallerFeatures,
          computed_at: now.toISOString()
        }),
        evidence_coverage: evidenceCoverage.coverage_bps
      };
      const derivedProfileFeatures =
        !allowCallerFeatures
          ? normalizeFeaturesFromProfiles({
              featureRegistry: req.body.feature_registry,
              normalizationProfile: req.body.normalization_profile,
              weightProfile: req.body.weight_profile,
              rawFeatures: rawFeatureValues
            })
          : undefined;
      if (derivedProfileFeatures?.errors.length) {
        res.status(400).json({
          error: { code: "TSL_PROFILE_DERIVED_SCORING_REQUIRED", message: derivedProfileFeatures.errors.join("; ") }
        });
        return;
      }
      const normalizedFeatures =
        allowCallerFeatures && req.body.normalized_features_bps
          ? req.body.normalized_features_bps
          : derivedProfileFeatures!.normalized;
      const weights =
        allowCallerFeatures && req.body.weights_bps
          ? req.body.weights_bps
          : derivedProfileFeatures!.weights;
      const unsigned = computeReferenceScoreV0({
        subject,
        issuer,
        scoring_profile_id: String(req.body.scoring_profile?.profile_id ?? req.body.scoring_profile_id ?? "did:tsl:provider:local/profile/reference-rc4"),
        model_version: String(req.body.scoring_profile?.model_version ?? req.body.model_version ?? "reference-rc4.0.0"),
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
        calibration_profile: allowCallerFeatures ? req.body.scoring_profile?.calibration_profile : req.body.calibration_profile,
        confidence_profile: allowCallerFeatures ? req.body.scoring_profile?.confidence_profile : req.body.confidence_profile,
        bootstrap_evidence_hashes: [
          eventHash(verifyInput.envelope),
          ...(verifyInput.receipts ?? []).map((receipt) => receiptHash(receipt)),
          ...(verifyInput.attestations ?? []).map((attestation) => attestationHash(attestation)),
          ...(verifyInput.attestations_v2 ?? []).map((attestation) => sha256Hex(canonicalBytes(attestation)))
        ],
        has_adverse_evidence: Boolean(
          req.body.has_adverse_evidence === true || verifyInput.sybil_assessment?.risk_label === "high" || verifyInput.drift_report?.drift_label === "severe"
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
