import "../../../scripts/load-env.cjs";
import express from "express";
import { rateLimit } from "express-rate-limit";
import {
  CompositeTrustResolver,
  createPostgresRepositoryFromEnv,
  createSettlementBackendFromEnv,
  MemoryTrustResolver,
  PostgresTrustResolver,
  verifyTSL,
  type IdentityDocumentV1,
  type VerifierPolicy,
  type VerifyTSLInput
} from "../../../packages/core-ts/src/index";

export function createVerifierApi() {
  const app = express();
  const settlementBackend = createSettlementBackendFromEnv();
  const repo = createPostgresRepositoryFromEnv();
  let migrated = false;
  async function durableResolver(localIdentities: IdentityDocumentV1[]) {
    if (!repo) return new MemoryTrustResolver(localIdentities);
    if (!migrated) {
      await repo.migrate();
      migrated = true;
    }
    return new CompositeTrustResolver([new MemoryTrustResolver(localIdentities), new PostgresTrustResolver(repo)]);
  }
  app.use(express.json({ limit: "1mb" }));
  app.use(rateLimit({
    windowMs: Number(process.env.TSL_HTTP_RATE_LIMIT_WINDOW_MS ?? 60_000),
    limit: Number(process.env.TSL_HTTP_RATE_LIMIT_MAX ?? 1000),
    standardHeaders: true,
    legacyHeaders: false
  }));

  app.get("/health", (_req, res) => {
    res.json({ ok: true, service: "tsl-verifier-api" });
  });

  app.get("/v1/release/health", (_req, res) => {
    res.json({
      ok: true,
      service: "tsl-verifier-api",
      settlement_backend_configured: Boolean(settlementBackend),
      postgres_configured: Boolean(repo),
      zk_claims_supported: ["identity_age_days", "reciprocal_receipt_count"],
      audit_consistency_supported: true,
      token_free_verification: true
    });
  });

  app.post("/v1/verify", async (req, res) => {
    try {
      const identities: IdentityDocumentV1[] = [];
      const bundle = req.body.proof_bundle;
      if (bundle?.identity) identities.push(bundle.identity);
      if (req.body.identity) identities.push(req.body.identity);
      if (req.body.identity_document) identities.push(req.body.identity_document);
      if (Array.isArray(req.body.identities)) identities.push(...req.body.identities);

      const resolver = await durableResolver(identities);
      const input: VerifyTSLInput = {
        proof_bundle: bundle,
        envelope: req.body.envelope ?? bundle?.envelope,
        proof: req.body.proof ?? bundle?.proof,
        receipt_proofs: req.body.receipt_proofs,
        checkpoint: req.body.checkpoint ?? bundle?.checkpoint,
        settlement_evidence: req.body.settlement_evidence ?? bundle?.settlement_evidence,
        redaction_manifest: req.body.redaction_manifest ?? bundle?.redaction_manifest,
        message_disclosure: req.body.message_disclosure ?? bundle?.message_disclosure,
        receipts: req.body.receipts ?? bundle?.receipts,
        attestations: req.body.attestations ?? bundle?.attestations,
        revocations: req.body.revocations ?? bundle?.revocations,
        assessment: req.body.assessment ?? bundle?.assessment,
        assessment_v2: req.body.assessment_v2 ?? bundle?.assessment_v2,
        scoring_profile: req.body.scoring_profile ?? bundle?.scoring_profile,
        domain_policy: req.body.domain_policy ?? bundle?.domain_policy,
        evidence_coverage: req.body.evidence_coverage ?? bundle?.evidence_coverage,
        metadata_fingerprints: req.body.metadata_fingerprints ?? bundle?.metadata_fingerprints,
        graph_profile: req.body.graph_profile ?? bundle?.graph_profile,
        graph_feature_vector: req.body.graph_feature_vector ?? bundle?.graph_feature_vector,
        trusted_seeds: req.body.trusted_seeds ?? bundle?.trusted_seeds,
        adversarial_seeds: req.body.adversarial_seeds ?? bundle?.adversarial_seeds,
        trusted_seed_governance: req.body.trusted_seed_governance ?? bundle?.trusted_seed_governance,
        adversarial_seed_governance: req.body.adversarial_seed_governance ?? bundle?.adversarial_seed_governance,
        event_receivers: req.body.event_receivers ?? bundle?.event_receivers,
        sybil_assessment: req.body.sybil_assessment ?? bundle?.sybil_assessment,
        sybil_profile: req.body.sybil_profile ?? bundle?.sybil_profile,
        drift_report: req.body.drift_report ?? bundle?.drift_report,
        drift_feature_history: req.body.drift_feature_history ?? bundle?.drift_feature_history,
        drift_cohort_baseline_components: req.body.drift_cohort_baseline_components ?? bundle?.drift_cohort_baseline_components,
        zk_proofs: req.body.zk_proofs ?? bundle?.zk_proofs,
        zk_circuit_manifests: req.body.zk_circuit_manifests ?? bundle?.zk_circuit_manifests,
        zk_verification_key_registry: req.body.zk_verification_key_registry ?? bundle?.zk_verification_key_registry,
        delegations: req.body.delegations ?? bundle?.delegations,
        delegation_policies: req.body.delegation_policies ?? bundle?.delegation_policies,
        agent_actions: req.body.agent_actions ?? bundle?.agent_actions,
        audit_findings: req.body.audit_findings ?? bundle?.audit_findings,
        consistency_proofs: req.body.consistency_proofs ?? bundle?.consistency_proofs,
        non_membership_proofs: req.body.non_membership_proofs ?? bundle?.non_membership_proofs,
        governance_policy: req.body.governance_policy ?? bundle?.governance_policy,
        disclosure_consents: req.body.disclosure_consents ?? bundle?.disclosure_consents
      };
	      const policy: VerifierPolicy = req.body.verifier_policy ?? req.body.policy ?? {
	        require_inclusion: Boolean(req.body.proof ?? bundle?.proof),
	        require_checkpoint: Boolean(req.body.checkpoint ?? bundle?.checkpoint),
	        require_settlement: false
	      };

      const result = await verifyTSL(input, resolver, policy, settlementBackend ?? undefined);
      res.status(result.verified ? 200 : 422).json(result);
    } catch (error) {
      res.status(400).json({
        error: {
          code: "TSL_VERIFY_REQUEST_INVALID",
          message: error instanceof Error ? error.message : "Invalid verify request"
        }
      });
    }
  });

  return app;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT ?? 8083);
  createVerifierApi().listen(port, () => {
    process.stdout.write(`tsl verifier-api listening on http://localhost:${port}\n`);
  });
}
