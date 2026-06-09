import "../../../scripts/load-env.cjs";
import express from "express";
import { rateLimit } from "express-rate-limit";
import {
  assessmentCommitmentHash,
  assessmentHash,
  attestationCommitmentHash,
  attestationHash,
  CompositeTrustResolver,
  createPostgresRepositoryFromEnv,
  createQueueFromEnv,
  createSettlementBackendFromEnv,
  findVerificationMethod,
  InMemoryRelayStore,
  keyActiveAt,
  MemoryTrustResolver,
  PostgresTrustResolver,
  QUEUE_TOPICS,
  receiptCommitmentHash,
  receiptHash,
  RelayValidationError,
  revocationCommitmentHash,
  revocationHash,
  type AttestationV1,
  type EventCommitmentV1,
  type Hex32,
  type IdentityDocumentV1,
  type ReceiptCommitmentV1,
  type RevocationV1,
  type TrustAssessmentV1,
  type TrustResolver,
  validateSchema,
  verifyEd25519,
  verifyTSL
} from "../../../packages/core-ts/src/index";

const REVOCATION_REASON_CODES: Record<RevocationV1["reason_class"], number> = {
  rotation: 0,
  compromise: 1,
  device_loss: 2,
  policy_update: 3
};

class FixedWindowRateLimiter {
  private readonly buckets = new Map<string, { count: number; resetAt: number }>();

  check(key: string, limit: number, windowMs: number): void {
    const now = Date.now();
    const bucket = this.buckets.get(key);
    if (!bucket || bucket.resetAt <= now) {
      this.buckets.set(key, { count: 1, resetAt: now + windowMs });
      return;
    }
    bucket.count += 1;
    if (bucket.count > limit) {
      throw new RelayValidationError("TSL_RATE_LIMITED", "Relay rate limit exceeded", { key, limit, reset_at: bucket.resetAt });
    }
  }
}

export function createRelayNode() {
  const settlementBackend = createSettlementBackendFromEnv();
  const repo = createPostgresRepositoryFromEnv();
  const queue = createQueueFromEnv();
  const rateLimiter = new FixedWindowRateLimiter();
  const appealRecords: Array<Record<string, unknown>> = [];
  const evidenceRecords: Array<Record<string, unknown>> = [];
  const store = new InMemoryRelayStore({
    relay_id: process.env.TSL_RELAY_ID ?? "did:tsl:relay:dev",
    relay_signing_key_id: process.env.TSL_RELAY_SIGNING_KEY_ID ?? "#relay-checkpoint",
    relay_signing_seed_hex: process.env.TSL_RELAY_SIGNING_SEED_HEX,
    epoch_duration_ms: Number(process.env.TSL_EPOCH_MS ?? 300000),
    timestamp_window_ms: Number(process.env.TSL_TIMESTAMP_WINDOW_MS ?? 600000),
    settlement_backend: settlementBackend
  });
  let migrated = false;
  async function ensureDurableReady() {
    if (repo && !migrated) {
      await repo.migrate();
      for (const identity of store.identities()) {
        await repo.upsertIdentity(identity);
      }
      migrated = true;
    }
  }

  const app = express();
  app.use(express.json({ limit: "1mb" }));
  app.use(rateLimit({
    windowMs: Number(process.env.TSL_HTTP_RATE_LIMIT_WINDOW_MS ?? 60_000),
    limit: Number(process.env.TSL_HTTP_RATE_LIMIT_MAX ?? 1000),
    standardHeaders: true,
    legacyHeaders: false
  }));

  function resolver(): TrustResolver {
    return repo ? new CompositeTrustResolver([store.resolver, new PostgresTrustResolver(repo)]) : store.resolver;
  }

  function checkRate(req: express.Request, action: string, limit: number, windowMs = 60 * 60 * 1000): void {
    rateLimiter.check(`${action}:${req.ip}`, limit, windowMs);
  }

  function assertTimestampInWindow(timestamp: string): void {
    const parsed = Date.parse(timestamp);
    if (!Number.isFinite(parsed)) throw new RelayValidationError("TSL_TIMESTAMP_INVALID", "Timestamp is not parseable");
    if (Math.abs(Date.now() - parsed) > store.timestamp_window_ms) {
      throw new RelayValidationError("TSL_TIMESTAMP_OUT_OF_WINDOW", "Timestamp is outside relay policy");
    }
  }

  async function assertSignedByIdentity(object: {
    trustId: string;
    signingKeyId: string;
    timestamp: string;
    hash: Hex32;
    signature: `0x${string}`;
    code: string;
  }): Promise<void> {
    const identity = await resolver().resolveTrustID(object.trustId, object.timestamp);
    const key = identity ? findVerificationMethod(identity, object.signingKeyId) : null;
    if (!key) throw new RelayValidationError("TSL_KEY_NOT_FOUND", "Signing key not found");
    if (!keyActiveAt(key, object.timestamp)) throw new RelayValidationError("TSL_KEY_INACTIVE", "Signing key inactive at timestamp");
    if (key.type !== "ed25519" || !verifyEd25519(key.public_key, object.hash, object.signature)) {
      throw new RelayValidationError(object.code, "Signature failed verification");
    }
  }

  app.get("/health", (_req, res) => {
    res.json({ ok: true, service: "tsl-relay-node", relay_id: store.relay_id });
  });

  app.post("/v1/identity/create", async (req, res) => {
    try {
      checkRate(req, "identity_create", 100);
      const identity = req.body.identity as IdentityDocumentV1;
      store.upsertIdentity(identity);
      await ensureDurableReady();
      await repo?.upsertIdentity(identity);
      let registryTx: string | undefined;
      if (settlementBackend?.registerIdentity) {
        registryTx = await settlementBackend.registerIdentity(identity);
      }
      res.json({
        trust_id: identity.id,
        registry_status: registryTx ? "registered" : repo ? "pending" : "local_only",
        ...(registryTx ? { registry_tx: registryTx } : {})
      });
    } catch (error) {
      sendRelayError(res, error);
    }
  });

  app.get("/v1/identity/:trustId", async (req, res) => {
    const memoryIdentity = store.resolver.resolveTrustID(req.params.trustId);
    if (memoryIdentity) {
      res.json(memoryIdentity);
      return;
    }
    await ensureDurableReady();
    const durableIdentity = await repo?.getIdentity(req.params.trustId);
    if (!durableIdentity) {
      res.status(404).json({ error: { code: "TSL_KEY_NOT_FOUND", message: "TrustID not found" } });
      return;
    }
    res.json(durableIdentity);
  });

  app.post("/v1/commitments", async (req, res) => {
    try {
      checkRate(req, "commitments", 10000);
      const event = (req.body.event ?? req.body.envelope) as EventCommitmentV1;
      await ensureDurableReady();
      const durableIdentity = await repo?.getIdentity(event.sender);
      if (durableIdentity) store.upsertIdentity(durableIdentity);
      const accepted = await store.acceptEvent(event);
      await repo?.insertEvent(event, accepted.relay_id, accepted.epoch_start_ms, accepted.epoch_duration_ms);
      await queue?.publish(QUEUE_TOPICS.commitmentsAccepted, { ...accepted });
      res.json({
        status: "accepted",
        commitment_hash: accepted.commitment_hash,
        relay_id: accepted.relay_id,
        epoch_start_ms: accepted.epoch_start_ms,
        epoch_duration_ms: accepted.epoch_duration_ms,
        shard: accepted.shard,
        log_index: accepted.log_index,
        inclusion_promise: `0x${accepted.commitment_hash.slice(2, 18)}`
      });
    } catch (error) {
      sendRelayError(res, error);
    }
  });

  app.post("/v1/receipts", async (req, res) => {
    try {
      checkRate(req, "receipts", 10000);
      const receipt = req.body.receipt as ReceiptCommitmentV1;
      const validation = validateSchema("receipt", receipt);
      if (!validation.valid) throw new RelayValidationError("TSL_SCHEMA_INVALID", "Receipt failed schema validation", validation.errors);
      assertTimestampInWindow(receipt.timestamp);
      const receiptCommitment = receiptCommitmentHash(receipt);
      const epochStartMs = Math.floor(Date.parse(receipt.timestamp) / store.epoch_duration_ms) * store.epoch_duration_ms;
      await ensureDurableReady();
      const eventKnown = Boolean((await repo?.getEvent(receipt.event_commitment)) ?? store.getAcceptedEvent(receipt.event_commitment));
      if (!eventKnown) throw new RelayValidationError("TSL_EVENT_NOT_FOUND", "Receipt references an unknown event commitment");
      await assertSignedByIdentity({
        trustId: receipt.receiver,
        signingKeyId: receipt.signing_key_id,
        timestamp: receipt.timestamp,
        hash: receiptHash(receipt),
        signature: receipt.signature,
        code: "TSL_RECEIPT_SIGNATURE_INVALID"
      });
      store.acceptReceipt(receipt);
      await repo?.insertReceipt(receipt, receiptCommitment, store.relay_id, epochStartMs);
      await queue?.publish(QUEUE_TOPICS.receiptsAccepted, { receipt_hash: receiptCommitment, receipt });
      res.json({ status: "accepted", receipt_hash: receiptCommitment, relay_id: store.relay_id, epoch_start_ms: epochStartMs });
    } catch (error) {
      sendRelayError(res, error);
    }
  });

  app.post("/v1/attestations", async (req, res) => {
    try {
      checkRate(req, "attestations", 10000);
      const attestation = req.body.attestation as AttestationV1;
      const validation = validateSchema("attestation", attestation);
      if (!validation.valid) throw new RelayValidationError("TSL_SCHEMA_INVALID", "Attestation failed schema validation", validation.errors);
      assertTimestampInWindow(attestation.issued_at);
      if (attestation.expires_at && Date.parse(attestation.expires_at) <= Date.parse(attestation.issued_at)) {
        throw new RelayValidationError("TSL_ATTESTATION_EXPIRED", "Attestation expires before or at issuance");
      }
      await assertSignedByIdentity({
        trustId: attestation.issuer,
        signingKeyId: req.body.signing_key_id ?? "#device-key-1",
        timestamp: attestation.issued_at,
        hash: attestationHash(attestation),
        signature: attestation.signature,
        code: "TSL_ATTESTATION_SIGNATURE_INVALID"
      }).catch(async () => {
        const identity = await resolver().resolveTrustID(attestation.issuer, attestation.issued_at);
        const key = identity?.verification_methods.find((method) => keyActiveAt(method, attestation.issued_at));
        if (!key || key.type !== "ed25519" || !verifyEd25519(key.public_key, attestationHash(attestation), attestation.signature)) {
          throw new RelayValidationError("TSL_ATTESTATION_SIGNATURE_INVALID", "Attestation signature failed verification");
        }
      });
      const attestationCommitment = attestationCommitmentHash(attestation);
      const epochStartMs = Math.floor(Date.parse(attestation.issued_at) / store.epoch_duration_ms) * store.epoch_duration_ms;
      store.acceptAttestation(attestation);
      await ensureDurableReady();
      await repo?.insertAttestation(attestation, store.relay_id, epochStartMs);
      await queue?.publish(QUEUE_TOPICS.attestationsAccepted, { attestation_hash: attestationCommitment, attestation });
      res.json({ status: "accepted", attestation_hash: attestationCommitment, relay_id: store.relay_id, epoch_start_ms: epochStartMs });
    } catch (error) {
      sendRelayError(res, error);
    }
  });

  app.post("/v1/keys/revoke", async (req, res) => {
    try {
      checkRate(req, "revocations", 100);
      const revocation = req.body.revocation as RevocationV1;
      const validation = validateSchema("revocation", revocation);
      if (!validation.valid) throw new RelayValidationError("TSL_SCHEMA_INVALID", "Revocation failed schema validation", validation.errors);
      assertTimestampInWindow(revocation.effective_at);
      const identity = await resolver().resolveTrustID(revocation.trust_id, revocation.effective_at);
      const key = identity ? findVerificationMethod(identity, revocation.revoked_key) ?? identity.verification_methods.find((method) => keyActiveAt(method, revocation.effective_at)) : null;
      if (!key || key.type !== "ed25519" || !verifyEd25519(key.public_key, revocationHash(revocation), revocation.signature)) {
        throw new RelayValidationError("TSL_REVOCATION_SIGNATURE_INVALID", "Revocation signature failed verification");
      }
      const revocationCommitment = revocationCommitmentHash(revocation);
      store.acceptRevocation(revocation);
      store.resolver.revokeKey(revocation.trust_id, revocation.revoked_key);
      await ensureDurableReady();
      await repo?.insertRevocation(revocation, store.relay_id, store.epoch_duration_ms);
      if (settlementBackend?.recordRevocation) {
        await settlementBackend.recordRevocation({
          trustId: revocation.trust_id,
          keyId: revocation.revoked_key,
          reason: REVOCATION_REASON_CODES[revocation.reason_class],
          effectiveAtMs: Date.parse(revocation.effective_at),
          replacementKeyId: revocation.replacement_key,
          controllerSignature: req.body.controller_signature ?? req.body.controllerSignature
        });
      }
      if (settlementBackend?.revokeIdentityKey) {
        await settlementBackend.revokeIdentityKey(revocation.trust_id, revocation.revoked_key, REVOCATION_REASON_CODES[revocation.reason_class]);
      }
      await queue?.publish(QUEUE_TOPICS.revocationsAccepted, { revocation_hash: revocationCommitment, revocation });
      res.json({ status: "accepted", revocation_hash: revocationCommitment });
    } catch (error) {
      sendRelayError(res, error);
    }
  });

  app.post("/v1/keys/rotate", async (req, res) => {
    try {
      checkRate(req, "rotations", 100);
      const revocation = req.body.revocation as RevocationV1;
      const validation = validateSchema("revocation", revocation);
      if (!validation.valid || revocation.reason_class !== "rotation" || !revocation.replacement_key) {
        throw new RelayValidationError("TSL_SCHEMA_INVALID", "Rotation requires a valid rotation revocation with replacement_key", validation.errors);
      }
      assertTimestampInWindow(revocation.effective_at);
      const identity = await resolver().resolveTrustID(revocation.trust_id, revocation.effective_at);
      const key = identity ? findVerificationMethod(identity, revocation.revoked_key) ?? identity.verification_methods.find((method) => keyActiveAt(method, revocation.effective_at)) : null;
      if (!key || key.type !== "ed25519" || !verifyEd25519(key.public_key, revocationHash(revocation), revocation.signature)) {
        throw new RelayValidationError("TSL_REVOCATION_SIGNATURE_INVALID", "Rotation revocation signature failed verification");
      }
      const revocationCommitment = revocationCommitmentHash(revocation);
      store.acceptRevocation(revocation);
      store.resolver.revokeKey(revocation.trust_id, revocation.revoked_key);
      await ensureDurableReady();
      await repo?.insertRevocation(revocation, store.relay_id, store.epoch_duration_ms);
      if (settlementBackend?.rotateIdentityKey) {
        await settlementBackend.rotateIdentityKey(revocation.trust_id, revocation.revoked_key, revocation.replacement_key);
      }
      if (settlementBackend?.recordRevocation) {
        await settlementBackend.recordRevocation({
          trustId: revocation.trust_id,
          keyId: revocation.revoked_key,
          reason: REVOCATION_REASON_CODES.rotation,
          effectiveAtMs: Date.parse(revocation.effective_at),
          replacementKeyId: revocation.replacement_key,
          controllerSignature: req.body.controller_signature ?? req.body.controllerSignature
        });
      }
      await queue?.publish(QUEUE_TOPICS.revocationsAccepted, { revocation_hash: revocationCommitment, revocation });
      res.json({ status: "accepted", rotation_hash: revocationCommitment });
    } catch (error) {
      sendRelayError(res, error);
    }
  });

  app.post("/v1/assessments", async (req, res) => {
    try {
      checkRate(req, "assessments", 1000);
      const assessment = req.body.assessment as TrustAssessmentV1;
      const validation = validateSchema("trustAssessment", assessment);
      if (!validation.valid) throw new RelayValidationError("TSL_SCHEMA_INVALID", "Assessment failed schema validation", validation.errors);
      if (!assessment.features_disclosed?.length || !assessment.explanation?.length) {
        throw new RelayValidationError("TSL_ASSESSMENT_EVIDENCE_INCOMPLETE", "Assessment requires disclosed features and explanation");
      }
      const identity = await resolver().resolveTrustID(assessment.issuer, assessment.issued_at);
      const key = identity?.verification_methods.find((method) => keyActiveAt(method, assessment.issued_at));
      if (!key || key.type !== "ed25519" || !verifyEd25519(key.public_key, assessmentHash(assessment), assessment.signature)) {
        throw new RelayValidationError("TSL_ASSESSMENT_SIGNATURE_INVALID", "Assessment signature failed verification");
      }
      const assessmentCommitment = assessmentCommitmentHash(assessment);
      await ensureDurableReady();
      await repo?.insertTrustAssessment(assessment);
      res.json({ status: "accepted", assessment_hash: assessmentCommitment });
    } catch (error) {
      sendRelayError(res, error);
    }
  });

  app.get("/v1/proofs/:commitment", async (req, res) => {
    checkRate(req, "proofs", 1000);
    await ensureDurableReady();
    const durableProof = await repo?.buildProofBundleForEvent(req.params.commitment as Hex32);
    if (durableProof) {
      res.json(durableProof);
      return;
    }
    const proof = store.proofFor(req.params.commitment as Hex32);
    if (proof) {
      res.json(proof);
      return;
    }
    const fallbackProof = await repo?.buildInclusionProofFor("event", req.params.commitment as Hex32);
    if (!fallbackProof) {
      res.status(404).json({ error: { code: "TSL_PROOF_NOT_FOUND", message: "Commitment not found" } });
      return;
    }
    res.json(fallbackProof);
  });

  app.get("/v1/proof-bundles/:bundleId", async (req, res) => {
    checkRate(req, "proof_bundles", 1000);
    await ensureDurableReady();
    const bundle = await repo?.buildProofBundleForEvent(req.params.bundleId as Hex32);
    if (!bundle) {
      res.status(404).json({ error: { code: "TSL_PROOF_NOT_FOUND", message: "Proof bundle not found" } });
      return;
    }
    res.json(bundle);
  });

  app.get("/v1/proofs/:treeKind/:commitment", async (req, res) => {
    checkRate(req, "proofs", 1000);
    const treeKind = req.params.treeKind as "event" | "receipt" | "attestation" | "revocation";
    if (!["event", "receipt", "attestation", "revocation"].includes(treeKind)) {
      res.status(400).json({ error: { code: "TSL_TREE_KIND_INVALID", message: "Unsupported tree kind" } });
      return;
    }
    await ensureDurableReady();
    const durableProof = await repo?.buildInclusionProofFor(treeKind, req.params.commitment as Hex32);
    if (!durableProof) {
      res.status(404).json({ error: { code: "TSL_PROOF_NOT_FOUND", message: "Commitment not found" } });
      return;
    }
    res.json(durableProof);
  });

  app.get("/v1/checkpoints/:epoch/:shard", async (req, res) => {
    await ensureDurableReady();
    const durable = await repo?.getCheckpoint(Number(req.params.epoch), req.params.shard);
    res.json(durable ?? store.checkpointFor(Number(req.params.epoch), req.params.shard));
  });

  app.post("/v1/checkpoints/:epoch/:shard/submit", async (req, res) => {
    try {
      checkRate(req, "checkpoint_submit", 1, store.epoch_duration_ms);
      const checkpoint = await store.submitCheckpoint(Number(req.params.epoch), req.params.shard);
      res.json({
        status: "settled",
        checkpoint
      });
    } catch (error) {
      sendRelayError(res, error);
    }
  });

  app.post("/v1/verify", async (req, res) => {
    try {
      const bundleIdentity = req.body.proof_bundle?.identity;
      const bundleResolver = bundleIdentity ? new MemoryTrustResolver([bundleIdentity]) : null;
      const resolver = repo
        ? new CompositeTrustResolver([...(bundleResolver ? [bundleResolver] : []), store.resolver, new PostgresTrustResolver(repo)])
        : bundleResolver
          ? new CompositeTrustResolver([bundleResolver, store.resolver])
          : store.resolver;
      const result = await verifyTSL(
        {
          proof_bundle: req.body.proof_bundle,
          envelope: req.body.envelope ?? req.body.proof_bundle?.envelope,
          proof: req.body.proof ?? req.body.proof_bundle?.proof,
          receipt_proofs: req.body.receipt_proofs,
          checkpoint: req.body.checkpoint ?? req.body.proof_bundle?.checkpoint,
          settlement_evidence: req.body.settlement_evidence ?? req.body.proof_bundle?.settlement_evidence,
          redaction_manifest: req.body.redaction_manifest ?? req.body.proof_bundle?.redaction_manifest,
          message_disclosure: req.body.message_disclosure ?? req.body.proof_bundle?.message_disclosure,
          receipts: req.body.receipts ?? req.body.proof_bundle?.receipts,
          attestations: req.body.attestations ?? req.body.proof_bundle?.attestations,
          revocations: req.body.revocations ?? req.body.proof_bundle?.revocations,
          assessment: req.body.assessment ?? req.body.proof_bundle?.assessment,
          assessment_v2: req.body.assessment_v2 ?? req.body.proof_bundle?.assessment_v2,
          scoring_profile: req.body.scoring_profile ?? req.body.proof_bundle?.scoring_profile,
          domain_policy: req.body.domain_policy ?? req.body.proof_bundle?.domain_policy,
          evidence_coverage: req.body.evidence_coverage ?? req.body.proof_bundle?.evidence_coverage,
          metadata_fingerprints: req.body.metadata_fingerprints ?? req.body.proof_bundle?.metadata_fingerprints,
          graph_profile: req.body.graph_profile ?? req.body.proof_bundle?.graph_profile,
          graph_feature_vector: req.body.graph_feature_vector ?? req.body.proof_bundle?.graph_feature_vector,
          trusted_seeds: req.body.trusted_seeds ?? req.body.proof_bundle?.trusted_seeds,
          adversarial_seeds: req.body.adversarial_seeds ?? req.body.proof_bundle?.adversarial_seeds,
          trusted_seed_governance: req.body.trusted_seed_governance ?? req.body.proof_bundle?.trusted_seed_governance,
          adversarial_seed_governance: req.body.adversarial_seed_governance ?? req.body.proof_bundle?.adversarial_seed_governance,
          event_receivers: req.body.event_receivers ?? req.body.proof_bundle?.event_receivers,
          sybil_assessment: req.body.sybil_assessment ?? req.body.proof_bundle?.sybil_assessment,
          sybil_profile: req.body.sybil_profile ?? req.body.proof_bundle?.sybil_profile,
          drift_report: req.body.drift_report ?? req.body.proof_bundle?.drift_report,
          drift_feature_history: req.body.drift_feature_history ?? req.body.proof_bundle?.drift_feature_history,
          drift_cohort_baseline_components: req.body.drift_cohort_baseline_components ?? req.body.proof_bundle?.drift_cohort_baseline_components,
          zk_proofs: req.body.zk_proofs ?? req.body.proof_bundle?.zk_proofs,
          zk_circuit_manifests: req.body.zk_circuit_manifests ?? req.body.proof_bundle?.zk_circuit_manifests,
          zk_verification_key_registry: req.body.zk_verification_key_registry ?? req.body.proof_bundle?.zk_verification_key_registry,
          delegations: req.body.delegations ?? req.body.proof_bundle?.delegations,
          delegation_policies: req.body.delegation_policies ?? req.body.proof_bundle?.delegation_policies,
          agent_actions: req.body.agent_actions ?? req.body.proof_bundle?.agent_actions,
          audit_findings: req.body.audit_findings ?? req.body.proof_bundle?.audit_findings,
          consistency_proofs: req.body.consistency_proofs ?? req.body.proof_bundle?.consistency_proofs,
          non_membership_proofs: req.body.non_membership_proofs ?? req.body.proof_bundle?.non_membership_proofs,
          governance_policy: req.body.governance_policy ?? req.body.proof_bundle?.governance_policy,
          disclosure_consents: req.body.disclosure_consents ?? req.body.proof_bundle?.disclosure_consents
        },
        resolver,
	        req.body.verifier_policy ?? req.body.policy ?? {
	          require_inclusion: Boolean(req.body.proof ?? req.body.proof_bundle?.proof),
	          require_checkpoint: Boolean(req.body.checkpoint ?? req.body.proof_bundle?.checkpoint),
	          require_settlement: false
	        },
        settlementBackend ?? undefined
      );
      res.status(result.verified ? 200 : 422).json(result);
    } catch (error) {
      sendRelayError(res, error);
    }
  });

  app.post("/v1/delegations/verify", async (req, res) => {
    try {
      const requestIdentities = Array.isArray(req.body.identities) ? req.body.identities : [];
      const requestResolver = requestIdentities.length ? new MemoryTrustResolver(requestIdentities) : null;
      const resolver = repo
        ? new CompositeTrustResolver([...(requestResolver ? [requestResolver] : []), store.resolver, new PostgresTrustResolver(repo)])
        : requestResolver
          ? new CompositeTrustResolver([requestResolver, store.resolver])
          : store.resolver;
      const result = await verifyTSL(
        {
          envelope: req.body.envelope,
          proof: req.body.proof,
          receipt_proofs: req.body.receipt_proofs,
          checkpoint: req.body.checkpoint,
          delegations: req.body.delegations,
          delegation_policies: req.body.delegation_policies,
          agent_actions: req.body.agent_actions,
          disclosure_consents: req.body.disclosure_consents
        },
        resolver,
        req.body.policy ?? {
          require_agent_scope: req.body.require_agent_scope ?? "inside_scope",
          require_settlement: Boolean(req.body.require_settlement)
        },
        settlementBackend ?? undefined
      );
      const inside = result.checks.delegated_action_valid === true || result.checks.agent_scope_valid === true;
      if (inside) {
        res.json({ status: "agent_inside_scope", result });
        return;
      }
      res.status(422).json({
        error: {
          code: result.errors[0] ?? "TSL_DELEGATED_ACTION_INVALID",
          message: result.errors.length ? result.errors.join("; ") : "Delegated action is outside scope"
        }
      });
    } catch (error) {
      sendRelayError(res, error);
    }
  });

  app.post("/v1/gossip/audit-finding", async (req, res) => {
    try {
      await queue?.publish(QUEUE_TOPICS.auditFindings, { finding: req.body.finding });
      res.json({ status: "accepted" });
    } catch (error) {
      sendRelayError(res, error);
    }
  });

  app.post("/v1/abuse/evidence", async (req, res) => {
    try {
      const record = {
        type: "tsl.abuse.evidence_metadata.v1",
        evidence_commitment: req.body.evidence_commitment,
        issuer: req.body.issuer,
        subject: req.body.subject,
        claim_class: req.body.claim_class,
        appeal_pointer: req.body.appeal_pointer,
        review_state: req.body.review_state ?? "pending_review",
        created_at: new Date().toISOString()
      };
      await ensureDurableReady();
      await repo?.insertAbuseEvidence(record);
      evidenceRecords.push(record);
      res.json({ status: "accepted", record });
    } catch (error) {
      sendRelayError(res, error);
    }
  });

  app.post("/v1/abuse/appeals", async (req, res) => {
    try {
      const record = {
        type: "tsl.abuse.appeal.v1",
        appeal_id: `appeal_${Date.now().toString(36)}_${appealRecords.length}`,
        subject: req.body.subject,
        evidence_commitment: req.body.evidence_commitment,
        appeal_pointer: req.body.appeal_pointer,
        review_state: "submitted",
        created_at: new Date().toISOString()
      };
      await ensureDurableReady();
      await repo?.insertAbuseAppeal(record);
      appealRecords.push(record);
      res.json({ status: "accepted", record });
    } catch (error) {
      sendRelayError(res, error);
    }
  });

  app.get("/v1/abuse/appeals", async (req, res) => {
    await ensureDurableReady();
    res.json({ appeals: repo ? await repo.listAbuseAppeals(Number(req.query.limit ?? 100)) : appealRecords });
  });

  return { app, store };
}

function sendRelayError(res: express.Response, error: unknown): void {
  if (error instanceof RelayValidationError) {
    res.status(422).json({
      error: {
        code: error.code,
        message: error.message,
        details: error.details
      }
    });
    return;
  }
  res.status(400).json({
    error: {
      code: "TSL_REQUEST_INVALID",
      message: error instanceof Error ? error.message : "Invalid relay request"
    }
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT ?? 8080);
  createRelayNode().app.listen(port, () => {
    process.stdout.write(`tsl relay-node listening on http://localhost:${port}\n`);
  });
}
