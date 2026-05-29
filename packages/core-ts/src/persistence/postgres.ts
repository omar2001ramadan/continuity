import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import pg from "pg";
import { canonicalBytes } from "../canonicalize";
import {
  assessmentCommitmentHash,
  attestationCommitmentHash,
  commitmentHash,
  hashDomain,
  DOMAIN_TAGS,
  revocationCommitmentHash,
  sha256Hex,
  ZERO_HASH
} from "../crypto";
import { buildInclusionProof, buildMerkleTree } from "../merkle";
import { filterProofBundleDisclosures, type ProofBundleDisclosureOptions } from "../proofBundle";
import { checkpointHash, shardForTrustID } from "../relayStore";
import type {
  AttestationV1,
  BatchCheckpointV1,
  EventCommitmentV1,
  Hex32,
  IdentityDocumentV1,
  InclusionProofV1,
  ProofBundleV1,
  ReceiptCommitmentV1,
  RevocationV1,
  TrustAssessmentV1,
  TrustAssessmentV2,
  ScoringProfileV2,
  EvidenceCoverageV1,
  AuditFindingV1
} from "../types";
import { scoringProfileV2Hash, trustAssessmentV2Hash } from "../v2";

const { Pool } = pg;

export class PostgresRepository {
  readonly pool: pg.Pool;

  constructor(readonly databaseUrl: string) {
    this.pool = new Pool({ connectionString: databaseUrl });
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  async migrate(migrationsDir = "infra/db/migrations"): Promise<void> {
    await this.pool.query("CREATE TABLE IF NOT EXISTS schema_migrations (filename TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())");
    const files = readdirSync(migrationsDir).filter((file) => file.endsWith(".sql")).sort();
    for (const file of files) {
      const existing = await this.pool.query("SELECT 1 FROM schema_migrations WHERE filename = $1", [file]);
      if (existing.rowCount) continue;
      const sql = readFileSync(join(migrationsDir, file), "utf8");
      await this.pool.query("BEGIN");
      try {
        await this.pool.query(sql);
        await this.pool.query("INSERT INTO schema_migrations(filename) VALUES ($1)", [file]);
        await this.pool.query("COMMIT");
      } catch (error) {
        await this.pool.query("ROLLBACK");
        throw error;
      }
    }
  }

  async upsertIdentity(identity: IdentityDocumentV1): Promise<void> {
    const identityHash = hashDomain(DOMAIN_TAGS.IDENTITY_V1, canonicalBytes(identity));
    await this.pool.query(
      `INSERT INTO trust_identities(trust_id, controller, created_at, identity_document, identity_hash)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (trust_id) DO UPDATE SET
         controller = EXCLUDED.controller,
         identity_document = EXCLUDED.identity_document,
         identity_hash = EXCLUDED.identity_hash`,
      [identity.id, identity.controller, identity.created_at, identity, identityHash]
    );
    for (const key of identity.verification_methods) {
      await this.pool.query(
        `INSERT INTO verification_keys(trust_id, key_id, key_type, public_key, status, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (trust_id, key_id) DO UPDATE SET
           key_type = EXCLUDED.key_type,
           public_key = EXCLUDED.public_key,
           status = EXCLUDED.status,
           expires_at = EXCLUDED.expires_at`,
        [identity.id, key.id, key.type, key.public_key, key.status, key.created_at, key.expires_at ?? null]
      );
    }
  }

  async getIdentity(trustId: string): Promise<IdentityDocumentV1 | null> {
    const result = await this.pool.query("SELECT identity_document FROM trust_identities WHERE trust_id = $1", [trustId]);
    const identity = (result.rows[0]?.identity_document as IdentityDocumentV1 | undefined) ?? null;
    if (!identity) return null;
    const keys = await this.pool.query(
      "SELECT key_id, key_type, public_key, status, created_at, expires_at, revoked_at FROM verification_keys WHERE trust_id = $1 ORDER BY key_id",
      [trustId]
    );
    if (keys.rows.length === 0) return identity;
    return {
      ...identity,
      verification_methods: keys.rows.map((row) => ({
        id: row.key_id,
        type: row.key_type,
        public_key: row.public_key,
        status: row.status,
        created_at: new Date(row.created_at).toISOString(),
        ...(row.expires_at ? { expires_at: new Date(row.expires_at).toISOString() } : {}),
        ...(row.revoked_at ? { revoked_at: new Date(row.revoked_at).toISOString() } : {})
      }))
    };
  }

  async getEvent(commitmentHash: Hex32): Promise<EventCommitmentV1 | null> {
    const result = await this.pool.query("SELECT canonical_body FROM event_commitments WHERE commitment_hash = $1", [commitmentHash]);
    const body = result.rows[0]?.canonical_body;
    return body ? (JSON.parse(Buffer.from(body).toString("utf8")) as EventCommitmentV1) : null;
  }

  private async assertSegmentOpen(epochStartMs: number, shard: string): Promise<void> {
    const closed = await this.pool.query("SELECT checkpoint_hash FROM checkpoints WHERE epoch_start_ms = $1 AND shard = $2 LIMIT 1", [epochStartMs, shard]);
    if (closed.rows.length > 0) {
      throw new Error("TSL_LOG_SEGMENT_CLOSED");
    }
  }

  async insertEvent(event: EventCommitmentV1, relayId: string, epochStartMs: number, epochDurationMs: number): Promise<Hex32> {
    const hash = commitmentHash(event);
    const shard = shardForTrustID(event.sender);
    await this.assertSegmentOpen(epochStartMs, shard);
    await this.pool.query(
      `INSERT INTO event_commitments(
        commitment_hash, sender_trust_id, signing_key_id, event_class, content_commitment,
        receiver_commitment, metadata_commitment, previous_event_commitment, event_timestamp,
        nonce, disclosure_policy, canonical_body, signature, relay_id, shard, epoch_start_ms
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
      ON CONFLICT (commitment_hash) DO NOTHING`,
      [
        hash,
        event.sender,
        event.signing_key_id,
        event.event_class,
        event.content_commitment,
        event.receiver_commitment ?? null,
        event.metadata_commitment ?? null,
        event.previous_event_commitment ?? null,
        event.timestamp,
        event.nonce,
        event.disclosure_policy,
        Buffer.from(canonicalBytes(event)),
        event.signature,
        relayId,
        shard,
        epochStartMs
      ]
    );
    return hash;
  }

  async insertReceipt(receipt: ReceiptCommitmentV1, receiptHash: Hex32, relayId: string, epochStartMs: number): Promise<void> {
    const shard = shardForTrustID(receipt.receiver);
    await this.assertSegmentOpen(epochStartMs, shard);
    await this.pool.query(
      `INSERT INTO receipt_commitments(
        receipt_hash, event_commitment, receiver_trust_id, signing_key_id, receipt_class,
        receipt_timestamp, metadata_commitment, canonical_body, signature, relay_id, shard, epoch_start_ms
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
      ON CONFLICT (receipt_hash) DO NOTHING`,
      [
        receiptHash,
        receipt.event_commitment,
        receipt.receiver,
        receipt.signing_key_id,
        receipt.receipt_class,
        receipt.timestamp,
        receipt.metadata_commitment ?? null,
        Buffer.from(canonicalBytes(receipt)),
        receipt.signature,
        relayId,
        shard,
        epochStartMs
      ]
    );
  }

  async insertAttestation(attestation: AttestationV1, relayId: string, epochStartMs: number): Promise<Hex32> {
    const hash = attestationCommitmentHash(attestation);
    const shard = shardForTrustID(attestation.issuer);
    await this.assertSegmentOpen(epochStartMs, shard);
    await this.pool.query(
      `INSERT INTO attestations(
        attestation_hash, issuer_trust_id, subject_trust_id, attestation_class, visibility,
        issued_at, expires_at, claim_commitment, canonical_body, signature, relay_id, shard, epoch_start_ms
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
      ON CONFLICT (attestation_hash) DO NOTHING`,
      [
        hash,
        attestation.issuer,
        attestation.subject,
        attestation.attestation_class,
        attestation.visibility,
        attestation.issued_at,
        attestation.expires_at ?? null,
        attestation.claim_commitment,
        Buffer.from(canonicalBytes(attestation)),
        attestation.signature,
        relayId,
        shard,
        epochStartMs
      ]
    );
    return hash;
  }

  async insertRevocation(revocation: RevocationV1, relayId = "did:tsl:relay:unknown", epochDurationMs = 300000): Promise<Hex32> {
    const hash = revocationCommitmentHash(revocation);
    const shard = shardForTrustID(revocation.trust_id);
    const epochStartMs = Math.floor(Date.parse(revocation.effective_at) / epochDurationMs) * epochDurationMs;
    await this.assertSegmentOpen(epochStartMs, shard);
    await this.pool.query(
      `INSERT INTO revocations(
        revocation_hash, trust_id, key_id, reason_class, effective_at,
        replacement_key_id, canonical_body, signature, relay_id, shard, epoch_start_ms
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      ON CONFLICT (revocation_hash) DO NOTHING`,
      [
        hash,
        revocation.trust_id,
        revocation.revoked_key,
        revocation.reason_class,
        revocation.effective_at,
        revocation.replacement_key ?? null,
        Buffer.from(canonicalBytes(revocation)),
        revocation.signature,
        relayId,
        shard,
        epochStartMs
      ]
    );
    await this.pool.query(
      `UPDATE verification_keys
       SET status = 'revoked', revoked_at = $3, revocation_reason = $4
       WHERE trust_id = $1 AND key_id = $2`,
      [revocation.trust_id, revocation.revoked_key, revocation.effective_at, revocation.reason_class]
    );
    return hash;
  }

  async insertTrustAssessment(assessment: TrustAssessmentV1): Promise<Hex32> {
    const hash = assessmentCommitmentHash(assessment);
    await this.pool.query(
      `INSERT INTO trust_assessments(
        assessment_hash, subject_trust_id, issuer_provider_id, score_bps, label,
        model_version, evidence_commitment, issued_at, expires_at, canonical_body, signature
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      ON CONFLICT (assessment_hash) DO NOTHING`,
      [
        hash,
        assessment.subject,
        assessment.issuer,
        assessment.score_bps,
        assessment.label,
        assessment.model_version,
        assessment.evidence_commitment,
        assessment.issued_at,
        assessment.expires_at,
        Buffer.from(canonicalBytes(assessment)),
        assessment.signature
      ]
    );
    return hash;
  }

  async upsertScoringProfileV2(profile: ScoringProfileV2): Promise<Hex32> {
    const hash = scoringProfileV2Hash(profile);
    await this.pool.query(
      `INSERT INTO scoring_profiles_v2(
        profile_id, provider_id, domain, model_version, profile_hash,
        evaluation_report_commitment, issued_at, expires_at, canonical_body, signature
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
      ON CONFLICT (profile_id) DO UPDATE SET
        provider_id = EXCLUDED.provider_id,
        domain = EXCLUDED.domain,
        model_version = EXCLUDED.model_version,
        profile_hash = EXCLUDED.profile_hash,
        evaluation_report_commitment = EXCLUDED.evaluation_report_commitment,
        issued_at = EXCLUDED.issued_at,
        expires_at = EXCLUDED.expires_at,
        canonical_body = EXCLUDED.canonical_body,
        signature = EXCLUDED.signature`,
      [
        profile.profile_id,
        profile.provider,
        profile.domain,
        profile.model_version,
        hash,
        profile.evaluation_report_commitment,
        profile.issued_at,
        profile.expires_at,
        Buffer.from(canonicalBytes(profile)),
        profile.signature
      ]
    );
    return hash;
  }

  async getScoringProfileV2(profileId: string): Promise<ScoringProfileV2 | null> {
    const result = await this.pool.query("SELECT canonical_body FROM scoring_profiles_v2 WHERE profile_id = $1", [profileId]);
    const body = result.rows[0]?.canonical_body;
    return body ? (JSON.parse(Buffer.from(body).toString("utf8")) as ScoringProfileV2) : null;
  }

  async listScoringProfilesV2(limit = 100): Promise<ScoringProfileV2[]> {
    const result = await this.pool.query("SELECT canonical_body FROM scoring_profiles_v2 ORDER BY issued_at DESC LIMIT $1", [limit]);
    return result.rows.map((row) => JSON.parse(Buffer.from(row.canonical_body).toString("utf8")) as ScoringProfileV2);
  }

  async upsertEvidenceCoverageV1(coverage: EvidenceCoverageV1): Promise<Hex32> {
    const hash = sha256Hex(canonicalBytes(coverage));
    await this.pool.query(
      `INSERT INTO evidence_coverage_v1(
        coverage_hash, subject_trust_id, signed_event_count, reciprocal_receipt_count,
        unique_counterparty_count, trusted_counterparty_mass_bps, coverage_bps,
        computed_at, canonical_body
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
      ON CONFLICT (coverage_hash) DO UPDATE SET canonical_body = EXCLUDED.canonical_body`,
      [
        hash,
        coverage.subject,
        coverage.valid_signed_event_count,
        coverage.valid_receipt_count,
        coverage.unique_counterparty_count,
        0,
        coverage.coverage_bps,
        coverage.computed_at,
        Buffer.from(canonicalBytes(coverage))
      ]
    );
    return hash;
  }

  async getEvidenceCoverageV1(coverageHash: Hex32): Promise<EvidenceCoverageV1 | null> {
    const result = await this.pool.query("SELECT canonical_body FROM evidence_coverage_v1 WHERE coverage_hash = $1", [coverageHash]);
    const body = result.rows[0]?.canonical_body;
    return body ? (JSON.parse(Buffer.from(body).toString("utf8")) as EvidenceCoverageV1) : null;
  }

  async insertTrustAssessmentV2(assessment: TrustAssessmentV2): Promise<Hex32> {
    const hash = trustAssessmentV2Hash(assessment);
    await this.pool.query(
      `INSERT INTO trust_assessments_v2(
        assessment_hash, subject_trust_id, provider_id, profile_id, score_bps,
        confidence_low_bps, confidence_high_bps, risk_label, evidence_coverage_hash,
        evidence_commitment, issued_at, expires_at, canonical_body, signature
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
      ON CONFLICT (assessment_hash) DO UPDATE SET canonical_body = EXCLUDED.canonical_body`,
      [
        hash,
        assessment.subject,
        assessment.issuer,
        assessment.scoring_profile_id,
        assessment.score_bps ?? null,
        assessment.confidence_interval_bps?.[0] ?? null,
        assessment.confidence_interval_bps?.[1] ?? null,
        assessment.label,
        assessment.evidence_coverage_commitment ?? null,
        assessment.feature_vector_commitment ?? null,
        assessment.issued_at,
        assessment.expires_at,
        Buffer.from(canonicalBytes(assessment)),
        assessment.signature
      ]
    );
    return hash;
  }

  async getTrustAssessmentV2(assessmentIdOrHash: string): Promise<TrustAssessmentV2 | null> {
    const direct = await this.pool.query("SELECT canonical_body FROM trust_assessments_v2 WHERE assessment_hash = $1 LIMIT 1", [assessmentIdOrHash]);
    const rows =
      direct.rows.length > 0
        ? direct.rows
        : (await this.pool.query("SELECT canonical_body FROM trust_assessments_v2 ORDER BY issued_at DESC LIMIT 1000")).rows;
    for (const row of rows) {
      const assessment = JSON.parse(Buffer.from(row.canonical_body).toString("utf8")) as TrustAssessmentV2;
      if (assessment.assessment_id === assessmentIdOrHash || trustAssessmentV2Hash(assessment) === assessmentIdOrHash) return assessment;
    }
    return null;
  }

  async upsertModelCardV2(modelCard: Record<string, unknown>): Promise<Hex32> {
    const hash = sha256Hex(canonicalBytes(modelCard));
    await this.pool.query(
      `INSERT INTO model_cards_v2(
        model_id, provider_id, model_version, model_card_hash, evaluation_report_commitment,
        privacy_report_commitment, issued_at, canonical_body, signature
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
      ON CONFLICT (model_id) DO UPDATE SET
        provider_id = EXCLUDED.provider_id,
        model_version = EXCLUDED.model_version,
        model_card_hash = EXCLUDED.model_card_hash,
        evaluation_report_commitment = EXCLUDED.evaluation_report_commitment,
        privacy_report_commitment = EXCLUDED.privacy_report_commitment,
        issued_at = EXCLUDED.issued_at,
        canonical_body = EXCLUDED.canonical_body,
        signature = EXCLUDED.signature`,
      [
        modelCard.model_id,
        modelCard.provider,
        modelCard.model_version,
        hash,
        modelCard.evaluation_report_commitment,
        modelCard.privacy_report_commitment,
        modelCard.issued_at,
        Buffer.from(canonicalBytes(modelCard)),
        modelCard.signature
      ]
    );
    return hash;
  }

  async getModelCardV2(modelId: string): Promise<Record<string, unknown> | null> {
    const result = await this.pool.query("SELECT canonical_body FROM model_cards_v2 WHERE model_id = $1", [modelId]);
    const body = result.rows[0]?.canonical_body;
    return body ? (JSON.parse(Buffer.from(body).toString("utf8")) as Record<string, unknown>) : null;
  }

  async upsertEvaluationReportV1(report: Record<string, unknown>): Promise<Hex32> {
    const hash = sha256Hex(canonicalBytes(report));
    const metrics = (report.metrics ?? {}) as Record<string, unknown>;
    await this.pool.query(
      `INSERT INTO evaluation_reports_v1(
        report_id, model_id, domain, auroc_bps, auprc_bps, ece_bps, privacy_leakage_bps,
        promotion_gate_result, issued_at, canonical_body, signature
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      ON CONFLICT (report_id) DO UPDATE SET
        model_id = EXCLUDED.model_id,
        domain = EXCLUDED.domain,
        auroc_bps = EXCLUDED.auroc_bps,
        auprc_bps = EXCLUDED.auprc_bps,
        ece_bps = EXCLUDED.ece_bps,
        privacy_leakage_bps = EXCLUDED.privacy_leakage_bps,
        promotion_gate_result = EXCLUDED.promotion_gate_result,
        issued_at = EXCLUDED.issued_at,
        canonical_body = EXCLUDED.canonical_body,
        signature = EXCLUDED.signature`,
      [
        report.report_id,
        report.model_id,
        report.domain,
        metrics.auroc_bps ?? null,
        metrics.auprc_bps ?? null,
        metrics.ece_bps ?? null,
        metrics.privacy_leakage_bps ?? null,
        report.promotion_gate_result,
        report.issued_at,
        Buffer.from(canonicalBytes(report)),
        report.signature
      ]
    );
    return hash;
  }

  async getEvaluationReportV1(reportId: string): Promise<Record<string, unknown> | null> {
    const result = await this.pool.query("SELECT canonical_body FROM evaluation_reports_v1 WHERE report_id = $1", [reportId]);
    const body = result.rows[0]?.canonical_body;
    return body ? (JSON.parse(Buffer.from(body).toString("utf8")) as Record<string, unknown>) : null;
  }

  async insertAuditFinding(finding: AuditFindingV1): Promise<Hex32> {
    const hash = hashDomain(DOMAIN_TAGS.AUDIT_FINDING_V1, canonicalBytes(finding));
    await this.pool.query(
      `INSERT INTO audit_findings(
        finding_hash, auditor, finding_class, severity, checkpoint_hash, epoch_start_ms, shard,
        evidence_commitment, canonical_body, signature, issued_at
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      ON CONFLICT (finding_hash) DO NOTHING`,
      [
        hash,
        finding.auditor,
        finding.finding_class,
        finding.severity,
        finding.checkpoint_hash ?? null,
        finding.epoch_start_ms ?? null,
        finding.shard ?? null,
        finding.evidence_commitment,
        Buffer.from(canonicalBytes(finding)),
        finding.signature,
        finding.issued_at
      ]
    );
    return hash;
  }

  async listAuditFindings(limit = 100, checkpointHashFilter?: Hex32): Promise<AuditFindingV1[]> {
    const result = await this.pool.query(
      `SELECT canonical_body
         FROM audit_findings
        WHERE ($2::text IS NULL OR checkpoint_hash = $2)
        ORDER BY accepted_at DESC
        LIMIT $1`,
      [limit, checkpointHashFilter ?? null]
    );
    return result.rows.map((row) => JSON.parse(Buffer.from(row.canonical_body).toString("utf8")) as AuditFindingV1);
  }

  async upsertGossipPeer(peerUrl: string): Promise<void> {
    await this.pool.query(
      `INSERT INTO gossip_peers(peer_url)
       VALUES ($1)
       ON CONFLICT (peer_url) DO UPDATE SET updated_at = now()`,
      [peerUrl]
    );
  }

  async listGossipPeers(): Promise<string[]> {
    const result = await this.pool.query("SELECT peer_url FROM gossip_peers ORDER BY updated_at DESC");
    return result.rows.map((row) => row.peer_url as string);
  }

  async insertAbuseEvidence(record: Record<string, unknown>): Promise<void> {
    await this.pool.query(
      `INSERT INTO abuse_evidence(evidence_commitment, issuer, subject, claim_class, appeal_pointer, review_state, metadata)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (evidence_commitment) DO UPDATE SET
         appeal_pointer = EXCLUDED.appeal_pointer,
         review_state = EXCLUDED.review_state,
         metadata = EXCLUDED.metadata`,
      [
        record.evidence_commitment,
        record.issuer ?? null,
        record.subject ?? null,
        record.claim_class ?? null,
        record.appeal_pointer ?? null,
        record.review_state ?? "pending_review",
        record
      ]
    );
  }

  async insertAbuseAppeal(record: Record<string, unknown>): Promise<void> {
    await this.pool.query(
      `INSERT INTO abuse_appeals(appeal_id, subject, evidence_commitment, appeal_pointer, review_state, metadata)
       VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT (appeal_id) DO UPDATE SET review_state = EXCLUDED.review_state, metadata = EXCLUDED.metadata`,
      [
        record.appeal_id,
        record.subject ?? null,
        record.evidence_commitment ?? null,
        record.appeal_pointer ?? null,
        record.review_state ?? "submitted",
        record
      ]
    );
  }

  async listAbuseAppeals(limit = 100): Promise<Record<string, unknown>[]> {
    const result = await this.pool.query("SELECT metadata FROM abuse_appeals ORDER BY created_at DESC LIMIT $1", [limit]);
    return result.rows.map((row) => row.metadata as Record<string, unknown>);
  }

  async getRevocations(trustId: string): Promise<RevocationV1[]> {
    const result = await this.pool.query("SELECT canonical_body FROM revocations WHERE trust_id = $1 ORDER BY effective_at", [trustId]);
    return result.rows.map((row) => JSON.parse(Buffer.from(row.canonical_body).toString("utf8")) as RevocationV1);
  }

  async getReceiptsForEvent(eventCommitment: Hex32): Promise<ReceiptCommitmentV1[]> {
    const result = await this.pool.query("SELECT canonical_body FROM receipt_commitments WHERE event_commitment = $1 ORDER BY accepted_at", [eventCommitment]);
    return result.rows.map((row) => JSON.parse(Buffer.from(row.canonical_body).toString("utf8")) as ReceiptCommitmentV1);
  }

  async getAttestationsForSubject(subjectTrustId: string): Promise<AttestationV1[]> {
    const result = await this.pool.query("SELECT canonical_body FROM attestations WHERE subject_trust_id = $1 ORDER BY issued_at DESC", [subjectTrustId]);
    return result.rows.map((row) => JSON.parse(Buffer.from(row.canonical_body).toString("utf8")) as AttestationV1);
  }

  async getLatestAssessmentForSubject(subjectTrustId: string): Promise<TrustAssessmentV1 | null> {
    const result = await this.pool.query(
      "SELECT canonical_body FROM trust_assessments WHERE subject_trust_id = $1 ORDER BY issued_at DESC LIMIT 1",
      [subjectTrustId]
    );
    const body = result.rows[0]?.canonical_body;
    return body ? (JSON.parse(Buffer.from(body).toString("utf8")) as TrustAssessmentV1) : null;
  }

  async buildProofBundleForEvent(commitment: Hex32, disclosureOptions: ProofBundleDisclosureOptions = {}): Promise<ProofBundleV1 | null> {
    const proof = await this.buildInclusionProofFor("event", commitment);
    const envelope = await this.getEvent(commitment);
    if (!proof || !envelope) return null;
    const identity = await this.getIdentity(envelope.sender);
    const receipts = await this.getReceiptsForEvent(commitment);
    const attestations = await this.getAttestationsForSubject(envelope.sender);
    const revocations = await this.getRevocations(envelope.sender);
    const assessment = await this.getLatestAssessmentForSubject(envelope.sender);
    const bundle: ProofBundleV1 = {
      type: "tsl.proof_bundle.v1",
      bundle_id: commitment,
      created_at: envelope.timestamp,
      identity: identity ?? {
        type: "tsl.identity.v1",
        id: envelope.sender,
        controller: envelope.sender,
        created_at: envelope.timestamp,
        verification_methods: []
      },
      envelope,
      ...proof,
      receipts,
      attestations,
      revocations,
      redaction_manifest: {
        raw_content_included: false,
        exact_counterparties_included: false,
        metadata_fields_redacted: ["raw_content", "content_salt", "exact_counterparties", "platform", "ip_address", "user_agent"]
      },
      ...(assessment ? { assessment } : {})
    };
    return filterProofBundleDisclosures(bundle, disclosureOptions);
  }

  async insertCheckpoint(checkpoint: BatchCheckpointV1, status = "pending"): Promise<Hex32> {
    const hash = checkpointHash(checkpoint);
    const previous = await this.pool.query(
      `SELECT checkpoint_hash FROM checkpoints
       WHERE shard = $1 AND epoch_start_ms < $2
       ORDER BY epoch_start_ms DESC
       LIMIT 1`,
      [checkpoint.shard, checkpoint.epoch_start_ms]
    );
    const expectedPrevious = (previous.rows[0]?.checkpoint_hash as Hex32 | undefined) ?? ZERO_HASH;
    if (checkpoint.previous_checkpoint !== expectedPrevious) {
      throw new Error("TSL_CHECKPOINT_CHAIN_BROKEN");
    }
    const next = await this.pool.query(
      `SELECT previous_checkpoint FROM checkpoints
       WHERE shard = $1 AND epoch_start_ms > $2
       ORDER BY epoch_start_ms ASC
       LIMIT 1`,
      [checkpoint.shard, checkpoint.epoch_start_ms]
    );
    if (next.rows[0]?.previous_checkpoint && next.rows[0].previous_checkpoint !== hash) {
      throw new Error("TSL_CHECKPOINT_CHAIN_BROKEN");
    }
    const inserted = await this.pool.query(
      `INSERT INTO checkpoints(
        checkpoint_hash, epoch_start_ms, epoch_duration_ms, shard, event_root, receipt_root,
        attestation_root, revocation_root, event_count, receipt_count, previous_checkpoint,
        relay_id, relay_signature, settlement_backend, settlement_tx, settlement_status
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
      ON CONFLICT (epoch_start_ms, shard) DO NOTHING`,
      [
        hash,
        checkpoint.epoch_start_ms,
        checkpoint.epoch_duration_ms,
        checkpoint.shard,
        checkpoint.event_root,
        checkpoint.receipt_root,
        checkpoint.attestation_root,
        checkpoint.revocation_root,
        checkpoint.event_count,
        checkpoint.receipt_count,
        checkpoint.previous_checkpoint,
        checkpoint.relay_id,
        checkpoint.relay_signature,
        checkpoint.settlement_backend ?? null,
        checkpoint.settlement_tx ?? null,
        status
      ]
    );
    if (inserted.rowCount === 0) {
      const existing = await this.pool.query(
        "SELECT checkpoint_hash FROM checkpoints WHERE epoch_start_ms = $1 AND shard = $2",
        [checkpoint.epoch_start_ms, checkpoint.shard]
      );
      if (existing.rows[0]?.checkpoint_hash !== hash) {
        throw new Error("TSL_CHECKPOINT_CONFLICT");
      }
      if (checkpoint.settlement_tx || status === "settled") {
        await this.markCheckpointSettled(checkpoint);
      }
    }
    return hash;
  }

  async getCheckpoint(epochStartMs: number, shard: string): Promise<BatchCheckpointV1 | null> {
    const result = await this.pool.query("SELECT * FROM checkpoints WHERE epoch_start_ms = $1 AND shard = $2", [epochStartMs, shard]);
    const row = result.rows[0];
    if (!row) return null;
    const checkpoint: BatchCheckpointV1 = {
      type: "tsl.batch_checkpoint.v1",
      epoch_start_ms: Number(row.epoch_start_ms),
      epoch_duration_ms: Number(row.epoch_duration_ms),
      shard: row.shard,
      event_root: row.event_root,
      receipt_root: row.receipt_root,
      attestation_root: row.attestation_root,
      revocation_root: row.revocation_root,
      event_count: Number(row.event_count),
      receipt_count: Number(row.receipt_count),
      previous_checkpoint: row.previous_checkpoint,
      settlement_backend: row.settlement_backend ?? undefined,
      settlement_tx: row.settlement_tx ?? undefined,
      relay_id: row.relay_id,
      relay_signature: row.relay_signature
    };
    checkpoint.checkpoint_identity_hash = row.checkpoint_hash ?? checkpointHash(checkpoint);
    return checkpoint;
  }

  async buildInclusionProofFor(treeKind: "event" | "receipt" | "attestation" | "revocation", commitment: Hex32): Promise<{
    proof: InclusionProofV1;
    checkpoint: BatchCheckpointV1;
  } | null> {
    const table =
      treeKind === "event"
        ? { name: "event_commitments", hash: "commitment_hash" }
        : treeKind === "receipt"
          ? { name: "receipt_commitments", hash: "receipt_hash" }
          : treeKind === "attestation"
            ? { name: "attestations", hash: "attestation_hash" }
            : { name: "revocations", hash: "revocation_hash" };
    const located = await this.pool.query(
      `SELECT epoch_start_ms, shard FROM ${table.name} WHERE ${table.hash} = $1`,
      [commitment]
    );
    const row = located.rows[0];
    if (!row) return null;
    const items = await this.pool.query(
      `SELECT ${table.hash} AS hash FROM ${table.name} WHERE epoch_start_ms = $1 AND shard = $2 ORDER BY log_index NULLS LAST, accepted_at`,
      [row.epoch_start_ms, row.shard]
    );
    const commitments = items.rows.map((item) => item.hash as Hex32);
    const leafIndex = commitments.indexOf(commitment);
    if (leafIndex < 0) return null;
    const checkpoint = await this.getCheckpoint(Number(row.epoch_start_ms), row.shard);
    if (!checkpoint) return null;
    return {
      checkpoint,
      proof: buildInclusionProof({
        commitments,
        leaf_index: leafIndex,
        tree_kind: treeKind,
        epoch_start_ms: checkpoint.epoch_start_ms,
        epoch_duration_ms: checkpoint.epoch_duration_ms,
        shard: checkpoint.shard,
        checkpoint_hash: checkpointHash(checkpoint)
      })
    };
  }

  async buildConsistencyProofFor(epochStartMs: number, shard: string): Promise<import("../types").ConsistencyProofV1 | null> {
    const result = await this.pool.query(
      `SELECT *
         FROM checkpoints
        WHERE shard = $1 AND epoch_start_ms <= $2
        ORDER BY epoch_start_ms ASC`,
      [shard, epochStartMs]
    );
    if (result.rows.length < 2) return null;
    const checkpoints = result.rows.map((row) => ({
      type: "tsl.batch_checkpoint.v1" as const,
      epoch_start_ms: Number(row.epoch_start_ms),
      epoch_duration_ms: Number(row.epoch_duration_ms),
      shard: row.shard,
      event_root: row.event_root,
      receipt_root: row.receipt_root,
      attestation_root: row.attestation_root,
      revocation_root: row.revocation_root,
      event_count: Number(row.event_count),
      receipt_count: Number(row.receipt_count),
      previous_checkpoint: row.previous_checkpoint,
      settlement_backend: row.settlement_backend ?? undefined,
      settlement_tx: row.settlement_tx ?? undefined,
      relay_id: row.relay_id,
      relay_signature: row.relay_signature
    }));
    const { buildConsistencyProof } = await import("../consistency");
    return buildConsistencyProof(checkpoints);
  }

  async assignLogIndexes(epochStartMs: number, shard: string): Promise<void> {
    const tables = [
      { name: "event_commitments", hash: "commitment_hash" },
      { name: "receipt_commitments", hash: "receipt_hash" },
      { name: "attestations", hash: "attestation_hash" },
      { name: "revocations", hash: "revocation_hash" }
    ];
    for (const table of tables) {
      await this.pool.query(
        `WITH ordered AS (
           SELECT ${table.hash}, row_number() OVER (ORDER BY accepted_at, ${table.hash}) - 1 AS next_index
           FROM ${table.name}
           WHERE epoch_start_ms = $1 AND shard = $2
         )
         UPDATE ${table.name} target
            SET log_index = ordered.next_index
           FROM ordered
          WHERE target.${table.hash} = ordered.${table.hash}`,
        [epochStartMs, shard]
      );
    }
  }

  async persistMerkleNodes(epochStartMs: number, shard: string, treeKind: "event" | "receipt" | "attestation" | "revocation", levels: Hex32[][]): Promise<void> {
    const closed = await this.pool.query("SELECT checkpoint_hash FROM checkpoints WHERE epoch_start_ms = $1 AND shard = $2 LIMIT 1", [epochStartMs, shard]);
    if (closed.rows.length > 0) {
      throw new Error("TSL_LOG_SEGMENT_CLOSED");
    }
    await this.pool.query("DELETE FROM merkle_nodes WHERE epoch_start_ms = $1 AND shard = $2 AND tree_kind = $3", [epochStartMs, shard, treeKind]);
    for (let level = 0; level < levels.length; level += 1) {
      for (let nodeIndex = 0; nodeIndex < levels[level].length; nodeIndex += 1) {
        await this.pool.query(
          `INSERT INTO merkle_nodes(epoch_start_ms, shard, tree_kind, level, node_index, node_hash)
           VALUES ($1,$2,$3,$4,$5,$6)
           ON CONFLICT (epoch_start_ms, shard, tree_kind, level, node_index)
           DO UPDATE SET node_hash = EXCLUDED.node_hash`,
          [epochStartMs, shard, treeKind, level, nodeIndex, levels[level][nodeIndex]]
        );
      }
    }
  }

  private async previousCheckpointHash(epochStartMs: number, shard: string): Promise<Hex32> {
    const result = await this.pool.query(
      `SELECT checkpoint_hash
         FROM checkpoints
        WHERE shard = $1 AND epoch_start_ms < $2
        ORDER BY epoch_start_ms DESC
        LIMIT 1`,
      [shard, epochStartMs]
    );
    return (result.rows[0]?.checkpoint_hash as Hex32 | undefined) ?? ZERO_HASH;
  }

  async buildCheckpoint(epochStartMs: number, shard: string, epochDurationMs: number, relayId: string, relaySignature: string, settlementBackend?: string): Promise<BatchCheckpointV1> {
    const closed = await this.pool.query("SELECT checkpoint_hash FROM checkpoints WHERE epoch_start_ms = $1 AND shard = $2 LIMIT 1", [epochStartMs, shard]);
    if (closed.rows.length > 0) {
      throw new Error("TSL_LOG_SEGMENT_CLOSED");
    }
    await this.assignLogIndexes(epochStartMs, shard);
    const events = await this.pool.query(
      "SELECT commitment_hash FROM event_commitments WHERE epoch_start_ms = $1 AND shard = $2 ORDER BY log_index, accepted_at",
      [epochStartMs, shard]
    );
    const receipts = await this.pool.query(
      "SELECT receipt_hash FROM receipt_commitments WHERE epoch_start_ms = $1 AND shard = $2 ORDER BY log_index, accepted_at",
      [epochStartMs, shard]
    );
    const attestations = await this.pool.query(
      "SELECT attestation_hash FROM attestations WHERE epoch_start_ms = $1 AND shard = $2 ORDER BY log_index, accepted_at",
      [epochStartMs, shard]
    );
    const revocations = await this.pool.query(
      "SELECT revocation_hash FROM revocations WHERE epoch_start_ms = $1 AND shard = $2 ORDER BY log_index, accepted_at",
      [epochStartMs, shard]
    );
    const eventCommitments = events.rows.map((row) => row.commitment_hash as Hex32);
    const receiptCommitments = receipts.rows.map((row) => row.receipt_hash as Hex32);
    const attestationCommitments = attestations.rows.map((row) => row.attestation_hash as Hex32);
    const revocationCommitments = revocations.rows.map((row) => row.revocation_hash as Hex32);
    const eventTree = buildMerkleTree(eventCommitments);
    const receiptTree = buildMerkleTree(receiptCommitments);
    const attestationTree = buildMerkleTree(attestationCommitments);
    const revocationTree = buildMerkleTree(revocationCommitments);
    await this.persistMerkleNodes(epochStartMs, shard, "event", eventTree.levels);
    await this.persistMerkleNodes(epochStartMs, shard, "receipt", receiptTree.levels);
    await this.persistMerkleNodes(epochStartMs, shard, "attestation", attestationTree.levels);
    await this.persistMerkleNodes(epochStartMs, shard, "revocation", revocationTree.levels);
    const checkpoint: BatchCheckpointV1 = {
      type: "tsl.batch_checkpoint.v1",
      epoch_start_ms: epochStartMs,
      epoch_duration_ms: epochDurationMs,
      shard,
      event_root: eventTree.root,
      receipt_root: receiptTree.root,
      attestation_root: attestationTree.root,
      revocation_root: revocationTree.root,
      event_count: eventCommitments.length,
      receipt_count: receiptCommitments.length,
      previous_checkpoint: await this.previousCheckpointHash(epochStartMs, shard),
      ...(settlementBackend ? { settlement_backend: settlementBackend } : {}),
      relay_id: relayId,
      relay_signature: relaySignature as `0x${string}`
    };
    checkpoint.checkpoint_identity_hash = checkpointHash(checkpoint);
    return checkpoint;
  }

  async listPendingCheckpoints(limit = 100): Promise<BatchCheckpointV1[]> {
    const result = await this.pool.query(
      "SELECT * FROM checkpoints WHERE settlement_status = 'pending' ORDER BY created_at LIMIT $1",
      [limit]
    );
    return result.rows.map((row) => {
      const checkpoint: BatchCheckpointV1 = {
      type: "tsl.batch_checkpoint.v1",
      epoch_start_ms: Number(row.epoch_start_ms),
      epoch_duration_ms: Number(row.epoch_duration_ms),
      shard: row.shard,
      event_root: row.event_root,
      receipt_root: row.receipt_root,
      attestation_root: row.attestation_root,
      revocation_root: row.revocation_root,
      event_count: Number(row.event_count),
      receipt_count: Number(row.receipt_count),
      previous_checkpoint: row.previous_checkpoint,
      relay_id: row.relay_id,
      relay_signature: row.relay_signature
      };
      checkpoint.checkpoint_identity_hash = row.checkpoint_hash ?? checkpointHash(checkpoint);
      return checkpoint;
    });
  }

  async markCheckpointSettled(checkpoint: BatchCheckpointV1): Promise<void> {
    const existing = await this.getCheckpoint(checkpoint.epoch_start_ms, checkpoint.shard);
    if (!existing) throw new Error("TSL_CHECKPOINT_MISSING");
    if (checkpointHash(existing) !== checkpointHash({ ...checkpoint, settlement_tx: undefined })) {
      throw new Error("TSL_CHECKPOINT_IDENTITY_MISMATCH");
    }
    await this.pool.query(
      `UPDATE checkpoints
       SET settlement_tx = $3, settlement_status = 'settled', settled_at = now()
       WHERE epoch_start_ms = $1 AND shard = $2`,
      [checkpoint.epoch_start_ms, checkpoint.shard, checkpoint.settlement_tx ?? null]
    );
  }
}

export function createPostgresRepositoryFromEnv(env: NodeJS.ProcessEnv = process.env): PostgresRepository | null {
  const url = env.TSL_DATABASE_URL ?? env.DATABASE_URL;
  return url ? new PostgresRepository(url) : null;
}
