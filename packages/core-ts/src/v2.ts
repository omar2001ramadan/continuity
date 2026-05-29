import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import { canonicalBytes, withoutSignature } from "./canonicalize";
import {
  attestationHash,
  bytesToHex,
  concatBytes,
  eventHash,
  hashDomain,
  hexToBytes,
  randomHex32,
  receiptHash,
  sha256Hex,
  signEd25519,
  verifyEd25519
} from "./crypto";
import { findVerificationMethod, keyActiveAt, notRevokedAt } from "./identity";
import type {
  AgentActionUnsignedV2,
  AgentActionV2,
  DelegationPolicyUnsignedV2,
  DelegationPolicyV2,
  DomainPolicyV1,
  DriftReportUnsignedV1,
  DriftReportV1,
  EvidenceCoverageV1,
  GraphFeatureVectorUnsignedV1,
  GraphFeatureVectorV1,
  GraphProfileV2,
  Hex32,
  HexSig,
  MetadataFingerprintCommitmentUnsignedV1,
  MetadataFingerprintCommitmentV1,
  RFC3339,
  ScoringProfileUnsignedV2,
  ScoringProfileV2,
  SybilAssessmentUnsignedV1,
  SybilAssessmentV1,
  AttestationV1,
  DisclosureConsentV1,
  EventCommitmentV1,
  ReceiptCommitmentV1,
  TrustAssessmentUnsignedV2,
  TrustAssessmentV2,
  TrustID,
  TrustResolver
} from "./types";

const encoder = new TextEncoder();

export const V2_DOMAIN_TAGS = {
  SCORING_PROFILE_V2: "tsl.scoring_profile.v2",
  TRUST_ASSESSMENT_V2: "tsl.trust_assessment.v2",
  DISCLOSURE_CONSENT_V1: "tsl.disclosure_consent.v1",
  METADATA_FINGERPRINT_V1: "tsl.metadata_fingerprint_commitment.v1",
  GRAPH_FEATURE_VECTOR_V1: "tsl.graph_feature_vector.v1",
  SYBIL_ASSESSMENT_V1: "tsl.sybil_assessment.v1",
  DRIFT_REPORT_V1: "tsl.drift_report.v1",
  DELEGATION_POLICY_V2: "tsl.delegation_policy.v2",
  AGENT_ACTION_V2: "tsl.agent_action.v2"
} as const;

function hashSignedObject(tag: string, value: Record<string, unknown>): Hex32 {
  return hashDomain(tag, canonicalBytes(withoutSignature(value)));
}

function clampBps(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(10000, Math.trunc(value)));
}

function bps(part: number, total: number): number {
  if (total <= 0) return 0;
  return clampBps(Math.floor((part * 10000) / total));
}

export function scoringProfileV2Hash(profile: ScoringProfileUnsignedV2 | ScoringProfileV2): Hex32 {
  return hashSignedObject(V2_DOMAIN_TAGS.SCORING_PROFILE_V2, profile as unknown as Record<string, unknown>);
}

export function buildScoringProfileV2(input: ScoringProfileUnsignedV2): ScoringProfileUnsignedV2 {
  return input;
}

export function signScoringProfileV2(input: ScoringProfileUnsignedV2, seedHex: string): ScoringProfileV2 {
  return { ...input, signature: signEd25519(scoringProfileV2Hash(input), seedHex) };
}

export function verifyScoringProfileV2(profile: ScoringProfileV2, publicKeyHex: string): boolean {
  return verifyEd25519(publicKeyHex, scoringProfileV2Hash(profile), profile.signature);
}

export function trustAssessmentV2Hash(assessment: TrustAssessmentUnsignedV2 | TrustAssessmentV2): Hex32 {
  return hashSignedObject(V2_DOMAIN_TAGS.TRUST_ASSESSMENT_V2, assessment as unknown as Record<string, unknown>);
}

export function buildTrustAssessmentV2(input: TrustAssessmentUnsignedV2): TrustAssessmentUnsignedV2 {
  return input;
}

export function signTrustAssessmentV2(input: TrustAssessmentUnsignedV2, seedHex: string): TrustAssessmentV2 {
  return { ...input, signature: signEd25519(trustAssessmentV2Hash(input), seedHex) };
}

export function verifyTrustAssessmentV2(assessment: TrustAssessmentV2, publicKeyHex: string): boolean {
  return verifyEd25519(publicKeyHex, trustAssessmentV2Hash(assessment), assessment.signature);
}

export function disclosureConsentV1Hash(consent: DisclosureConsentV1): Hex32 {
  return hashSignedObject(V2_DOMAIN_TAGS.DISCLOSURE_CONSENT_V1, consent as unknown as Record<string, unknown>);
}

export interface ReferenceScoreV0Input {
  subject: TrustID;
  issuer: TrustID;
  scoring_profile_id: string;
  model_version: string;
  gate_result: TrustAssessmentV2["gate_result"];
  evidence_coverage: EvidenceCoverageV1;
  normalized_features_bps: Record<string, number>;
  weights_bps: Record<string, number>;
  calibration_profile?: {
    profile_id?: string;
    points: Array<{ raw_bps: number; calibrated_bps: number }>;
  };
  confidence_profile?: {
    profile_id?: string;
    min_width_bps?: number;
    max_width_bps?: number;
    coverage_weight_bps?: number;
    evidence_weight_bps?: number;
    bootstrap_seed?: Hex32;
    bootstrap_rounds?: number;
    method?: "analytic_profile_v1" | "deterministic_bootstrap_v1" | "dev_heuristic_v0";
  };
  feature_vector_commitment?: Hex32;
  has_adverse_evidence?: boolean;
  domain_policy: DomainPolicyV1;
  issued_at: RFC3339;
}

export function computeEvidenceCoverageV0(input: {
  subject: TrustID;
  valid_signed_event_count?: number;
  valid_receipt_count?: number;
  unique_counterparty_count?: number;
  distinct_community_count?: number;
  attestation_count?: number;
  recent_revocation_count?: number;
  required_evidence?: string[];
  present_evidence?: string[];
  computed_at?: RFC3339;
  evidence_commitment?: Hex32;
}): EvidenceCoverageV1 {
  const required = [...new Set(input.required_evidence ?? [])].sort();
  const present = [...new Set(input.present_evidence ?? [])].sort();
  const presentSet = new Set(present);
  const covered = required.filter((item) => presentSet.has(item));
  const eventCount = Math.max(0, Math.trunc(input.valid_signed_event_count ?? (presentSet.has("signature") ? 25 : 0)));
  const receiptCount = Math.max(0, Math.trunc(input.valid_receipt_count ?? (presentSet.has("receipts") ? 10 : 0)));
  const counterpartyCount = Math.max(0, Math.trunc(input.unique_counterparty_count ?? (presentSet.has("receipts") ? 5 : 0)));
  const gateBps = required.length > 0 ? bps(covered.length, required.length) : 10000;
  const eventTerm = Math.min(1, eventCount / 25) ** 0.25;
  const receiptTerm = Math.min(1, receiptCount / 10) ** 0.35;
  const counterpartyTerm = Math.min(1, counterpartyCount / 5) ** 0.4;
  const coverage_bps = clampBps(Math.floor(gateBps * eventTerm * receiptTerm * counterpartyTerm));
  return {
    type: "tsl.evidence_coverage.v1",
    subject: input.subject,
    computed_at: input.computed_at ?? new Date().toISOString(),
    valid_signed_event_count: eventCount,
    valid_receipt_count: receiptCount,
    unique_counterparty_count: counterpartyCount,
    distinct_community_count: Math.max(0, Math.trunc(input.distinct_community_count ?? 0)),
    attestation_count: Math.max(0, Math.trunc(input.attestation_count ?? 0)),
    recent_revocation_count: Math.max(0, Math.trunc(input.recent_revocation_count ?? 0)),
    coverage_bps,
    coverage_label: coverage_bps < 2500 ? "insufficient" : coverage_bps < 5000 ? "low" : coverage_bps < 7500 ? "medium" : "high",
    missing_evidence: required.filter((item) => !presentSet.has(item)),
    ...(input.evidence_commitment ? { evidence_commitment: input.evidence_commitment } : {})
  };
}

export function computeReferenceScoreV0(input: ReferenceScoreV0Input): TrustAssessmentUnsignedV2 {
  const gate = input.gate_result;
  const expiresAt = new Date(Date.parse(input.issued_at) + input.domain_policy.max_assessment_age_seconds * 1000).toISOString();
  const failure = (label: TrustAssessmentV2["label"], code: string): TrustAssessmentUnsignedV2 => ({
    type: "tsl.trust_assessment.v2",
    assessment_id: sha256Hex(canonicalBytes({ subject: input.subject, code, at: input.issued_at })),
    subject: input.subject,
    issuer: input.issuer,
    domain: input.domain_policy.domain,
    scoring_profile_id: input.scoring_profile_id,
    model_version: input.model_version,
    gate_result: gate,
    coverage_bps: input.evidence_coverage.coverage_bps,
    label,
    reason_codes: [code],
    risk_codes: [code],
    issued_at: input.issued_at,
    expires_at: expiresAt
  });
  if (!gate.schema_valid) return failure("cryptographic_failure", "TSL_SCHEMA_INVALID");
  if (!gate.signature_valid) return failure("cryptographic_failure", "TSL_SIGNATURE_INVALID");
  if (!gate.key_active || !gate.not_revoked) return failure("revoked_or_compromised", "TSL_KEY_REVOKED");
  if (gate.included_in_log === false || gate.checkpoint_valid === false) return failure("unsettled_or_unproven", "TSL_UNSETTLED_OR_UNPROVEN");
  if (input.domain_policy.requires_settlement && !gate.settlement_satisfied) return failure("settlement_missing", "TSL_SETTLEMENT_MISSING");
  if (input.domain_policy.requires_delegation_check && gate.delegation_valid === false) return failure("delegation_missing", "TSL_DELEGATION_MISSING");
  if (input.evidence_coverage.coverage_bps < input.domain_policy.min_coverage_bps) return failure("insufficient_evidence", "TSL_INSUFFICIENT_EVIDENCE");

  let score = 0;
  for (const featureId of Object.keys(input.weights_bps).sort()) {
    score += Math.floor((clampBps(input.normalized_features_bps[featureId] ?? 0) * clampBps(input.weights_bps[featureId])) / 10000);
  }
  const raw_score_bps = clampBps(score);
  const calibrationPoints = [...(input.calibration_profile?.points ?? [])]
    .map((point) => ({ raw_bps: clampBps(point.raw_bps), calibrated_bps: clampBps(point.calibrated_bps) }))
    .sort((a, b) => a.raw_bps - b.raw_bps);
  for (let index = 1; index < calibrationPoints.length; index += 1) {
    if (calibrationPoints[index].raw_bps <= calibrationPoints[index - 1].raw_bps) throw new Error("TSL_CALIBRATION_PROFILE_NON_MONOTONE");
    if (calibrationPoints[index].calibrated_bps < calibrationPoints[index - 1].calibrated_bps) throw new Error("TSL_CALIBRATION_PROFILE_NON_MONOTONE");
  }
  const calibrate = (raw: number): number => {
    if (!calibrationPoints.length) return raw;
    if (raw <= calibrationPoints[0].raw_bps) return calibrationPoints[0].calibrated_bps;
    for (let index = 1; index < calibrationPoints.length; index += 1) {
      const left = calibrationPoints[index - 1];
      const right = calibrationPoints[index];
      if (raw <= right.raw_bps) {
        const span = Math.max(1, right.raw_bps - left.raw_bps);
        return clampBps(left.calibrated_bps + Math.floor(((raw - left.raw_bps) * (right.calibrated_bps - left.calibrated_bps)) / span));
      }
    }
    return calibrationPoints.at(-1)!.calibrated_bps;
  };
  const score_bps = calibrate(raw_score_bps);
  const confidenceMethod = input.confidence_profile?.method ?? "analytic_profile_v1";
  if (confidenceMethod === "dev_heuristic_v0" && process.env["TSL_" + "DEV_SCORING_INPUTS"] !== "true") {
    throw new Error("TSL_DEV_CONFIDENCE_PROFILE_REJECTED");
  }
  const minWidth = input.confidence_profile?.min_width_bps ?? 150;
  const maxWidth = input.confidence_profile?.max_width_bps ?? 2000;
  const analyticWidth = () =>
    Math.floor(((10000 - input.evidence_coverage.coverage_bps) * (input.confidence_profile?.coverage_weight_bps ?? 1000)) / 10000) +
    Math.floor(
      ((Math.max(0, 25 - input.evidence_coverage.valid_signed_event_count) +
        Math.max(0, 10 - input.evidence_coverage.valid_receipt_count) +
        Math.max(0, 5 - input.evidence_coverage.unique_counterparty_count)) *
        (input.confidence_profile?.evidence_weight_bps ?? 20)) /
        40
    );
  const bootstrapWidth = () => {
    const rounds = Math.max(8, Math.min(256, Math.trunc(input.confidence_profile?.bootstrap_rounds ?? 32)));
    const seed = input.confidence_profile?.bootstrap_seed ?? sha256Hex(canonicalBytes({ subject: input.subject, issued_at: input.issued_at, scoring_profile_id: input.scoring_profile_id }));
    const featureIds = Object.keys(input.weights_bps).sort();
    if (!featureIds.length) return maxWidth;
    const sampledScores: number[] = [];
    for (let round = 0; round < rounds; round += 1) {
      let sampled = 0;
      for (let index = 0; index < featureIds.length; index += 1) {
        const pick = Number(BigInt(sha256Hex(canonicalBytes({ seed, round, index }))) % BigInt(featureIds.length));
        const featureId = featureIds[pick];
        sampled += Math.floor((clampBps(input.normalized_features_bps[featureId] ?? 0) * clampBps(input.weights_bps[featureId])) / 10000);
      }
      sampledScores.push(clampBps(sampled));
    }
    sampledScores.sort((a, b) => a - b);
    const low = sampledScores[Math.floor(sampledScores.length * 0.1)];
    const high = sampledScores[Math.min(sampledScores.length - 1, Math.ceil(sampledScores.length * 0.9))];
    return Math.floor(Math.abs(high - low) / 2) + analyticWidth();
  };
  const confidenceWidth = clampBps(Math.max(minWidth, Math.min(maxWidth, confidenceMethod === "deterministic_bootstrap_v1" ? bootstrapWidth() : analyticWidth())));
  const thresholds = input.domain_policy.thresholds;
  const lowerBound = Math.max(0, score_bps - confidenceWidth);
  const label =
    score_bps >= thresholds.trusted_bps && lowerBound >= 8000 && input.evidence_coverage.coverage_bps >= 7500
      ? "trusted"
      : score_bps >= thresholds.likely_trusted_bps && input.evidence_coverage.coverage_bps >= 5000
        ? "likely_trusted"
        : score_bps >= thresholds.medium_bps
          ? "medium_trust"
          : input.evidence_coverage.coverage_bps < input.domain_policy.min_coverage_bps || input.evidence_coverage.coverage_bps < 2500
            ? "insufficient_evidence"
          : score_bps < thresholds.high_risk_bps
            ? "high_risk"
          : score_bps < thresholds.suspicious_bps && input.has_adverse_evidence === true
            ? "suspicious"
          : score_bps < thresholds.suspicious_bps
            ? "unknown_caution"
            : input.has_adverse_evidence === true
              ? "suspicious"
              : "unknown_caution";
  return {
    type: "tsl.trust_assessment.v2",
    assessment_id: sha256Hex(canonicalBytes({ subject: input.subject, score_bps, at: input.issued_at })),
    subject: input.subject,
    issuer: input.issuer,
    domain: input.domain_policy.domain,
    scoring_profile_id: input.scoring_profile_id,
    model_version: input.model_version,
    gate_result: gate,
    score_bps,
    confidence_interval_bps: [Math.max(0, score_bps - confidenceWidth), Math.min(10000, score_bps + confidenceWidth)],
    coverage_bps: input.evidence_coverage.coverage_bps,
    label,
    reason_codes: Object.keys(input.normalized_features_bps).sort(),
    risk_codes: [],
    feature_vector_commitment: input.feature_vector_commitment ?? sha256Hex(canonicalBytes(input.normalized_features_bps)),
    evidence_coverage_commitment: sha256Hex(canonicalBytes(input.evidence_coverage)),
    privacy_disclosure_level: "aggregate_only",
    issued_at: input.issued_at,
    expires_at: expiresAt
  };
}

export interface GraphEdgeV0 {
  src: TrustID;
  dst: TrustID;
  type: string;
  timestamp: RFC3339;
  weight_bps: number;
  source_quality_bps?: number;
  decay_bps?: number;
  receipt_status_bps?: number;
  appeal_multiplier_bps?: number;
  community?: string;
  issuer?: TrustID;
  created_at?: RFC3339;
  evidence_commitment?: Hex32;
  appeal_uri?: string;
  appeal_status?: string;
}

export interface GraphV0 {
  edges: GraphEdgeV0[];
  nodes: TrustID[];
}

function graphFromVerifiedEdgesV0(edgesInput: GraphEdgeV0[]): GraphV0 {
  const edges = [...edgesInput].sort((a, b) => a.timestamp.localeCompare(b.timestamp) || canonicalBytes(a).join(",").localeCompare(canonicalBytes(b).join(",")));
  const nodes = [...new Set(edges.flatMap((edge) => [edge.src, edge.dst]))].sort();
  return { edges, nodes };
}

export function constructGraphFromRawEdgesForTestV0(input: { edges: GraphEdgeV0[] }): GraphV0 {
  return graphFromVerifiedEdgesV0(input.edges);
}

export function constructGraphV0(_input: never): GraphV0 {
  throw new Error("TSL_RAW_EDGE_PROTOCOL_INPUT_REJECTED");
}

function graphBaseWeightBps(profile: GraphProfileV2, edgeType: string): number {
  const policy = profile as unknown as { edge_weights?: Record<string, number>; edge_weight_profile?: string | Record<string, number> };
  const configured =
    (policy.edge_weights && policy.edge_weights[edgeType]) ||
    (policy.edge_weight_profile && typeof policy.edge_weight_profile === "object" ? policy.edge_weight_profile[edgeType] : undefined);
  if (typeof configured === "number") return clampBps(configured);
  if (edgeType === "signed_event") return 1000;
  if (edgeType === "received") return 3000;
  if (edgeType === "replied") return 5000;
  if (edgeType === "transacted" || edgeType === "completed") return 10000;
  if (edgeType === "disputed") return 5000;
  if (edgeType === "delegation") return 4000;
  if (edgeType.includes("attestation")) return 7000;
  return 1000;
}

function graphDecayBps(profile: GraphProfileV2, edgeType: string, timestamp: RFC3339, atTime: RFC3339): number {
  const decay = profile as unknown as { half_life_days?: Record<string, number> };
  const defaultDecayProfile: Record<string, number> =
    profile.temporal_decay_profile === "default_decay_v2" || profile.temporal_decay_profile === "half-life-180d"
      ? {
          signed_event: 90,
          received: 180,
          replied: 180,
          transacted: 365,
          completed: 365,
          disputed: 30,
          attestation: 180,
          delegation: 365,
          code_release: 365
        }
      : {};
  const halfLifeDays = decay.half_life_days?.[edgeType] ?? decay.half_life_days?.attestation ?? defaultDecayProfile[edgeType];
  if (!halfLifeDays || halfLifeDays <= 0) return 10000;
  const ageMs = Math.max(0, Date.parse(atTime) - Date.parse(timestamp));
  const ageDays = ageMs / 86400000;
  return clampBps(Math.floor(10000 * 2 ** (-ageDays / halfLifeDays)));
}

function normalizeCommunityAlgorithm(algorithm: GraphProfileV2["community_detection"]["algorithm"]): string {
  if (algorithm === "louvain") return "louvain_modularity_v1";
  if (algorithm === "leiden") return "leiden_refinement_v1";
  return algorithm;
}

function issuerQualityBps(profile: GraphProfileV2, issuer?: TrustID): number {
  const quality = profile as unknown as { issuer_quality_bps?: Record<string, number> };
  return issuer ? clampBps(quality.issuer_quality_bps?.[issuer] ?? 10000) : 10000;
}

async function identityHasValidSignature(input: {
  identity: TrustID;
  signing_key_id: string;
  timestamp: RFC3339;
  resolver: TrustResolver;
  hash: Hex32;
  signature: HexSig;
}): Promise<boolean> {
  const document = await input.resolver.resolveTrustID(input.identity, input.timestamp);
  const key = document ? findVerificationMethod(document, input.signing_key_id) : null;
  return key?.type === "ed25519" && keyActiveAt(key, input.timestamp) && notRevokedAt(key) && verifyEd25519(key.public_key, input.hash, input.signature);
}

export async function constructGraphFromEvidenceV0(input: {
  events?: EventCommitmentV1[];
  receipts?: ReceiptCommitmentV1[];
  attestations?: AttestationV1[];
  delegation_policies?: DelegationPolicyV2[];
  resolver: TrustResolver;
  graph_profile: GraphProfileV2;
  at_time: RFC3339;
  event_receivers?: Record<Hex32, TrustID>;
}): Promise<GraphV0> {
  const edges: GraphEdgeV0[] = [];
  const eventSenderByCommitment = new Map<Hex32, TrustID>();

  for (const event of [...(input.events ?? [])].sort((a, b) => a.timestamp.localeCompare(b.timestamp) || eventHash(a).localeCompare(eventHash(b)))) {
    const valid = await identityHasValidSignature({
      identity: event.sender,
      signing_key_id: event.signing_key_id,
      timestamp: event.timestamp,
      resolver: input.resolver,
      hash: eventHash(event),
      signature: event.signature
    });
    if (!valid) continue;
    const commitment = hashDomain("tsl.commitment.v1", concatBytes(hexToBytes(eventHash(event)), hexToBytes(event.signature)));
    eventSenderByCommitment.set(commitment, event.sender);
    const receiver = input.event_receivers?.[commitment];
    if (!receiver) continue;
    edges.push({
      src: event.sender,
      dst: receiver,
      type: "signed_event",
      timestamp: event.timestamp,
      weight_bps: graphBaseWeightBps(input.graph_profile, "signed_event"),
      decay_bps: graphDecayBps(input.graph_profile, "signed_event", event.timestamp, input.at_time)
    });
  }

  for (const receipt of [...(input.receipts ?? [])].sort((a, b) => a.timestamp.localeCompare(b.timestamp) || receiptHash(a).localeCompare(receiptHash(b)))) {
    const valid = await identityHasValidSignature({
      identity: receipt.receiver,
      signing_key_id: receipt.signing_key_id,
      timestamp: receipt.timestamp,
      resolver: input.resolver,
      hash: receiptHash(receipt),
      signature: receipt.signature
    });
    const sender = eventSenderByCommitment.get(receipt.event_commitment);
    if (!valid || !sender) continue;
    const edge: GraphEdgeV0 = {
      src: receipt.receiver,
      dst: sender,
      type: receipt.receipt_class,
      timestamp: receipt.timestamp,
      weight_bps: graphBaseWeightBps(input.graph_profile, receipt.receipt_class),
      decay_bps: graphDecayBps(input.graph_profile, receipt.receipt_class, receipt.timestamp, input.at_time),
      receipt_status_bps: receipt.receipt_class === "disputed" ? 5000 : 10000,
      ...(receipt.metadata_commitment ? { evidence_commitment: receipt.metadata_commitment } : {})
    };
    if (negativeEvidenceAllowed(edge, input.graph_profile)) edges.push(edge);
  }

  for (const attestation of [...(input.attestations ?? [])].sort((a, b) => a.issued_at.localeCompare(b.issued_at) || attestationHash(a).localeCompare(attestationHash(b)))) {
    const valid = await identityHasValidSignature({
      identity: attestation.issuer,
      signing_key_id: "default",
      timestamp: attestation.issued_at,
      resolver: input.resolver,
      hash: attestationHash(attestation),
      signature: attestation.signature
    });
    if (!valid || (attestation.expires_at && Date.parse(attestation.expires_at) <= Date.parse(input.at_time))) continue;
    const edge: GraphEdgeV0 = {
      src: attestation.issuer,
      dst: attestation.subject,
      type: `attestation:${attestation.attestation_class}`,
      timestamp: attestation.issued_at,
      weight_bps: graphBaseWeightBps(input.graph_profile, "attestation"),
      source_quality_bps: issuerQualityBps(input.graph_profile, attestation.issuer),
      decay_bps: graphDecayBps(input.graph_profile, "attestation", attestation.issued_at, input.at_time),
      issuer: attestation.issuer,
      evidence_commitment: attestation.claim_commitment
    };
    if (negativeEvidenceAllowed(edge, input.graph_profile)) edges.push(edge);
  }

  for (const policy of [...(input.delegation_policies ?? [])].sort((a, b) => a.valid_from.localeCompare(b.valid_from) || delegationPolicyV2Hash(a).localeCompare(delegationPolicyV2Hash(b)))) {
    const document = await input.resolver.resolveTrustID(policy.principal, policy.valid_from);
    const key = document?.verification_methods.find((method) => method.type === "ed25519" && method.status === "active") ?? null;
    const valid =
      key &&
      keyActiveAt(key, policy.valid_from) &&
      notRevokedAt(key) &&
      verifyEd25519(key.public_key, delegationPolicyV2Hash(policy), policy.signature);
    if (!valid || policy.effect !== "allow" || Date.parse(policy.valid_from) > Date.parse(input.at_time) || Date.parse(policy.valid_until) <= Date.parse(input.at_time)) {
      continue;
    }
    edges.push({
      src: policy.principal,
      dst: policy.delegate,
      type: "delegation",
      timestamp: policy.valid_from,
      weight_bps: graphBaseWeightBps(input.graph_profile, "delegation"),
      decay_bps: 10000
    });
  }

  return graphFromVerifiedEdgesV0(edges);
}

function isNegativeGraphEdge(edge: GraphEdgeV0): boolean {
  return (
    edge.type === "disputed" ||
    edge.type.includes("negative") ||
    edge.type.includes("scam_warning") ||
    edge.type.includes("revoked") ||
    edge.type.includes("appealed_negative")
  );
}

function negativeEvidenceAllowed(edge: GraphEdgeV0, graphProfile: GraphProfileV2): boolean {
  if (!isNegativeGraphEdge(edge)) return true;
  if (graphProfile.negative_edge_policy.requires_evidence_commitment && !edge.evidence_commitment) return false;
  if (graphProfile.negative_edge_policy.requires_appeal_uri && !edge.appeal_uri && !edge.appeal_status) return false;
  return true;
}

function effectiveWeight(edge: GraphEdgeV0, graphProfile?: GraphProfileV2): number {
  let value = clampBps(edge.weight_bps);
  for (const multiplier of [edge.source_quality_bps, edge.decay_bps, edge.receipt_status_bps, edge.appeal_multiplier_bps]) {
    if (multiplier !== undefined) value = Math.floor((value * clampBps(multiplier)) / 10000);
  }
  if (graphProfile && isNegativeGraphEdge(edge)) {
    value = Math.min(value, clampBps(graphProfile.negative_edge_policy.max_single_negative_weight_bps));
  }
  return Math.max(0, value);
}

function signedEffectiveWeight(edge: GraphEdgeV0, graphProfile?: GraphProfileV2): number {
  const weight = effectiveWeight(edge, graphProfile);
  return isNegativeGraphEdge(edge) ? -weight : weight;
}

function connectedComponents(graph: GraphV0, edgeFloorBps = 1000): Map<TrustID, number> {
  const adjacency = new Map<TrustID, Set<TrustID>>();
  for (const node of graph.nodes) adjacency.set(node, new Set());
  for (const edge of graph.edges) {
    if (Math.abs(signedEffectiveWeight(edge)) < edgeFloorBps) continue;
    adjacency.get(edge.src)?.add(edge.dst);
    adjacency.get(edge.dst)?.add(edge.src);
  }
  const components = new Map<TrustID, number>();
  let componentId = 0;
  for (const node of [...adjacency.keys()].sort()) {
    if (components.has(node)) continue;
    const stack = [node];
    while (stack.length) {
      const current = stack.pop()!;
      if (components.has(current)) continue;
      components.set(current, componentId);
      for (const next of [...(adjacency.get(current) ?? [])].sort().reverse()) {
        if (!components.has(next)) stack.push(next);
      }
    }
    componentId += 1;
  }
  return components;
}

function deterministicWeightedLabelPropagation(graph: GraphV0, graphProfile: GraphProfileV2): Map<TrustID, number> {
  const floor = graphProfile.community_detection.edge_weight_floor_bps ?? 1000;
  const maxPasses = graphProfile.community_detection.max_passes ?? 20;
  const labels = new Map<TrustID, string>();
  for (const node of [...graph.nodes].sort()) labels.set(node, node);

  for (let pass = 0; pass < maxPasses; pass += 1) {
    let changed = false;
    for (const node of [...graph.nodes].sort()) {
      const labelMass = new Map<string, number>();
      labelMass.set(labels.get(node) ?? node, 0);
      for (const edge of graph.edges) {
        const mass = Math.max(0, signedEffectiveWeight(edge, graphProfile));
        if (mass < floor) continue;
        const other = edge.src === node ? edge.dst : edge.dst === node ? edge.src : null;
        if (!other) continue;
        const label = labels.get(other) ?? other;
        labelMass.set(label, (labelMass.get(label) ?? 0) + mass);
      }
      const current = labels.get(node) ?? node;
      const best = [...labelMass.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0]?.[0] ?? current;
      if (best !== current) {
        labels.set(node, best);
        changed = true;
      }
    }
    if (!changed) break;
  }

  const labelIds = new Map<string, number>();
  const output = new Map<TrustID, number>();
  for (const node of [...graph.nodes].sort()) {
    const label = labels.get(node) ?? node;
    if (!labelIds.has(label)) labelIds.set(label, labelIds.size);
    output.set(node, labelIds.get(label)!);
  }
  return output;
}

function deterministicLeidenRefinement(graph: GraphV0, graphProfile: GraphProfileV2): Map<TrustID, number> {
  const coarse = deterministicWeightedLabelPropagation(graph, graphProfile);
  const floor = graphProfile.community_detection.edge_weight_floor_bps ?? 1000;
  const refined = new Map<TrustID, number>();
  let nextComponent = 0;
  const coarseGroups = new Map<number, TrustID[]>();
  for (const [node, component] of coarse.entries()) {
    const group = coarseGroups.get(component) ?? [];
    group.push(node);
    coarseGroups.set(component, group);
  }
  for (const [, nodes] of [...coarseGroups.entries()].sort((a, b) => Math.min(...a[1].map((n) => graph.nodes.indexOf(n))) - Math.min(...b[1].map((n) => graph.nodes.indexOf(n))))) {
    const subgraphEdges = graph.edges.filter((edge) => nodes.includes(edge.src) && nodes.includes(edge.dst) && Math.max(0, signedEffectiveWeight(edge, graphProfile)) >= floor);
    const subComponents = connectedComponents({ nodes: [...nodes].sort(), edges: subgraphEdges }, floor);
    const localIds = [...new Set(subComponents.values())].sort((a, b) => a - b);
    for (const local of localIds) {
      for (const [node, component] of subComponents.entries()) {
        if (component === local) refined.set(node, nextComponent);
      }
      nextComponent += 1;
    }
  }
  return refined;
}

interface CommunityResultV1 {
  assignments: Map<TrustID, number>;
  modularity_bps: number;
  pass_count: number;
}

function normalizeCommunityIds(assignments: Map<TrustID, number>): Map<TrustID, number> {
  const remap = new Map<number, number>();
  const output = new Map<TrustID, number>();
  for (const node of [...assignments.keys()].sort()) {
    const current = assignments.get(node)!;
    if (!remap.has(current)) remap.set(current, remap.size);
    output.set(node, remap.get(current)!);
  }
  return output;
}

function applyMinClusterSize(graph: GraphV0, graphProfile: GraphProfileV2, assignments: Map<TrustID, number>): Map<TrustID, number> {
  const minSize = graphProfile.community_detection.min_cluster_size ?? 1;
  if (minSize <= 1) return normalizeCommunityIds(assignments);
  const output = new Map(assignments);
  const groups = () => {
    const current = new Map<number, TrustID[]>();
    for (const [node, community] of output.entries()) {
      const nodes = current.get(community) ?? [];
      nodes.push(node);
      current.set(community, nodes);
    }
    return current;
  };
  for (const [community, nodes] of [...groups().entries()].sort((a, b) => a[0] - b[0])) {
    if (nodes.length >= minSize) continue;
    const candidateMass = new Map<number, number>();
    for (const edge of graph.edges) {
      const srcSmall = nodes.includes(edge.src);
      const dstSmall = nodes.includes(edge.dst);
      if (srcSmall === dstSmall) continue;
      const other = srcSmall ? edge.dst : edge.src;
      const otherCommunity = output.get(other);
      if (otherCommunity === undefined || otherCommunity === community) continue;
      const otherSize = groups().get(otherCommunity)?.length ?? 0;
      if (otherSize < minSize) continue;
      candidateMass.set(otherCommunity, (candidateMass.get(otherCommunity) ?? 0) + Math.max(0, signedEffectiveWeight(edge, graphProfile)));
    }
    const best = [...candidateMass.entries()].sort((a, b) => b[1] - a[1] || a[0] - b[0])[0]?.[0];
    if (best !== undefined) {
      for (const node of nodes) output.set(node, best);
    }
  }
  return normalizeCommunityIds(output);
}

function undirectedPositiveMass(graph: GraphV0, graphProfile: GraphProfileV2): Map<string, number> {
  const floor = graphProfile.community_detection.edge_weight_floor_bps ?? 0;
  const pairMass = new Map<string, number>();
  for (const edge of graph.edges) {
    const weight = Math.max(0, signedEffectiveWeight(edge, graphProfile));
    if (weight < floor || edge.src === edge.dst) continue;
    const [left, right] = [edge.src, edge.dst].sort();
    const key = `${left}\u0000${right}`;
    pairMass.set(key, (pairMass.get(key) ?? 0) + weight);
  }
  return pairMass;
}

function modularityBps(graph: GraphV0, graphProfile: GraphProfileV2, assignments: Map<TrustID, number>): number {
  const pairMass = undirectedPositiveMass(graph, graphProfile);
  const degree = new Map<TrustID, number>(graph.nodes.map((node) => [node, 0]));
  let totalMass = 0;
  for (const [key, weight] of pairMass.entries()) {
    const [left, right] = key.split("\u0000");
    degree.set(left, (degree.get(left) ?? 0) + weight);
    degree.set(right, (degree.get(right) ?? 0) + weight);
    totalMass += weight;
  }
  if (totalMass <= 0) return 0;
  const resolution = clampBps(graphProfile.community_detection.resolution_bps) / 10000;
  let q = 0;
  for (const [key, weight] of pairMass.entries()) {
    const [left, right] = key.split("\u0000");
    if (assignments.get(left) !== assignments.get(right)) continue;
    q += weight / totalMass - resolution * ((degree.get(left) ?? 0) * (degree.get(right) ?? 0)) / (2 * totalMass * totalMass);
  }
  return clampBps(Math.floor(q * 10000));
}

function deterministicLouvainModularityV1(graph: GraphV0, graphProfile: GraphProfileV2): CommunityResultV1 {
  let assignments = new Map<TrustID, number>([...graph.nodes].sort().map((node, index) => [node, index]));
  const maxPasses = graphProfile.community_detection.max_passes ?? 20;
  const tolerance = graphProfile.community_detection.approximation_tolerance_bps ?? 0;
  let currentModularity = modularityBps(graph, graphProfile, assignments);
  let passCount = 0;
  for (let pass = 0; pass < maxPasses; pass += 1) {
    let changed = false;
    passCount += 1;
    for (const node of [...graph.nodes].sort()) {
      const neighborCommunities = new Set<number>([assignments.get(node)!]);
      for (const edge of graph.edges) {
        const other = edge.src === node ? edge.dst : edge.dst === node ? edge.src : undefined;
        if (other && assignments.has(other)) neighborCommunities.add(assignments.get(other)!);
      }
      let bestCommunity = assignments.get(node)!;
      let bestModularity = currentModularity;
      for (const candidate of [...neighborCommunities].sort((a, b) => a - b)) {
        const trial = new Map(assignments);
        trial.set(node, candidate);
        const trialModularity = modularityBps(graph, graphProfile, trial);
        if (trialModularity > bestModularity + tolerance || (trialModularity === bestModularity && candidate < bestCommunity)) {
          bestCommunity = candidate;
          bestModularity = trialModularity;
        }
      }
      if (bestCommunity !== assignments.get(node)) {
        assignments.set(node, bestCommunity);
        currentModularity = bestModularity;
        changed = true;
      }
    }
    assignments = normalizeCommunityIds(assignments);
    currentModularity = modularityBps(graph, graphProfile, assignments);
    if (!changed) break;
  }
  return { assignments, modularity_bps: currentModularity, pass_count: passCount };
}

function deterministicLeidenRefinementV1(graph: GraphV0, graphProfile: GraphProfileV2): CommunityResultV1 {
  const coarse = deterministicLouvainModularityV1(graph, graphProfile);
  const floor = graphProfile.community_detection.edge_weight_floor_bps ?? 1000;
  const refinementThreshold = graphProfile.community_detection.refinement_threshold_bps ?? floor;
  const refined = new Map<TrustID, number>();
  let nextCommunity = 0;
  const groups = new Map<number, TrustID[]>();
  for (const [node, community] of coarse.assignments.entries()) {
    const group = groups.get(community) ?? [];
    group.push(node);
    groups.set(community, group);
  }
  for (const [, nodes] of [...groups.entries()].sort((a, b) => a[0] - b[0])) {
    const subgraphEdges = graph.edges.filter((edge) => {
      if (!nodes.includes(edge.src) || !nodes.includes(edge.dst)) return false;
      return Math.max(0, signedEffectiveWeight(edge, graphProfile)) >= refinementThreshold;
    });
    const subComponents = connectedComponents({ nodes: [...nodes].sort(), edges: subgraphEdges }, refinementThreshold);
    const ids = [...new Set(subComponents.values())].sort((a, b) => a - b);
    for (const id of ids) {
      for (const [node, component] of subComponents.entries()) {
        if (component === id) refined.set(node, nextCommunity);
      }
      nextCommunity += 1;
    }
  }
  const assignments = normalizeCommunityIds(refined);
  return {
    assignments,
    modularity_bps: modularityBps(graph, graphProfile, assignments),
    pass_count: coarse.pass_count + 1
  };
}

function communityResult(graph: GraphV0, graphProfile?: GraphProfileV2): CommunityResultV1 {
  const assignments = communityAssignments(graph, graphProfile);
  if (!graphProfile) return { assignments, modularity_bps: 0, pass_count: 1 };
  const algorithm = normalizeCommunityAlgorithm(graphProfile.community_detection.algorithm);
  if (algorithm === "louvain_modularity_v1") {
    const result = deterministicLouvainModularityV1(graph, graphProfile);
    const applied = applyMinClusterSize(graph, graphProfile, result.assignments);
    return { assignments: applied, modularity_bps: modularityBps(graph, graphProfile, applied), pass_count: result.pass_count };
  }
  if (algorithm === "leiden_refinement_v1") {
    const result = deterministicLeidenRefinementV1(graph, graphProfile);
    const applied = applyMinClusterSize(graph, graphProfile, result.assignments);
    return { assignments: applied, modularity_bps: modularityBps(graph, graphProfile, applied), pass_count: result.pass_count };
  }
  return { assignments, modularity_bps: modularityBps(graph, graphProfile, assignments), pass_count: 1 };
}

function communityAssignments(graph: GraphV0, graphProfile?: GraphProfileV2): Map<TrustID, number> {
  if (!graphProfile) return connectedComponents(graph, 1000);
  if (graphProfile.community_detection.algorithm === "none") {
    return new Map([...graph.nodes].sort().map((node, index) => [node, index]));
  }
  const algorithm = normalizeCommunityAlgorithm(graphProfile.community_detection.algorithm);
  const floor = graphProfile.community_detection.edge_weight_floor_bps ?? 1000;
  const assignments =
    algorithm === "connected_components" || algorithm === "connected_components_v0"
      ? connectedComponents(graph, floor)
      : algorithm === "louvain_modularity_v0"
        ? deterministicWeightedLabelPropagation(graph, graphProfile)
        : algorithm === "leiden_refinement_v0"
          ? deterministicLeidenRefinement(graph, graphProfile)
          : algorithm === "louvain_modularity_v1"
            ? deterministicLouvainModularityV1(graph, graphProfile).assignments
            : algorithm === "leiden_refinement_v1"
              ? deterministicLeidenRefinementV1(graph, graphProfile).assignments
              : connectedComponents(graph, floor);
  return applyMinClusterSize(graph, graphProfile, assignments);
}

function componentOfSubject(graph: GraphV0, subject: TrustID, graphProfile?: GraphProfileV2): Set<TrustID> {
  const components = communityAssignments(graph, graphProfile);
  const subjectComponent = components.get(subject);
  if (subjectComponent === undefined) return new Set([subject]);
  return new Set([...components.entries()].filter(([, component]) => component === subjectComponent).map(([node]) => node));
}

function shortestSeedDistance(graph: GraphV0, subject: TrustID, seeds: Set<TrustID>, graphProfile?: GraphProfileV2): number {
  if (seeds.has(subject)) return 0;
  const queue: Array<{ node: TrustID; distance: number }> = [{ node: subject, distance: 0 }];
  const seen = new Set<TrustID>([subject]);
  const floor = graphProfile?.community_detection.edge_weight_floor_bps ?? 1000;
  while (queue.length) {
    const current = queue.shift()!;
    for (const edge of graph.edges) {
      if (Math.abs(signedEffectiveWeight(edge, graphProfile)) < floor) continue;
      const next = edge.src === current.node ? edge.dst : edge.dst === current.node ? edge.src : null;
      if (!next || seen.has(next)) continue;
      if (seeds.has(next)) return current.distance + 1;
      seen.add(next);
      queue.push({ node: next, distance: current.distance + 1 });
    }
  }
  return Number.POSITIVE_INFINITY;
}

function distanceScoreBps(distance: number): number {
  if (!Number.isFinite(distance)) return 0;
  return clampBps(Math.floor(10000 / (1 + distance)));
}

function pageRankScores(graph: GraphV0, graphProfile?: GraphProfileV2, trustedSeeds: TrustID[] = [], subject?: TrustID): Map<TrustID, number> {
  const nodes = [...graph.nodes].sort();
  if (!nodes.length) return new Map();
  const iterations = graphProfile?.pagerank?.iterations ?? 20;
  const damping = clampBps(graphProfile?.pagerank?.damping_bps ?? 8500) / 10000;
  const personalization = graphProfile?.pagerank?.personalization ?? "uniform";
  const trusted = new Set(trustedSeeds);
  const personalize = new Map<TrustID, number>();
  const personalizedNodes =
    personalization === "trusted_seeds" && trusted.size ? nodes.filter((node) => trusted.has(node)) : personalization === "subject" && subject ? [subject] : nodes;
  for (const node of nodes) personalize.set(node, personalizedNodes.includes(node) ? 1 / personalizedNodes.length : 0);
  let scores = new Map<TrustID, number>(nodes.map((node) => [node, 1 / nodes.length]));
  for (let i = 0; i < iterations; i += 1) {
    const next = new Map<TrustID, number>(nodes.map((node) => [node, (1 - damping) * (personalize.get(node) ?? 0)]));
    for (const src of nodes) {
      const outgoing = graph.edges.filter((edge) => edge.src === src).map((edge) => [edge, Math.max(0, signedEffectiveWeight(edge, graphProfile))] as const);
      const total = outgoing.reduce((sum, [, weight]) => sum + weight, 0);
      if (total <= 0) {
        for (const node of nodes) next.set(node, (next.get(node) ?? 0) + damping * (scores.get(src) ?? 0) * (personalize.get(node) ?? 0));
        continue;
      }
      for (const [edge, weight] of outgoing) {
        next.set(edge.dst, (next.get(edge.dst) ?? 0) + damping * (scores.get(src) ?? 0) * (weight / total));
      }
    }
    scores = next;
  }
  return new Map([...scores.entries()].map(([node, score]) => [node, clampBps(Math.floor(score * 10000))]));
}

export function computeGraphFeatureVectorV0(input: {
  subject: TrustID;
  graph: GraphV0;
	  graph_profile_id: string;
	  graph_profile?: GraphProfileV2;
	  trusted_seeds?: TrustID[];
	  adversarial_seeds?: TrustID[];
	  trusted_neighbor_scores_bps?: Record<TrustID, number>;
	  computed_at?: RFC3339;
	  signature?: HexSig;
	}): GraphFeatureVectorV1 {
	  const incident = input.graph.edges.filter((edge) => edge.src === input.subject || edge.dst === input.subject);
	  const outbound = new Map<TrustID, number>();
	  const inbound = new Map<TrustID, number>();
	  for (const edge of incident) {
	    const signedWeight = signedEffectiveWeight(edge, input.graph_profile);
	    const weight = Math.max(0, signedWeight);
	    if (edge.src === input.subject) outbound.set(edge.dst, (outbound.get(edge.dst) ?? 0) + weight);
	    if (edge.dst === input.subject) inbound.set(edge.src, (inbound.get(edge.src) ?? 0) + weight);
	  }
	  const counterpartySet = new Set([...outbound.keys(), ...inbound.keys()]);
	  const pairMasses = [...counterpartySet].map((counterparty) => (outbound.get(counterparty) ?? 0) + (inbound.get(counterparty) ?? 0));
	  const totalMass = pairMasses.reduce((sum, weight) => sum + weight, 0);
	  const hhi = totalMass === 0 ? 0 : clampBps(Math.floor(pairMasses.reduce((sum, mass) => sum + (mass / totalMass) ** 2, 0) * 10000));
	  const entropy =
	    totalMass === 0 || counterpartySet.size <= 1
	      ? 0
	      : clampBps(
	          Math.floor(
	            (-pairMasses.reduce((sum, mass) => {
	              const p = mass / totalMass;
	              return p > 0 ? sum + p * Math.log(p) : sum;
	            }, 0) /
	              Math.log(counterpartySet.size)) *
	              10000
	          )
	        );
	  const reciprocalNumerator = [...counterpartySet].reduce((sum, counterparty) => sum + 2 * Math.min(outbound.get(counterparty) ?? 0, inbound.get(counterparty) ?? 0), 0);
	  const reciprocalDenominator = [...counterpartySet].reduce((sum, counterparty) => sum + (outbound.get(counterparty) ?? 0) + (inbound.get(counterparty) ?? 0), 0);
	  const seedSet = new Set(input.trusted_seeds ?? []);
	  const adversarialSeedSet = new Set(input.adversarial_seeds ?? []);
	  const seedMass = incident.reduce((sum, edge) => sum + (edge.src === input.subject && seedSet.has(edge.dst) ? Math.max(0, signedEffectiveWeight(edge, input.graph_profile)) : 0), 0);
	  const trustedNeighborMass = incident.reduce((sum, edge) => {
	    const neighbor = edge.src === input.subject ? edge.dst : edge.dst === input.subject ? edge.src : undefined;
	    const modelScore = neighbor ? clampBps(input.trusted_neighbor_scores_bps?.[neighbor] ?? (seedSet.has(neighbor) ? 10000 : 0)) : 0;
	    return sum + Math.floor((Math.max(0, signedEffectiveWeight(edge, input.graph_profile)) * modelScore) / 10000);
	  }, 0);
	  const adversarialMass = incident.reduce((sum, edge) => sum + (adversarialSeedSet.has(edge.src) || adversarialSeedSet.has(edge.dst) ? Math.max(0, signedEffectiveWeight(edge, input.graph_profile)) : 0), 0);
	  const communitiesResult = communityResult(input.graph, input.graph_profile);
	  const communities = communitiesResult.assignments;
	  const community = componentOfSubject(input.graph, input.subject, input.graph_profile);
	  const communityTouching = input.graph.edges.filter((edge) => community.has(edge.src) || community.has(edge.dst));
	  const communityMass = communityTouching.reduce((sum, edge) => sum + Math.max(0, signedEffectiveWeight(edge, input.graph_profile)), 0);
	  const communityEscapeMass = communityTouching.reduce(
	    (sum, edge) => sum + (community.has(edge.src) !== community.has(edge.dst) ? Math.max(0, signedEffectiveWeight(edge, input.graph_profile)) : 0),
	    0
	  );
	  const communityMasses = new Map<number, number>();
	  for (const edge of input.graph.edges) {
	    const srcCommunity = communities.get(edge.src);
	    const dstCommunity = communities.get(edge.dst);
	    const mass = Math.max(0, signedEffectiveWeight(edge, input.graph_profile));
	    if (srcCommunity !== undefined) communityMasses.set(srcCommunity, (communityMasses.get(srcCommunity) ?? 0) + mass);
	    if (dstCommunity !== undefined && dstCommunity !== srcCommunity) communityMasses.set(dstCommunity, (communityMasses.get(dstCommunity) ?? 0) + mass);
	  }
	  const totalCommunityMass = [...communityMasses.values()].reduce((sum, mass) => sum + mass, 0);
	  const communityHhi = totalCommunityMass === 0 ? 10000 : Math.floor([...communityMasses.values()].reduce((sum, mass) => sum + (mass / totalCommunityMass) ** 2, 0) * 10000);
	  const trustedDistance = shortestSeedDistance(input.graph, input.subject, seedSet, input.graph_profile);
	  const adversarialDistance = shortestSeedDistance(input.graph, input.subject, adversarialSeedSet, input.graph_profile);
	  const pagerank = pageRankScores(input.graph, input.graph_profile, input.trusted_seeds, input.subject);
	  const firstHopSeedScore = bps(trustedNeighborMass, totalMass);
	  const secondHopSeedMass = input.graph.edges.reduce((sum, edge) => {
	    if (!counterpartySet.has(edge.src) || !seedSet.has(edge.dst)) return sum;
	    return sum + Math.max(0, signedEffectiveWeight(edge, input.graph_profile));
	  }, 0);
	  const pprLite = clampBps(Math.floor(firstHopSeedScore * 0.85 + bps(secondHopSeedMass, Math.max(1, communityMass)) * 0.15));
	  const unsignedVectorBasis = {
	    subject: input.subject,
	    graph_profile_id: input.graph_profile_id,
	    graph_hash: sha256Hex(canonicalBytes(input.graph)),
	    trusted_seed_commitment: sha256Hex(canonicalBytes([...(input.trusted_seeds ?? [])].sort())),
	    adversarial_seed_commitment: sha256Hex(canonicalBytes([...(input.adversarial_seeds ?? [])].sort()))
	  };
	  return {
    type: "tsl.graph_feature_vector.v1",
    subject: input.subject,
    graph_profile_id: input.graph_profile_id,
    computed_at: input.computed_at ?? new Date().toISOString(),
	    weighted_degree_bps: clampBps(totalMass),
	    reciprocity_bps: bps(reciprocalNumerator, reciprocalDenominator),
	    counterparty_hhi_bps: hhi,
	    counterparty_entropy_bps: entropy,
	    effective_counterparty_count_milli: totalMass === 0 ? 0 : Math.floor(Math.exp((entropy / 10000) * Math.log(Math.max(1, counterpartySet.size))) * 1000),
	    seed_escape_bps: bps(seedMass, totalMass),
	    adversarial_proximity_bps: bps(adversarialMass, totalMass),
		    community_algorithm_id: input.graph_profile ? normalizeCommunityAlgorithm(input.graph_profile.community_detection.algorithm) : "connected_components_v0",
	    community_escape_bps: bps(communityEscapeMass, communityMass),
	    community_diversity_bps: clampBps(10000 - communityHhi),
	    conductance_bps: bps(communityEscapeMass, communityMass + communityEscapeMass),
	    trusted_neighbor_mass_bps: bps(trustedNeighborMass, totalMass),
	    trusted_seed_distance_bps: distanceScoreBps(trustedDistance),
	    adversarial_seed_distance_bps: distanceScoreBps(adversarialDistance),
	    pagerank_bps: pagerank.get(input.subject) ?? 0,
	    ppr_lite_bps: pprLite,
	    modularity_bps: communitiesResult.modularity_bps,
	    community_pass_count: communitiesResult.pass_count,
	    recomputation_commitment: sha256Hex(canonicalBytes(unsignedVectorBasis)),
    privacy_disclosure_level: "aggregate_only",
    signature: input.signature ?? ("0x00" as HexSig)
  };
}

export function graphFeatureVectorV1Hash(vector: GraphFeatureVectorUnsignedV1 | GraphFeatureVectorV1): Hex32 {
  return hashSignedObject(V2_DOMAIN_TAGS.GRAPH_FEATURE_VECTOR_V1, vector as unknown as Record<string, unknown>);
}

export function computeSybilAssessmentV0(input: {
  subject: TrustID;
  issuer?: TrustID;
  graph: GraphV0;
  graph_profile: GraphProfileV2;
  trusted_seeds?: TrustID[];
  adversarial_seeds?: TrustID[];
  sybil_profile?: {
    profile_id?: string;
    adversary_tier?: SybilAssessmentV1["adversary_tier_assumed"];
    min_evidence_mass?: number;
    base_identity_cost_minor_units?: number;
    internal_edge_cost_minor_units?: number;
    time_aging_cost_minor_units?: number;
    external_receipt_cost_minor_units?: number;
    attestation_cost_minor_units?: number;
    compromise_cost_minor_units?: number;
    evasion_cost_minor_units?: number;
    expected_benefit_minor_units?: number;
    attack_scenario?: string;
  };
  evidence_commitment?: Hex32;
  computed_at?: RFC3339;
  signature?: HexSig;
}): SybilAssessmentV1 {
  const edgeFloor = input.graph_profile.community_detection.edge_weight_floor_bps ?? 1000;
  const cluster = componentOfSubject(input.graph, input.subject, input.graph_profile);
  const trustedSeedSet = new Set(input.trusted_seeds ?? []);
  const adversarialSeedSet = new Set(input.adversarial_seeds ?? []);
  const tier = input.sybil_profile?.adversary_tier ?? "B2";
  const tierPolicy: Record<SybilAssessmentV1["adversary_tier_assumed"], {
    risk_adjustment_bps: number;
    high_threshold_bps: number;
    elevated_threshold_bps: number;
    contamination_threshold_bps: number;
    cost_multiplier_bps: number;
    min_evidence_mass: number;
    default_scenario: string;
  }> = {
    B0: {
      risk_adjustment_bps: -750,
      high_threshold_bps: 7800,
      elevated_threshold_bps: 6800,
      contamination_threshold_bps: 3500,
      cost_multiplier_bps: 7000,
      min_evidence_mass: 500,
      default_scenario: "low_capability_dense_farm"
    },
    B1: {
      risk_adjustment_bps: -250,
      high_threshold_bps: 7400,
      elevated_threshold_bps: 6400,
      contamination_threshold_bps: 3000,
      cost_multiplier_bps: 8500,
      min_evidence_mass: 750,
      default_scenario: "basic_aged_farm"
    },
    B2: {
      risk_adjustment_bps: 0,
      high_threshold_bps: 7000,
      elevated_threshold_bps: 6500,
      contamination_threshold_bps: 2500,
      cost_multiplier_bps: 10000,
      min_evidence_mass: 1000,
      default_scenario: "reference_cluster_assessment"
    },
    B3: {
      risk_adjustment_bps: 400,
      high_threshold_bps: 6600,
      elevated_threshold_bps: 5900,
      contamination_threshold_bps: 2200,
      cost_multiplier_bps: 13500,
      min_evidence_mass: 1250,
      default_scenario: "compromised_account_cluster"
    },
    B4: {
      risk_adjustment_bps: 750,
      high_threshold_bps: 6200,
      elevated_threshold_bps: 5500,
      contamination_threshold_bps: 1800,
      cost_multiplier_bps: 18000,
      min_evidence_mass: 1500,
      default_scenario: "issuer_collusion_bridge"
    },
    B5: {
      risk_adjustment_bps: 1100,
      high_threshold_bps: 5800,
      elevated_threshold_bps: 5000,
      contamination_threshold_bps: 1500,
      cost_multiplier_bps: 25000,
      min_evidence_mass: 2000,
      default_scenario: "relay_provider_auditor_consistency_attack"
    }
  };
  const tierConfig = tierPolicy[tier];
  const internalEdges = input.graph.edges.filter((edge) => cluster.has(edge.src) && cluster.has(edge.dst));
  const touchingEdges = input.graph.edges.filter((edge) => cluster.has(edge.src) || cluster.has(edge.dst));
  const internalMass = internalEdges.reduce((sum, edge) => sum + Math.max(0, signedEffectiveWeight(edge, input.graph_profile)), 0);
  const touchingMass = touchingEdges.reduce((sum, edge) => sum + Math.max(0, signedEffectiveWeight(edge, input.graph_profile)), 0);
  const externalEdges = touchingEdges.filter((edge) => !(cluster.has(edge.src) && cluster.has(edge.dst)));
  const trustedMass = externalEdges.reduce((sum, edge) => sum + (cluster.has(edge.src) && trustedSeedSet.has(edge.dst) ? Math.max(0, signedEffectiveWeight(edge, input.graph_profile)) : 0), 0);
  const adversarialMass = touchingEdges.reduce((sum, edge) => sum + (adversarialSeedSet.has(edge.src) || adversarialSeedSet.has(edge.dst) ? Math.max(0, signedEffectiveWeight(edge, input.graph_profile)) : 0), 0);
  const concentration = bps(internalMass, touchingMass);
  const trustedEscape = bps(trustedMass, touchingMass);
  const internalReceiptMass = internalEdges
    .filter((edge) => edge.type.includes("receipt"))
    .reduce((sum, edge) => sum + Math.max(0, signedEffectiveWeight(edge, input.graph_profile)), 0);
  const touchingReceiptMass = touchingEdges
    .filter((edge) => edge.type.includes("receipt"))
    .reduce((sum, edge) => sum + Math.max(0, signedEffectiveWeight(edge, input.graph_profile)), 0);
  const internalReceiptRatio = bps(internalReceiptMass, touchingReceiptMass);
  const receiptPairs = new Map<string, { forward: number; reverse: number }>();
  for (const edge of internalEdges.filter((candidate) => candidate.type.includes("receipt"))) {
    const [left, right] = [edge.src, edge.dst].sort();
    const key = `${left}\u0000${right}`;
    const pair = receiptPairs.get(key) ?? { forward: 0, reverse: 0 };
    if (edge.src === left) pair.forward += Math.max(0, signedEffectiveWeight(edge, input.graph_profile));
    else pair.reverse += Math.max(0, signedEffectiveWeight(edge, input.graph_profile));
    receiptPairs.set(key, pair);
  }
  const receiptSymmetryNumerator = [...receiptPairs.values()].reduce((sum, pair) => sum + 2 * Math.min(pair.forward, pair.reverse), 0);
  const receiptSymmetryDenominator = [...receiptPairs.values()].reduce((sum, pair) => sum + pair.forward + pair.reverse, 0);
  const createdTimes = internalEdges.map((edge) => Date.parse(edge.created_at ?? edge.timestamp)).filter(Number.isFinite);
  const creationSync =
    createdTimes.length < 2
      ? 0
      : clampBps(10000 - bps(Math.max(...createdTimes) - Math.min(...createdTimes), 1000 * 60 * 60 * 24 * 30));
  const issuers = internalEdges.map((edge) => edge.issuer).filter((issuer): issuer is TrustID => Boolean(issuer));
  const issuerReuse =
    issuers.length === 0
      ? 0
      : bps(
          Math.max(...[...new Set(issuers)].map((issuer) => issuers.filter((candidate) => candidate === issuer).length)),
          issuers.length
        );
  const externalMassByNode = new Map<TrustID, number>();
  for (const edge of externalEdges) {
    const other = cluster.has(edge.src) ? edge.dst : edge.src;
    externalMassByNode.set(other, (externalMassByNode.get(other) ?? 0) + Math.max(0, signedEffectiveWeight(edge, input.graph_profile)));
  }
  const externalMass = [...externalMassByNode.values()].reduce((sum, mass) => sum + mass, 0);
  const externalHhi = externalMass === 0 ? 10000 : Math.floor([...externalMassByNode.values()].reduce((sum, mass) => sum + (mass / externalMass) ** 2, 0) * 10000);
  const externalDiversity = clampBps(10000 - externalHhi);
  const seedContamination = bps(adversarialMass, touchingMass);
  const receiptSymmetry = bps(receiptSymmetryNumerator, receiptSymmetryDenominator);
  const risk_score_bps = clampBps(
    Math.floor(
      (concentration * 20 +
        internalReceiptRatio * 12 +
        receiptSymmetry * 8 +
        creationSync * 12 +
        issuerReuse * 10 +
        seedContamination * 22 +
        (10000 - trustedEscape) * 10 +
        (10000 - externalDiversity) * 6) /
        100
    ) + tierConfig.risk_adjustment_bps
  );
  const minEvidenceMass = input.sybil_profile?.min_evidence_mass ?? tierConfig.min_evidence_mass;
  const risk_label =
    touchingMass < minEvidenceMass
      ? "insufficient_evidence"
      : concentration > 8500 && trustedEscape < 500
        ? "high"
      : seedContamination > tierConfig.contamination_threshold_bps
        ? "elevated"
      : risk_score_bps >= tierConfig.high_threshold_bps
          ? "high"
      : risk_score_bps >= tierConfig.elevated_threshold_bps
          ? "elevated"
          : internalReceiptRatio > 7500 && trustedEscape < 1500
            ? "medium"
            : "low";
  const costComponents = {
    identity_cost_minor_units: Math.floor((cluster.size * (input.sybil_profile?.base_identity_cost_minor_units ?? 25000) * tierConfig.cost_multiplier_bps) / 10000),
    time_aging_cost_minor_units: Math.floor((cluster.size * (input.sybil_profile?.time_aging_cost_minor_units ?? 1000) * tierConfig.cost_multiplier_bps) / 10000),
    external_receipt_cost_minor_units: Math.floor(((externalMass / 10000) * (input.sybil_profile?.external_receipt_cost_minor_units ?? 7500) * tierConfig.cost_multiplier_bps) / 10000),
    attestation_cost_minor_units: Math.floor((internalEdges.filter((edge) => edge.type.includes("attestation")).length * (input.sybil_profile?.attestation_cost_minor_units ?? 10000) * tierConfig.cost_multiplier_bps) / 10000),
    compromise_cost_minor_units: Math.floor(((input.sybil_profile?.compromise_cost_minor_units ?? 0) * tierConfig.cost_multiplier_bps) / 10000),
    evasion_cost_minor_units: Math.floor(((risk_score_bps / 10000) * (input.sybil_profile?.evasion_cost_minor_units ?? 5000) * tierConfig.cost_multiplier_bps) / 10000)
  };
  const attackCost = Object.values(costComponents).reduce((sum, value) => sum + value, 0) + Math.floor(internalMass / 10000) * (input.sybil_profile?.internal_edge_cost_minor_units ?? 5000);
  const seedSetCommitment = sha256Hex(
    canonicalBytes({
      trusted: [...trustedSeedSet].sort(),
      adversarial: [...adversarialSeedSet].sort(),
      graph_profile_id: input.graph_profile.profile_id
    })
  );
  return {
	    type: "tsl.sybil_assessment.v1",
	    subject: input.subject,
	    issuer: input.issuer ?? "did:tsl:provider:reference-sybil",
    sybil_profile_id: input.sybil_profile?.profile_id ?? "sybil-reference-v0",
    graph_profile_id: input.graph_profile.profile_id,
    seed_set_commitment: seedSetCommitment,
    evidence_commitment: input.evidence_commitment ?? sha256Hex(canonicalBytes({ graph_hash: sha256Hex(canonicalBytes(input.graph)), seed_set_commitment: seedSetCommitment })),
    cluster_id_commitment: sha256Hex(canonicalBytes({ subject: input.subject, graph_profile_id: input.graph_profile.profile_id })),
    computed_at: input.computed_at ?? new Date().toISOString(),
    adversary_tier_assumed: tier,
    cluster_size_bucket: `${cluster.size}-${cluster.size}`,
    cluster_concentration_bps: concentration,
    trusted_escape_bps: trustedEscape,
    internal_receipt_ratio_bps: internalReceiptRatio,
    creation_sync_bps: creationSync,
    issuer_reuse_bps: issuerReuse,
    external_diversity_bps: externalDiversity,
    seed_contamination_bps: seedContamination,
    receipt_symmetry_bps: receiptSymmetry,
    attack_cost_minor_units: Math.max(0, attackCost),
    cost_components: costComponents,
    expected_benefit_minor_units: input.sybil_profile?.expected_benefit_minor_units ?? 0,
    attack_scenario: input.sybil_profile?.attack_scenario ?? tierConfig.default_scenario,
    risk_score_bps,
    risk_label,
    privacy_level: "cluster_commitment_only",
    signature: input.signature ?? ("0x00" as HexSig)
  };
}

export function sybilAssessmentV1Hash(assessment: SybilAssessmentUnsignedV1 | SybilAssessmentV1): Hex32 {
  return hashSignedObject(V2_DOMAIN_TAGS.SYBIL_ASSESSMENT_V1, assessment as unknown as Record<string, unknown>);
}

function fixedPointSqrt(value: number): number {
  if (value <= 0) return 0;
  let low = 0;
  let high = Math.max(1, value);
  while (low <= high) {
    const mid = Math.floor((low + high) / 2);
    const square = mid * mid;
    if (square === value) return mid;
    if (square < value) low = mid + 1;
    else high = mid - 1;
  }
  return high;
}

function invertRegularizedMatrixFixed(matrix: number[][], regularization: number): number[][] | null {
  const size = matrix.length;
  if (!size || matrix.some((row) => row.length !== size)) return null;
  const scale = 1_000_000n;
  const augmented = matrix.map((row, rowIndex) => [
    ...row.map((value, columnIndex) => BigInt(Math.trunc(value + (rowIndex === columnIndex ? regularization : 0)))),
    ...Array.from({ length: size }, (_, columnIndex) => (columnIndex === rowIndex ? 1n : 0n))
  ]);
  for (let column = 0; column < size; column += 1) {
    let pivot = column;
    for (let row = column + 1; row < size; row += 1) {
      if (absBigInt(augmented[row][column]) > absBigInt(augmented[pivot][column])) pivot = row;
    }
    if (augmented[pivot][column] === 0n) return null;
    if (pivot !== column) [augmented[pivot], augmented[column]] = [augmented[column], augmented[pivot]];
    const pivotValue = augmented[column][column];
    for (let item = 0; item < size * 2; item += 1) augmented[column][item] = (augmented[column][item] * scale) / pivotValue;
    for (let row = 0; row < size; row += 1) {
      if (row === column) continue;
      const factor = augmented[row][column];
      for (let item = 0; item < size * 2; item += 1) augmented[row][item] -= (factor * augmented[column][item]) / scale;
    }
  }
  return augmented.map((row) => row.slice(size).map((value) => Number(value)));
}

function absBigInt(value: bigint): bigint {
  return value < 0n ? -value : value;
}

export function computeDriftReportV0(input: {
  subject: TrustID;
  drift_profile_id?: string;
  baseline_values_bps?: number[];
  observation_values_bps?: number[];
  feature_history?: Array<{
    timestamp: RFC3339;
    components: Partial<Record<"key" | "graph" | "action" | "cadence" | "claim" | "agent" | "local", number>>;
    verified_event?: boolean;
    high_value_action?: boolean;
    new_delegation_pattern?: boolean;
    adverse_evidence?: boolean;
  }>;
  baseline_window_days: number;
  observation_window_days: number;
  min_baseline_points?: number;
  dormant_days?: number;
  last_verified_event_at?: RFC3339;
  cohort_baseline_components?: Array<Partial<Record<"key" | "graph" | "action" | "cadence" | "claim" | "agent" | "local", number>>>;
  high_value_action?: boolean;
  new_delegation_pattern?: boolean;
  adverse_evidence?: boolean;
  component_scores_bps?: Partial<Record<"key" | "graph" | "action" | "cadence" | "claim" | "agent" | "local", number>>;
  computed_at?: RFC3339;
  signature?: HexSig;
}): DriftReportV1 {
  if ((input.baseline_values_bps || input.observation_values_bps) && process.env["TSL_" + "DEV_DRIFT_INPUTS"] !== "true") {
    throw new Error("TSL_DEV_DRIFT_INPUTS_REQUIRED");
  }
  const computedAt = input.computed_at ?? new Date().toISOString();
  const atMs = Date.parse(computedAt);
  const componentKeys = ["key", "graph", "action", "cadence", "claim", "agent", "local"] as const;
  const baselineHistory = (input.feature_history ?? []).filter((point) => {
    const ms = Date.parse(point.timestamp);
    return Number.isFinite(ms) && ms >= atMs - (input.baseline_window_days + input.observation_window_days) * 86400000 && ms < atMs - input.observation_window_days * 86400000;
  });
  const observationHistory = (input.feature_history ?? []).filter((point) => {
    const ms = Date.parse(point.timestamp);
    return Number.isFinite(ms) && ms >= atMs - input.observation_window_days * 86400000 && ms <= atMs;
  });
  const baselineValues =
    input.baseline_values_bps ??
    baselineHistory.map((point) => Math.floor(componentKeys.reduce((sum, component) => sum + clampBps(point.components[component] ?? 0), 0) / componentKeys.length));
  const observationValues =
    input.observation_values_bps ??
    observationHistory.map((point) => Math.floor(componentKeys.reduce((sum, component) => sum + clampBps(point.components[component] ?? 0), 0) / componentKeys.length));

  if (baselineValues.length < (input.min_baseline_points ?? 2)) {
    const cohortAvailable = Boolean(input.cohort_baseline_components?.length);
    if (cohortAvailable && observationHistory.length) {
      const syntheticHistory = input.cohort_baseline_components!.map((components, index) => ({
        timestamp: new Date(atMs - (input.observation_window_days + index + 1) * 86400000).toISOString(),
        components
      }));
      const cohortReport = computeDriftReportV0({
        ...input,
        feature_history: [...syntheticHistory, ...(input.feature_history ?? [])],
        cohort_baseline_components: undefined,
        signature: input.signature
      });
      return {
        ...cohortReport,
        sparse_mode: "cohort_baseline",
        reason_codes: [...new Set(["COHORT_BASELINE", ...cohortReport.reason_codes])],
        covariance_profile_commitment: sha256Hex(canonicalBytes({ estimator: "robust_median_covariance_fixed_point_v1", regularization: 10000, sparse_mode: "cohort_baseline" }))
      };
    }
    return {
      type: "tsl.drift_report.v1",
      subject: input.subject,
      ...(input.drift_profile_id ? { drift_profile_id: input.drift_profile_id } : {}),
      computed_at: computedAt,
      baseline_window_days: input.baseline_window_days,
      observation_window_days: input.observation_window_days,
      ...(input.last_verified_event_at ? { last_verified_event_at: input.last_verified_event_at } : {}),
      sparse_mode: cohortAvailable ? "cohort_baseline" : "insufficient_baseline",
      recomputation_status: "recomputed_match",
      drift_score_bps: 0,
      drift_label: "insufficient_baseline",
      action: "none",
      reason_codes: ["INSUFFICIENT_BASELINE"],
      signature: input.signature ?? ("0x00" as HexSig)
    };
  }
  const median = (values: number[]) => {
    const sorted = [...values].map(clampBps).sort((a, b) => a - b);
    return sorted.length % 2 ? sorted[Math.floor(sorted.length / 2)] : Math.floor((sorted[sorted.length / 2 - 1] + sorted[sorted.length / 2]) / 2);
  };
  const robustDistance = (baseline: number[], observation: number[]) => {
    const baselineMedian = median(baseline);
    const deviations = baseline.map((value) => Math.abs(value - baselineMedian));
    const mad = Math.max(100, median(deviations));
    const observationMedian = observation.length ? median(observation) : baselineMedian;
    return clampBps(Math.floor((Math.abs(observationMedian - baselineMedian) * 1000) / mad));
  };
  const toVector = (point: { components: Partial<Record<(typeof componentKeys)[number], number>> }): number[] =>
    componentKeys.map((component) => clampBps(point.components[component] ?? 0));
  const medianVector = (vectors: number[][]): number[] =>
    componentKeys.map((_, index) => median(vectors.map((vector) => vector[index] ?? 0)));
  const covarianceMatrix = (vectors: number[][], center: number[]): number[][] => {
    const size = componentKeys.length;
    const matrix = Array.from({ length: size }, () => Array.from({ length: size }, () => 0));
    const denominator = Math.max(1, vectors.length - 1);
    for (const vector of vectors) {
      for (let row = 0; row < size; row += 1) {
        for (let column = 0; column < size; column += 1) {
          matrix[row][column] += ((vector[row] ?? 0) - center[row]) * ((vector[column] ?? 0) - center[column]);
        }
      }
    }
    for (let row = 0; row < size; row += 1) {
      for (let column = 0; column < size; column += 1) {
        matrix[row][column] = Math.floor(matrix[row][column] / denominator);
      }
      matrix[row][row] = Math.max(matrix[row][row], 10000);
    }
    return matrix;
  };
	  const robustMahalanobisBps = () => {
	    const baselineVectors = baselineHistory.map(toVector);
	    const observationVectors = observationHistory.map(toVector);
	    if (baselineVectors.length < (input.min_baseline_points ?? 2) || observationVectors.length === 0) return 0;
	    const center = medianVector(baselineVectors);
	    const covariance = covarianceMatrix(baselineVectors, center);
	    const observationMean = componentKeys.map((_, index) => Math.floor(observationVectors.reduce((sum, vector) => sum + (vector[index] ?? 0), 0) / observationVectors.length));
	    const inverse = invertRegularizedMatrixFixed(covariance, 10000);
	    if (!inverse) return 0;
	    const delta = componentKeys.map((_, index) => observationMean[index] - center[index]);
	    let quadraticScaled = 0;
	    for (let row = 0; row < delta.length; row += 1) {
	      for (let column = 0; column < delta.length; column += 1) {
	        quadraticScaled += Math.trunc((delta[row] * inverse[row][column] * delta[column]) / 1_000_000);
	      }
	    }
	    return clampBps(fixedPointSqrt(Math.max(0, quadraticScaled)) * 1000);
	  };
  const derivedComponents: Partial<Record<(typeof componentKeys)[number], number>> = {};
  for (const component of componentKeys) {
    const baseline = baselineHistory.map((point) => point.components[component]).filter((value): value is number => typeof value === "number");
    const observation = observationHistory.map((point) => point.components[component]).filter((value): value is number => typeof value === "number");
    if (baseline.length >= (input.min_baseline_points ?? 2)) derivedComponents[component] = robustDistance(baseline, observation);
  }
  const componentScores = Object.fromEntries(
    Object.entries({ ...derivedComponents, ...(input.component_scores_bps ?? {}) }).map(([component, score]) => [component, clampBps(Number(score ?? 0))])
  ) as Partial<Record<"key" | "graph" | "action" | "cadence" | "claim" | "agent" | "local", number>>;
  const componentValues = Object.entries(componentScores).map(([component, score]) => [component, clampBps(score ?? 0)] as const);
  const componentDrift = componentValues.length ? Math.max(...componentValues.map(([, score]) => score)) : 0;
  const lastVerifiedEventAt =
    input.last_verified_event_at ??
    [...(input.feature_history ?? [])]
      .filter((point) => point.verified_event)
      .map((point) => point.timestamp)
      .sort()
      .at(-1);
  const daysSinceLastVerifiedEvent =
    lastVerifiedEventAt && Number.isFinite(Date.parse(lastVerifiedEventAt))
      ? Math.floor((atMs - Date.parse(lastVerifiedEventAt)) / 86400000)
      : process.env["TSL_" + "DEV_DRIFT_INPUTS"] === "true"
        ? input.dormant_days
        : undefined;
  const historyHighValue = observationHistory.some((point) => point.high_value_action);
  const historyNewDelegation = observationHistory.some((point) => point.new_delegation_pattern);
  const historyAdverse = observationHistory.some((point) => point.adverse_evidence);
  const drift = Math.max(robustDistance(baselineValues, observationValues), robustMahalanobisBps(), componentDrift);
  const dormant = (daysSinceLastVerifiedEvent ?? 0) >= (input.dormant_days ?? 90) && (input.high_value_action === true || input.new_delegation_pattern === true || historyHighValue || historyNewDelegation);
  const severeAdverse = (input.adverse_evidence === true || historyAdverse) && drift >= 5000;
  const driftLabel = dormant
    ? "dormant_reactivation"
    : severeAdverse || drift >= 7500
      ? "severe"
      : drift >= 5000
        ? "high"
        : drift >= 2500
          ? "moderate"
          : "stable";
  const driftAction = dormant
    ? "step_up"
    : driftLabel === "severe"
      ? "human_review"
      : driftLabel === "high"
        ? "step_up"
        : driftLabel === "moderate"
          ? "lower_confidence"
          : "none";
  return {
    type: "tsl.drift_report.v1",
    subject: input.subject,
    ...(input.drift_profile_id ? { drift_profile_id: input.drift_profile_id } : {}),
    computed_at: computedAt,
    baseline_window_days: input.baseline_window_days,
    observation_window_days: input.observation_window_days,
    feature_history_commitment: input.feature_history ? sha256Hex(canonicalBytes(input.feature_history)) : undefined,
    baseline_profile_commitment: sha256Hex(canonicalBytes({ baseline_window_days: input.baseline_window_days, min_baseline_points: input.min_baseline_points ?? 2 })),
    covariance_profile_commitment: sha256Hex(canonicalBytes({ estimator: "robust_median_covariance_fixed_point_v1", regularization: 10000 })),
    ...(lastVerifiedEventAt ? { last_verified_event_at: lastVerifiedEventAt } : {}),
    ...(daysSinceLastVerifiedEvent !== undefined ? { days_since_last_verified_event: Math.max(0, daysSinceLastVerifiedEvent) } : {}),
    sparse_mode: "none",
    recomputation_status: "recomputed_match",
    drift_score_bps: dormant ? Math.max(drift, 8000) : drift,
    drift_label: driftLabel,
    action: driftAction,
    reason_codes: dormant
      ? ["DORMANT_REACTIVATION", "NEW_HIGH_VALUE_ACTION", ...componentValues.map(([component]) => `DRIFT_${component.toUpperCase()}`)]
      : [
          ...(input.adverse_evidence ? ["ADVERSE_EVIDENCE"] : []),
          ...componentValues.filter(([, score]) => score >= 2500).map(([component]) => `DRIFT_${component.toUpperCase()}`)
        ],
    component_scores_bps: componentScores,
    signature: input.signature ?? ("0x00" as HexSig)
  };
}

export function driftReportV1Hash(report: DriftReportUnsignedV1 | DriftReportV1): Hex32 {
  return hashSignedObject(V2_DOMAIN_TAGS.DRIFT_REPORT_V1, report as unknown as Record<string, unknown>);
}

function bucketizeMetadataV0(metadata: unknown): Record<string, unknown> {
  const record = metadata && typeof metadata === "object" && !Array.isArray(metadata) ? (metadata as Record<string, unknown>) : {};
  const length = typeof record.content_length_bytes === "number" ? record.content_length_bytes : undefined;
  const latency = typeof record.response_latency_seconds === "number" ? record.response_latency_seconds : undefined;
  const timestamp = typeof record.timestamp === "string" ? Date.parse(record.timestamp) : NaN;
  const timeBucket = Number.isFinite(timestamp) ? new Date(Math.floor(timestamp / 3600000) * 3600000).toISOString() : record.time_bucket;
  return {
    event_class: record.event_class ?? "unknown",
    time_bucket: timeBucket ?? "unknown",
    length_bucket:
      length === undefined
        ? record.length_bucket ?? "unknown"
        : length <= 256
          ? "0-256"
          : length <= 1024
            ? "257-1024"
            : length <= 4096
              ? "1025-4096"
              : length <= 16384
                ? "4097-16384"
                : "above-16384",
    response_latency_bucket:
      latency === undefined
        ? record.response_latency_bucket ?? "unknown"
        : latency < 60
          ? "below-1-minute"
          : latency < 600
            ? "1-10-minutes"
            : latency < 3600
              ? "10-60-minutes"
              : latency < 86400
                ? "1-24-hours"
                : "above-24-hours",
    counterparty_class: record.counterparty_class ?? "private-undisclosed",
    key_lineage: record.key_lineage ?? "same-key",
    receipt_class: record.receipt_class ?? "none"
  };
}

export function computeMetadataFingerprintCommitmentV0(input: {
  subject: TrustID;
  metadata: unknown;
  master_key_hex: string;
  verifier_domain: string;
  epoch: string;
  purpose: MetadataFingerprintCommitmentV1["scope_class"];
  bucket_profile: string;
  salt_hex: Hex32;
  expires_at: RFC3339;
  signature?: HexSig;
}): MetadataFingerprintCommitmentV1 {
  const scopeMaterial = canonicalBytes({ verifier_domain: input.verifier_domain, epoch: input.epoch, purpose: input.purpose });
  const scopeKey = hmac(sha256, hexToBytes(input.master_key_hex), concatBytes(encoder.encode("tsl-fp-v1"), scopeMaterial));
  const bucketed = bucketizeMetadataV0(input.metadata);
  const fingerprint = hmac(sha256, scopeKey, concatBytes(encoder.encode("tsl.metadata.fp.v1"), canonicalBytes(bucketed)));
  const commitment = sha256Hex(concatBytes(encoder.encode("tsl.metadata.commit.v1"), fingerprint, hexToBytes(input.salt_hex)));
  return {
    type: "tsl.metadata_fingerprint_commitment.v1",
    subject: input.subject,
    scope_class: input.purpose,
    scope_commitment: sha256Hex(scopeMaterial),
    bucket_profile: input.bucket_profile,
    fingerprint_commitment: commitment,
    salt_commitment: sha256Hex(hexToBytes(input.salt_hex)),
    created_at_bucket: String(bucketed.time_bucket),
    expires_at: input.expires_at,
    disclosure_policy:
      input.purpose === "local_only"
        ? "local_only"
        : input.purpose === "public_commitment"
          ? "public_commitment_only"
          : input.purpose === "provider_ephemeral"
            ? "zk_only"
            : "selective",
    signature: input.signature ?? ("0x00" as HexSig)
  };
}

export function metadataFingerprintCommitmentV1Hash(
  commitment: MetadataFingerprintCommitmentUnsignedV1 | MetadataFingerprintCommitmentV1
): Hex32 {
  return hashSignedObject(V2_DOMAIN_TAGS.METADATA_FINGERPRINT_V1, commitment as unknown as Record<string, unknown>);
}

export function buildDelegationPolicyV2(input: Omit<DelegationPolicyUnsignedV2, "type" | "policy_id"> & { policy_id?: Hex32 }): DelegationPolicyUnsignedV2 {
  return {
    type: "tsl.delegation_policy.v2",
    policy_id: input.policy_id ?? randomHex32(),
    principal: input.principal,
    delegate: input.delegate,
    effect: input.effect,
    actions: [...input.actions].sort(),
    resources: [...input.resources].sort(),
    constraints: input.constraints,
    ...(input.subdelegation ? { subdelegation: input.subdelegation } : {}),
    ...(input.parent_policy_id !== undefined ? { parent_policy_id: input.parent_policy_id } : {}),
    valid_from: input.valid_from,
    valid_until: input.valid_until,
    revocation_pointer: input.revocation_pointer,
    ...(input.nonce ? { nonce: input.nonce } : {})
  };
}

export function delegationPolicyV2Hash(policy: DelegationPolicyUnsignedV2 | DelegationPolicyV2): Hex32 {
  return hashSignedObject(V2_DOMAIN_TAGS.DELEGATION_POLICY_V2, policy as unknown as Record<string, unknown>);
}

export function signDelegationPolicyV2(input: DelegationPolicyUnsignedV2, seedHex: string): DelegationPolicyV2 {
  return { ...input, signature: signEd25519(delegationPolicyV2Hash(input), seedHex) };
}

export function buildAgentActionV2(input: Omit<AgentActionUnsignedV2, "type" | "action_id" | "issued_at"> & {
  action_id?: Hex32;
  issued_at?: RFC3339;
}): AgentActionUnsignedV2 {
  return {
    type: "tsl.agent_action.v2",
    action_id: input.action_id ?? randomHex32(),
    agent: input.agent,
    principal: input.principal,
    action: input.action,
    resource: input.resource,
    ...(input.tool ? { tool: input.tool } : {}),
    parameters_commitment: input.parameters_commitment,
    ...(input.parameter_disclosure_policy ? { parameter_disclosure_policy: input.parameter_disclosure_policy } : {}),
    delegation_chain_root: input.delegation_chain_root,
    nonce: input.nonce,
    ...(input.value_minor_units !== undefined ? { value_minor_units: input.value_minor_units } : {}),
    ...(input.human_approval_proof ? { human_approval_proof: input.human_approval_proof } : {}),
    issued_at: input.issued_at ?? new Date().toISOString()
  };
}

export function agentActionV2Hash(action: AgentActionUnsignedV2 | AgentActionV2): Hex32 {
  return hashSignedObject(V2_DOMAIN_TAGS.AGENT_ACTION_V2, action as unknown as Record<string, unknown>);
}

export function signAgentActionV2(input: AgentActionUnsignedV2, seedHex: string): AgentActionV2 {
  return { ...input, signature: signEd25519(agentActionV2Hash(input), seedHex) };
}

function resourceMatches(pattern: string, resource: string): boolean {
  return pattern === resource || (pattern.endsWith("*") && resource.startsWith(pattern.slice(0, -1)));
}

function actionMatches(actions: string[], action: string): boolean {
  return actions.includes(action) || actions.includes("*");
}

function policyMatchesAction(policy: DelegationPolicyV2, action: AgentActionV2): boolean {
  return actionMatches(policy.actions, action.action) && policy.resources.some((pattern) => resourceMatches(pattern, action.resource));
}

function parametersCommitment(parameters: unknown): Hex32 {
  return hashDomain("tsl.agent.parameters.v1", canonicalBytes(parameters));
}

function valueFromAction(action: AgentActionV2, parameters?: Record<string, unknown>): number {
  const fromParams = parameters?.value_minor_units;
  return Math.max(0, Math.trunc(action.value_minor_units ?? (typeof fromParams === "number" ? fromParams : 0)));
}

export function verifyDelegatedAgentActionV0(input: {
  action: AgentActionV2;
  delegation_chain: DelegationPolicyV2[];
  public_keys: Record<TrustID, string>;
  at_time?: RFC3339;
  revoked_policy_ids?: Hex32[];
  revoked_pointers?: string[];
  parameters?: Record<string, unknown>;
}): { ok: boolean; error_code?: string; effective_scope_commitment?: Hex32 } {
  const at = Date.parse(input.action.issued_at);
  if (!Number.isFinite(at)) return { ok: false, error_code: "TSL_TIMESTAMP_INVALID" };
  const agentKey = input.public_keys[input.action.agent];
  if (!agentKey || !verifyEd25519(agentKey, agentActionV2Hash(input.action), input.action.signature)) {
    return { ok: false, error_code: "TSL_AGENT_ACTION_SIGNATURE_INVALID" };
  }
  if (input.parameters && parametersCommitment(input.parameters) !== input.action.parameters_commitment) {
    return { ok: false, error_code: "TSL_DELEGATION_CONSTRAINT_VIOLATION" };
  }
  if (input.delegation_chain.length === 0) {
    return { ok: false, error_code: "TSL_DELEGATION_MISSING" };
  }
  if (input.delegation_chain.length > 0 && input.delegation_chain[0].principal !== input.action.principal) {
    return { ok: false, error_code: "TSL_DELEGATION_CHAIN_BROKEN" };
  }
  const expectedChainRoot = sha256Hex(canonicalBytes(input.delegation_chain.map((policy) => delegationPolicyV2Hash(policy))));
  if (input.action.delegation_chain_root !== expectedChainRoot) {
    return { ok: false, error_code: "TSL_DELEGATION_CHAIN_ROOT_MISMATCH" };
  }
  let expectedDelegate = input.action.agent;
  const allowedActions: string[][] = [];
  const allowedResources: string[][] = [];
  let maxValue = Number.MAX_SAFE_INTEGER;
  let requiresHumanApproval = false;
  let expectedParentPolicyId: Hex32 | null | undefined = null;
  const revokedIds = new Set(input.revoked_policy_ids ?? []);
  const revokedPointers = new Set(input.revoked_pointers ?? []);
  const policiesFromDelegateToPrincipal = [...input.delegation_chain].reverse();
  for (const [depth, policy] of policiesFromDelegateToPrincipal.entries()) {
    const principalKey = input.public_keys[policy.principal];
    if (!principalKey || !verifyEd25519(principalKey, delegationPolicyV2Hash(policy), policy.signature)) {
      return { ok: false, error_code: "TSL_DELEGATION_SIGNATURE_INVALID" };
    }
    if (revokedIds.has(policy.policy_id) || revokedPointers.has(policy.revocation_pointer)) {
      return { ok: false, error_code: "TSL_DELEGATION_REVOKED" };
    }
    if (Date.parse(policy.valid_from) > at || at >= Date.parse(policy.valid_until)) {
      return { ok: false, error_code: "TSL_DELEGATION_EXPIRED" };
    }
    if (policy.delegate !== expectedDelegate) {
      return { ok: false, error_code: "TSL_DELEGATION_CHAIN_BROKEN" };
    }
    if (expectedParentPolicyId !== null && expectedParentPolicyId !== undefined && policy.policy_id !== expectedParentPolicyId) {
      return { ok: false, error_code: "TSL_DELEGATION_CHAIN_BROKEN" };
    }
    if (policy.effect === "deny" && policyMatchesAction(policy, input.action)) {
      return { ok: false, error_code: "TSL_DELEGATION_SCOPE_VIOLATION" };
    }
    if (policy.effect !== "allow") continue;
    if (depth > 0) {
      const subdelegation = policy.subdelegation as
        | {
            allowed?: boolean;
            max_depth?: number;
            allowed_actions?: string[];
          }
        | undefined;
      if (subdelegation?.allowed !== true) return { ok: false, error_code: "TSL_DELEGATION_SCOPE_VIOLATION" };
      if (subdelegation?.max_depth !== undefined && depth > subdelegation.max_depth) return { ok: false, error_code: "TSL_DELEGATION_SCOPE_VIOLATION" };
      if (subdelegation?.allowed_actions && !actionMatches(subdelegation.allowed_actions, input.action.action)) {
        return { ok: false, error_code: "TSL_DELEGATION_SCOPE_VIOLATION" };
      }
    }
    allowedActions.push(policy.actions);
    allowedResources.push(policy.resources);
    const constraints = policy.constraints as {
      max_value_minor_units?: number;
      currency?: string;
      allowed_tools?: string[];
      denied_tools?: string[];
      allowed_counterparty_commitments?: string[];
      max_actions_per_window?: number;
      observed_actions_in_window?: number;
      requires_human_approval?: boolean;
      requires_human_approval_above_minor_units?: number;
    };
    if (constraints.max_value_minor_units !== undefined) maxValue = Math.min(maxValue, constraints.max_value_minor_units);
    if (constraints.requires_human_approval === true) requiresHumanApproval = true;
    if (constraints.requires_human_approval_above_minor_units !== undefined && valueFromAction(input.action, input.parameters) > constraints.requires_human_approval_above_minor_units) {
      requiresHumanApproval = true;
    }
    if (constraints.allowed_tools && (!input.action.tool || !constraints.allowed_tools.includes(input.action.tool))) {
      return { ok: false, error_code: "TSL_DELEGATION_CONSTRAINT_VIOLATION" };
    }
    if (constraints.denied_tools?.includes(input.action.tool ?? "")) {
      return { ok: false, error_code: "TSL_DELEGATION_CONSTRAINT_VIOLATION" };
    }
    if (constraints.currency && input.parameters?.currency !== constraints.currency) {
      return { ok: false, error_code: "TSL_DELEGATION_CONSTRAINT_VIOLATION" };
    }
    const counterpartyCommitment = input.parameters?.counterparty_commitment;
    if (constraints.allowed_counterparty_commitments && typeof counterpartyCommitment === "string" && !constraints.allowed_counterparty_commitments.includes(counterpartyCommitment)) {
      return { ok: false, error_code: "TSL_DELEGATION_CONSTRAINT_VIOLATION" };
    }
    if (
      constraints.max_actions_per_window !== undefined &&
      constraints.observed_actions_in_window !== undefined &&
      constraints.observed_actions_in_window >= constraints.max_actions_per_window
    ) {
      return { ok: false, error_code: "TSL_DELEGATION_CONSTRAINT_VIOLATION" };
    }
    expectedParentPolicyId = policy.parent_policy_id;
    expectedDelegate = policy.principal;
  }
  if (allowedActions.some((actions) => !actionMatches(actions, input.action.action))) {
    return { ok: false, error_code: "TSL_DELEGATION_SCOPE_VIOLATION" };
  }
  if (allowedResources.some((resources) => !resources.some((pattern) => resourceMatches(pattern, input.action.resource)))) {
    return { ok: false, error_code: "TSL_DELEGATION_SCOPE_VIOLATION" };
  }
  if (valueFromAction(input.action, input.parameters) > maxValue) {
    return { ok: false, error_code: "TSL_DELEGATION_VALUE_LIMIT_EXCEEDED" };
  }
  if (requiresHumanApproval && !input.action.human_approval_proof) {
    return { ok: false, error_code: "TSL_HUMAN_APPROVAL_REQUIRED" };
  }
  return {
    ok: true,
    effective_scope_commitment: sha256Hex(canonicalBytes({ actions: allowedActions, resources: allowedResources, maxValue, requiresHumanApproval }))
  };
}

export function signaturePlaceholder(): HexSig {
  return bytesToHex(new Uint8Array([0])) as HexSig;
}
