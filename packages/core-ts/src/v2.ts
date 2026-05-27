import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import { canonicalBytes, withoutSignature } from "./canonicalize";
import {
  bytesToHex,
  concatBytes,
  hashDomain,
  hexToBytes,
  randomHex32,
  sha256Hex,
  signEd25519,
  verifyEd25519
} from "./crypto";
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
  TrustAssessmentUnsignedV2,
  TrustAssessmentV2,
  TrustID
} from "./types";

const encoder = new TextEncoder();

export const V2_DOMAIN_TAGS = {
  SCORING_PROFILE_V2: "tsl.scoring_profile.v2",
  TRUST_ASSESSMENT_V2: "tsl.trust_assessment.v2",
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

export interface ReferenceScoreV0Input {
  subject: TrustID;
  issuer: TrustID;
  scoring_profile_id: string;
  model_version: string;
  gate_result: TrustAssessmentV2["gate_result"];
  evidence_coverage: EvidenceCoverageV1;
  normalized_features_bps: Record<string, number>;
  weights_bps: Record<string, number>;
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
  const coverage_bps =
    required.length > 0
      ? bps(covered.length, required.length)
      : clampBps(
          Math.floor(
            Math.min(1, eventCount / 25) * 2500 +
              Math.min(1, receiptCount / 10) * 3500 +
              Math.min(1, counterpartyCount / 5) * 4000
          )
        );
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
  if (input.domain_policy.requires_settlement && !gate.settlement_satisfied) return failure("settlement_missing", "TSL_SETTLEMENT_MISSING");
  if (input.evidence_coverage.coverage_bps < input.domain_policy.min_coverage_bps) return failure("insufficient_evidence", "TSL_INSUFFICIENT_EVIDENCE");

  let score = 0;
  for (const featureId of Object.keys(input.weights_bps).sort()) {
    score += Math.floor((clampBps(input.normalized_features_bps[featureId] ?? 0) * clampBps(input.weights_bps[featureId])) / 10000);
  }
  const score_bps = clampBps(score);
  const thresholds = input.domain_policy.thresholds;
  const label =
    score_bps >= thresholds.trusted_bps
      ? "trusted"
      : score_bps >= thresholds.likely_trusted_bps
        ? "likely_trusted"
        : score_bps >= thresholds.medium_bps
          ? "medium_trust"
          : score_bps >= thresholds.suspicious_bps
            ? "unknown_caution"
            : score_bps >= thresholds.high_risk_bps
              ? "suspicious"
              : "high_risk";
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
    confidence_interval_bps: [Math.max(0, score_bps - 300), Math.min(10000, score_bps + 300)],
    coverage_bps: input.evidence_coverage.coverage_bps,
    label,
    reason_codes: Object.keys(input.normalized_features_bps).sort(),
    risk_codes: [],
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
}

export interface GraphV0 {
  edges: GraphEdgeV0[];
  nodes: TrustID[];
}

export function constructGraphV0(input: { edges: GraphEdgeV0[] }): GraphV0 {
  const edges = [...input.edges].sort((a, b) => a.timestamp.localeCompare(b.timestamp) || canonicalBytes(a).join(",").localeCompare(canonicalBytes(b).join(",")));
  const nodes = [...new Set(edges.flatMap((edge) => [edge.src, edge.dst]))].sort();
  return { edges, nodes };
}

export function computeGraphFeatureVectorV0(input: {
  subject: TrustID;
  graph: GraphV0;
  graph_profile_id: string;
  trusted_seeds?: TrustID[];
  computed_at?: RFC3339;
  signature?: HexSig;
}): GraphFeatureVectorV1 {
  const incident = input.graph.edges.filter((edge) => edge.src === input.subject || edge.dst === input.subject);
  const counterparties = incident.map((edge) => (edge.src === input.subject ? edge.dst : edge.src));
  const counterpartySet = new Set(counterparties);
  const counts = [...counterpartySet].map((counterparty) => counterparties.filter((item) => item === counterparty).length);
  const total = counts.reduce((sum, count) => sum + count, 0);
  const hhi = total === 0 ? 0 : counts.reduce((sum, count) => sum + Math.floor(((count * 10000) / total) ** 2 / 10000), 0);
  const reciprocalPairs = [...counterpartySet].filter(
    (counterparty) =>
      input.graph.edges.some((edge) => edge.src === input.subject && edge.dst === counterparty) &&
      input.graph.edges.some((edge) => edge.src === counterparty && edge.dst === input.subject)
  ).length;
  const seedSet = new Set(input.trusted_seeds ?? []);
  const seedEdges = incident.filter((edge) => seedSet.has(edge.src) || seedSet.has(edge.dst)).length;
  return {
    type: "tsl.graph_feature_vector.v1",
    subject: input.subject,
    graph_profile_id: input.graph_profile_id,
    computed_at: input.computed_at ?? new Date().toISOString(),
    weighted_degree_bps: clampBps(incident.reduce((sum, edge) => sum + clampBps(edge.weight_bps), 0)),
    reciprocity_bps: bps(reciprocalPairs, counterpartySet.size),
    counterparty_hhi_bps: clampBps(hhi),
    counterparty_entropy_bps: clampBps(10000 - hhi),
    effective_counterparty_count_milli: (hhi > 0 ? Math.max(1, Math.floor(10000 / hhi)) : counterpartySet.size) * 1000,
    seed_escape_bps: bps(seedEdges, incident.length),
    adversarial_proximity_bps: 0,
    privacy_disclosure_level: "aggregate_only",
    signature: input.signature ?? ("0x00" as HexSig)
  };
}

export function graphFeatureVectorV1Hash(vector: GraphFeatureVectorUnsignedV1 | GraphFeatureVectorV1): Hex32 {
  return hashSignedObject(V2_DOMAIN_TAGS.GRAPH_FEATURE_VECTOR_V1, vector as unknown as Record<string, unknown>);
}

export function computeSybilAssessmentV0(input: {
  subject: TrustID;
  graph: GraphV0;
  graph_profile: GraphProfileV2;
  trusted_seeds?: TrustID[];
  computed_at?: RFC3339;
  signature?: HexSig;
}): SybilAssessmentV1 {
  const incident = input.graph.edges.filter((edge) => edge.src === input.subject || edge.dst === input.subject);
  const neighbors = new Set(incident.map((edge) => (edge.src === input.subject ? edge.dst : edge.src)));
  const internal = input.graph.edges.filter((edge) => neighbors.has(edge.src) && neighbors.has(edge.dst)).length;
  const trusted = input.trusted_seeds ? incident.filter((edge) => input.trusted_seeds!.includes(edge.src) || input.trusted_seeds!.includes(edge.dst)).length : 0;
  const concentration = bps(internal, internal + Math.max(1, incident.length));
  const trustedEscape = bps(trusted, Math.max(1, incident.length));
  const internalReceiptRatio = bps(input.graph.edges.filter((edge) => edge.type.includes("receipt") && neighbors.has(edge.src) && neighbors.has(edge.dst)).length, Math.max(1, input.graph.edges.filter((edge) => edge.type.includes("receipt")).length));
  const risk_score_bps = clampBps(Math.floor((concentration + internalReceiptRatio + (10000 - trustedEscape)) / 3));
  const risk_label = concentration > 8500 && trustedEscape < 500 ? "high" : internalReceiptRatio > 7500 && trustedEscape < 1500 ? "medium" : "low";
  return {
    type: "tsl.sybil_assessment.v1",
    subject: input.subject,
    cluster_id_commitment: sha256Hex(canonicalBytes({ subject: input.subject, graph_profile_id: input.graph_profile.profile_id })),
    computed_at: input.computed_at ?? new Date().toISOString(),
    adversary_tier_assumed: "B2",
    cluster_size_bucket: `${neighbors.size}-${neighbors.size}`,
    cluster_concentration_bps: concentration,
    trusted_escape_bps: trustedEscape,
    internal_receipt_ratio_bps: internalReceiptRatio,
    creation_sync_bps: 0,
    issuer_reuse_bps: 0,
    external_diversity_bps: clampBps(10000 - concentration),
    attack_cost_minor_units: Math.max(0, neighbors.size * 25000 + internal * 5000),
    risk_score_bps,
    risk_label,
    privacy_level: "cluster_commitment_only",
    signature: input.signature ?? ("0x00" as HexSig)
  };
}

export function sybilAssessmentV1Hash(assessment: SybilAssessmentUnsignedV1 | SybilAssessmentV1): Hex32 {
  return hashSignedObject(V2_DOMAIN_TAGS.SYBIL_ASSESSMENT_V1, assessment as unknown as Record<string, unknown>);
}

export function computeDriftReportV0(input: {
  subject: TrustID;
  baseline_values_bps: number[];
  observation_values_bps: number[];
  baseline_window_days: number;
  observation_window_days: number;
  dormant_days?: number;
  high_value_action?: boolean;
  computed_at?: RFC3339;
  signature?: HexSig;
}): DriftReportV1 {
  if (input.baseline_values_bps.length < 2) {
    return {
      type: "tsl.drift_report.v1",
      subject: input.subject,
      computed_at: input.computed_at ?? new Date().toISOString(),
      baseline_window_days: input.baseline_window_days,
      observation_window_days: input.observation_window_days,
      drift_score_bps: 0,
      drift_label: "insufficient_baseline",
      action: "none",
      reason_codes: ["INSUFFICIENT_BASELINE"],
      signature: input.signature ?? ("0x00" as HexSig)
    };
  }
  const avg = (values: number[]) => Math.floor(values.reduce((sum, value) => sum + value, 0) / Math.max(1, values.length));
  const drift = clampBps(Math.abs(avg(input.observation_values_bps) - avg(input.baseline_values_bps)));
  const dormant = (input.dormant_days ?? 0) >= 90 && input.high_value_action === true;
  return {
    type: "tsl.drift_report.v1",
    subject: input.subject,
    computed_at: input.computed_at ?? new Date().toISOString(),
    baseline_window_days: input.baseline_window_days,
    observation_window_days: input.observation_window_days,
    drift_score_bps: dormant ? Math.max(drift, 8000) : drift,
    drift_label: dormant ? "dormant_reactivation" : drift >= 7000 ? "severe" : drift >= 4000 ? "moderate" : drift >= 1500 ? "minor" : "stable",
    action: dormant ? "step_up" : drift >= 7000 ? "human_review" : drift >= 4000 ? "lower_confidence" : "none",
    reason_codes: dormant ? ["DORMANT_REACTIVATION", "NEW_HIGH_VALUE_ACTION"] : [],
    signature: input.signature ?? ("0x00" as HexSig)
  };
}

export function driftReportV1Hash(report: DriftReportUnsignedV1 | DriftReportV1): Hex32 {
  return hashSignedObject(V2_DOMAIN_TAGS.DRIFT_REPORT_V1, report as unknown as Record<string, unknown>);
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
  const fingerprint = hmac(sha256, scopeKey, concatBytes(encoder.encode("tsl.metadata.fp.v1"), canonicalBytes(input.metadata)));
  const commitment = sha256Hex(concatBytes(encoder.encode("tsl.metadata.commit.v1"), fingerprint, hexToBytes(input.salt_hex)));
  return {
    type: "tsl.metadata_fingerprint_commitment.v1",
    subject: input.subject,
    scope_class: input.purpose,
    scope_commitment: sha256Hex(scopeMaterial),
    bucket_profile: input.bucket_profile,
    fingerprint_commitment: commitment,
    salt_commitment: sha256Hex(hexToBytes(input.salt_hex)),
    created_at_bucket: input.epoch,
    expires_at: input.expires_at,
    disclosure_policy: input.purpose === "local_only" ? "local_only" : "selective",
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

export function verifyDelegatedAgentActionV0(input: {
  action: AgentActionV2;
  delegation_chain: DelegationPolicyV2[];
  public_keys: Record<TrustID, string>;
  at_time?: RFC3339;
}): { ok: boolean; error_code?: string; effective_scope_commitment?: Hex32 } {
  const at = Date.parse(input.at_time ?? input.action.issued_at);
  const agentKey = input.public_keys[input.action.agent];
  if (!agentKey || !verifyEd25519(agentKey, agentActionV2Hash(input.action), input.action.signature)) {
    return { ok: false, error_code: "TSL_AGENT_ACTION_SIGNATURE_INVALID" };
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
  for (const policy of [...input.delegation_chain].reverse()) {
    const principalKey = input.public_keys[policy.principal];
    if (!principalKey || !verifyEd25519(principalKey, delegationPolicyV2Hash(policy), policy.signature)) {
      return { ok: false, error_code: "TSL_DELEGATION_SIGNATURE_INVALID" };
    }
    if (Date.parse(policy.valid_from) > at || at >= Date.parse(policy.valid_until)) {
      return { ok: false, error_code: "TSL_DELEGATION_EXPIRED" };
    }
    if (policy.delegate !== expectedDelegate) {
      return { ok: false, error_code: "TSL_DELEGATION_CHAIN_BROKEN" };
    }
    if (policy.effect !== "allow") {
      return { ok: false, error_code: "TSL_DELEGATION_SCOPE_VIOLATION" };
    }
    allowedActions.push(policy.actions);
    allowedResources.push(policy.resources);
    const constraints = policy.constraints as { max_value_minor_units?: number; requires_human_approval?: boolean };
    if (constraints.max_value_minor_units !== undefined) maxValue = Math.min(maxValue, constraints.max_value_minor_units);
    if (constraints.requires_human_approval === true) requiresHumanApproval = true;
    expectedDelegate = policy.principal;
  }
  if (allowedActions.some((actions) => !actions.includes(input.action.action))) {
    return { ok: false, error_code: "TSL_DELEGATION_SCOPE_VIOLATION" };
  }
  if (allowedResources.some((resources) => !resources.some((pattern) => resourceMatches(pattern, input.action.resource)))) {
    return { ok: false, error_code: "TSL_DELEGATION_SCOPE_VIOLATION" };
  }
  if ((input.action.value_minor_units ?? 0) > maxValue) {
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
