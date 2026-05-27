export interface ReferenceScoreInput {
  crypto_validity_bps: number;
  identity_age_bps: number;
  reciprocity_bps: number;
  trusted_neighbor_ratio_bps: number;
  receipt_quality_bps: number;
  attestation_quality_bps: number;
  temporal_consistency_bps: number;
  local_relationship_bps?: number;
}

export interface VerifiedEventSummary {
  sender: string;
  timestamp: string;
  event_class?: string;
  signature_valid?: boolean;
  counterparty?: string;
}

export interface VerifiedReceiptSummary {
  receiver: string;
  timestamp: string;
  receipt_class?: string;
}

export interface VerifiedAttestationSummary {
  issuer: string;
  subject: string;
  attestation_class: string;
  issued_at: string;
  expires_at?: string;
  issuer_quality_bps?: number;
}

export interface RevocationSummary {
  revoked: boolean;
  revocation_count: number;
  latest_effective_at?: string;
}

export interface LocalVerifierContext {
  local_relationship_bps?: number;
  first_seen_at?: string;
  reciprocal_receipt_count?: number;
}

export interface FeatureVectorV1 {
  type: "tsl.feature_vector.v1";
  subject: string;
  computed_at: string;
  identity_age_days: number;
  active_key_age_days: number;
  signed_event_count: number;
  reciprocal_receipt_count: number;
  unique_counterparty_count: number;
  trusted_neighbor_ratio_bps: number;
  attestation_quality_bps: number;
  temporal_consistency_bps: number;
  revocation_risk_bps: number;
  cluster_concentration_bps: number;
  dormant_reactivation_bps: number;
  outbound_burst_bps: number;
  sybil_risk_bps: number;
  issuer_quality_bps: number;
  receipt_quality_bps: number;
  local_relationship_bps?: number;
}

export interface FeatureExtractor {
  extract(input: {
    subject: string;
    identity_created_at?: string;
    active_key_created_at?: string;
    verifiedEvents: VerifiedEventSummary[];
    verifiedReceipts: VerifiedReceiptSummary[];
    attestations: VerifiedAttestationSummary[];
    revocationState: RevocationSummary;
    localContext?: LocalVerifierContext;
  }): Promise<FeatureVectorV1> | FeatureVectorV1;
}

export const referenceFeatureExtractor: FeatureExtractor = {
  extract(input) {
    const now = Date.now();
    const ageDays = input.identity_created_at ? Math.max(0, Math.floor((now - Date.parse(input.identity_created_at)) / 86400000)) : 0;
    const keyAgeDays = input.active_key_created_at ? Math.max(0, Math.floor((now - Date.parse(input.active_key_created_at)) / 86400000)) : ageDays;
    const counterparties = new Set(input.verifiedReceipts.map((receipt) => receipt.receiver));
    const eventCounterparties = new Set(input.verifiedEvents.map((event) => event.counterparty).filter(Boolean));
    const nonExpiredAttestations = input.attestations.filter((attestation) => !attestation.expires_at || Date.parse(attestation.expires_at) > now);
    const eventTimes = input.verifiedEvents.map((event) => Date.parse(event.timestamp)).filter(Number.isFinite).sort((a, b) => a - b);
    const latestEvent = eventTimes.at(-1);
    const previousEvent = eventTimes.length > 1 ? eventTimes.at(-2) : undefined;
    const dormantDays =
      latestEvent !== undefined && previousEvent !== undefined ? Math.floor((latestEvent - previousEvent) / 86400000) : 0;
    const lastHourEvents = eventTimes.filter((time) => latestEvent !== undefined && latestEvent - time <= 60 * 60 * 1000).length;
    const issuerQuality =
      nonExpiredAttestations.length === 0
        ? 0
        : Math.round(
            nonExpiredAttestations.reduce((sum, attestation) => sum + (attestation.issuer_quality_bps ?? 5000), 0) /
              nonExpiredAttestations.length
          );
    const clusterConcentration =
      input.verifiedReceipts.length > 0
        ? Math.round((Math.max(0, input.verifiedReceipts.length - counterparties.size) / input.verifiedReceipts.length) * 10000)
        : 0;
    const burstRisk = Math.min(10000, Math.max(0, (lastHourEvents - 25) * 250));
    const dormantRisk = dormantDays >= 90 ? Math.min(10000, dormantDays * 50) : 0;
    const receiptQuality = Math.min(10000, counterparties.size * 1200 + input.verifiedReceipts.length * 200);
    const sybilRisk = Math.min(
      10000,
      Math.round(clusterConcentration * 0.45 + burstRisk * 0.25 + dormantRisk * 0.2 + (counterparties.size < 3 ? 1000 : 0))
    );
    return {
      type: "tsl.feature_vector.v1",
      subject: input.subject,
      computed_at: new Date(now).toISOString(),
      identity_age_days: ageDays,
      active_key_age_days: keyAgeDays,
      signed_event_count: input.verifiedEvents.length,
      reciprocal_receipt_count: input.localContext?.reciprocal_receipt_count ?? input.verifiedReceipts.length,
      unique_counterparty_count: new Set([...counterparties, ...eventCounterparties]).size,
      trusted_neighbor_ratio_bps: counterparties.size > 0 ? Math.min(10000, counterparties.size * 1000) : 0,
      attestation_quality_bps: Math.min(10000, nonExpiredAttestations.length * 2000 + issuerQuality * 0.2),
      temporal_consistency_bps: Math.max(0, Math.min(10000, (input.verifiedEvents.length > 0 ? 8000 : 5000) - burstRisk - dormantRisk / 2)),
      revocation_risk_bps: input.revocationState.revoked ? 10000 : Math.min(10000, input.revocationState.revocation_count * 2000),
      cluster_concentration_bps: clusterConcentration,
      dormant_reactivation_bps: dormantRisk,
      outbound_burst_bps: burstRisk,
      sybil_risk_bps: sybilRisk,
      issuer_quality_bps: issuerQuality,
      receipt_quality_bps: receiptQuality,
      ...(input.localContext?.local_relationship_bps !== undefined
        ? { local_relationship_bps: input.localContext.local_relationship_bps }
        : {})
    };
  }
};

export function scoreInputFromFeatureVector(features: FeatureVectorV1): ReferenceScoreInput {
  return {
    crypto_validity_bps: features.revocation_risk_bps >= 10000 ? 0 : 10000,
    identity_age_bps: Math.min(10000, Math.round((features.identity_age_days / 365) * 10000)),
    reciprocity_bps: Math.min(10000, features.reciprocal_receipt_count * 1000),
    trusted_neighbor_ratio_bps: features.trusted_neighbor_ratio_bps,
    receipt_quality_bps: features.receipt_quality_bps,
    attestation_quality_bps: features.attestation_quality_bps,
    temporal_consistency_bps: features.temporal_consistency_bps,
    local_relationship_bps: features.local_relationship_bps ?? 0
  };
}

function clampBps(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(10000, Math.round(value)));
}

export function referenceScoreBps(input: ReferenceScoreInput): number {
  const local = input.local_relationship_bps ?? 0;
  return clampBps(
    (2000 * clampBps(input.crypto_validity_bps)) / 10000 +
      (1500 * clampBps(input.identity_age_bps)) / 10000 +
      (1500 * clampBps(input.reciprocity_bps)) / 10000 +
      (1500 * clampBps(input.trusted_neighbor_ratio_bps)) / 10000 +
      (1000 * clampBps(input.receipt_quality_bps)) / 10000 +
      (1000 * clampBps(input.attestation_quality_bps)) / 10000 +
      (1000 * clampBps(input.temporal_consistency_bps)) / 10000 +
      (500 * clampBps(local)) / 10000
  );
}

export function labelForScore(scoreBps: number): string {
  const score = clampBps(scoreBps) / 100;
  if (score >= 90) return "trusted";
  if (score >= 75) return "likely_trusted";
  if (score >= 55) return "medium_trust";
  if (score >= 35) return "unknown_caution";
  if (score >= 15) return "suspicious";
  return "high_risk";
}
