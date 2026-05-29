export type Hex = `0x${string}`;
export type Hex32 = `0x${string}`;
export type HexSig = `0x${string}`;
export type TrustID = string;
export type RFC3339 = string;

export type VerificationKeyType = "ed25519" | "secp256k1" | "smart_account";
export type VerificationKeyStatus = "active" | "revoked" | "expired";

export interface VerificationMethodV1 {
  id: string;
  type: VerificationKeyType;
  public_key: string;
  status: VerificationKeyStatus;
  created_at: RFC3339;
  expires_at?: RFC3339;
  revoked_at?: RFC3339;
}

export interface IdentityDocumentV1 {
  type: "tsl.identity.v1";
  id: TrustID;
  controller: string;
  created_at: RFC3339;
  verification_methods: VerificationMethodV1[];
  recovery?: Record<string, unknown>;
  privacy_policy_commitment?: Hex32;
}

export type EventClass = "message" | "transaction" | "attestation" | "agent_call" | "code_release";
export type DisclosurePolicy = "local_only" | "commitment_only" | "selective" | "public";

export interface EventCommitmentUnsignedV1 {
  type: "tsl.event_commitment.v1";
  event_class: EventClass;
  sender: TrustID;
  signing_key_id: string;
  receiver_commitment?: Hex32;
  content_commitment: Hex32;
  metadata_commitment?: Hex32;
  previous_event_commitment?: Hex32;
  timestamp: RFC3339;
  nonce: Hex32;
  disclosure_policy: DisclosurePolicy;
}

export interface EventCommitmentV1 extends EventCommitmentUnsignedV1 {
  signature: HexSig;
}

export type ReceiptClass = "received" | "replied" | "transacted" | "completed" | "disputed";

export interface ReceiptCommitmentV1 {
  type: "tsl.receipt_commitment.v1";
  event_commitment: Hex32;
  receiver: TrustID;
  signing_key_id: string;
  receipt_class: ReceiptClass;
  timestamp: RFC3339;
  metadata_commitment?: Hex32;
  signature: HexSig;
}

export type ReceiptCommitmentUnsignedV1 = Omit<ReceiptCommitmentV1, "signature">;

export interface ReceiptDisputeMetadataV1 {
  evidence_commitment: Hex32;
  appeal_uri?: string;
  appeal_status?: "none" | "submitted" | "under_review" | "upheld" | "reversed" | "expired" | "escalated";
  reversal_status?: "none" | "pending" | "reversed" | "upheld";
  severity?: "low" | "medium" | "high" | "critical";
}

export interface AttestationUnsignedV1 {
  type: "tsl.attestation.v1";
  issuer: TrustID;
  subject: TrustID;
  attestation_class: string;
  claim_commitment: Hex32;
  visibility: "public" | "selective" | "private";
  issued_at: RFC3339;
  expires_at?: RFC3339;
}

export interface AttestationV1 extends AttestationUnsignedV1 {
  signature: HexSig;
}

export interface RevocationUnsignedV1 {
  type: "tsl.revocation.v1";
  trust_id: TrustID;
  revoked_key: string;
  replacement_key?: string;
  reason_class: "rotation" | "compromise" | "device_loss" | "policy_update";
  effective_at: RFC3339;
}

export interface RevocationV1 extends RevocationUnsignedV1 {
  signature: HexSig;
}

export interface KeyRotationV1 {
  type: "tsl.key_rotation.v1";
  trust_id: TrustID;
  old_key: string;
  new_key: string;
  effective_at: RFC3339;
  signature: HexSig;
}

export type TreeKind = "event" | "receipt" | "attestation" | "revocation";
export type ProofSide = "left" | "right";

export interface InclusionProofStep {
  side: ProofSide;
  hash: Hex32;
}

export interface InclusionProofV1 {
  type: "tsl.inclusion_proof.v1";
  tree_kind: TreeKind;
  commitment: Hex32;
  leaf_index: number;
  leaf_hash: Hex32;
  root: Hex32;
  epoch_start_ms: number;
  epoch_duration_ms: number;
  shard: string;
  path: InclusionProofStep[];
  checkpoint_hash: Hex32;
}

export interface ConsistencyProofV1 {
  type: "tsl.consistency_proof.v1";
  shard: string;
  from_checkpoint: Hex32;
  to_checkpoint: Hex32;
  chain: Array<{
    checkpoint_hash: Hex32;
    previous_checkpoint: Hex32;
    epoch_start_ms: number;
  }>;
  auditor?: TrustID;
  signature?: HexSig;
}

export interface BatchCheckpointV1 {
  type: "tsl.batch_checkpoint.v1";
  epoch_start_ms: number;
  epoch_duration_ms: number;
  shard: string;
  event_root: Hex32;
  receipt_root: Hex32;
  attestation_root: Hex32;
  revocation_root: Hex32;
  event_count: number;
  receipt_count: number;
  previous_checkpoint: Hex32;
  checkpoint_identity_hash?: Hex32;
  settlement_backend?: string;
  settlement_tx?: string;
  relay_id: TrustID;
  relay_signature: HexSig;
}

export interface SettlementEvidenceV1 {
  type: "tsl.settlement_evidence.v1";
  checkpoint_hash: Hex32;
  checkpoint_identity_hash: Hex32;
  settlement_backend: string;
  chain_id: number;
  contract_address: string;
  contract_checkpoint_hash?: Hex32;
  contract_checkpoint_fields_hash: Hex32;
  settlement_tx: string;
  transaction_receipt_hash?: Hex32;
  block_hash?: Hex32;
  block_number?: number;
  receipt_status?: "success" | "reverted" | "unknown";
  chain_proof_commitment?: Hex32;
  settlement_event_hash?: Hex32;
  settlement_event_index?: number;
  receipt_proof_source_commitment?: Hex32;
  submitter: string;
  submitted_at: RFC3339;
  status: "submitted" | "settled" | "failed";
}

export interface TrustAssessmentV1 {
  type: "tsl.trust_assessment.v1";
  subject: TrustID;
  issuer: TrustID;
  score_bps: number;
  label:
    | "trusted"
    | "likely_trusted"
    | "medium_trust"
    | "unknown_caution"
    | "suspicious"
    | "high_risk"
    | "revoked"
    | "insufficient_evidence";
  model_version: string;
  evidence_commitment: Hex32;
  features_disclosed?: string[];
  explanation?: string[];
  issued_at: RFC3339;
  expires_at: RFC3339;
  signature: HexSig;
}

export type TrustAssessmentUnsignedV1 = Omit<TrustAssessmentV1, "signature">;

export interface ScoringProfileV2 {
  type: "tsl.scoring_profile.v2";
  profile_id: string;
  provider: TrustID;
  domain: string;
  model_family: string;
  model_version: string;
  feature_registry_uri?: string;
  feature_registry_commitment: Hex32;
  normalization_profile_commitment: Hex32;
  weight_profile_commitment: Hex32;
  calibration_profile_commitment: Hex32;
  threshold_policy_commitment: Hex32;
  privacy_policy_commitment: Hex32;
  evaluation_report_commitment: Hex32;
  appeal_policy_uri?: string;
  issued_at: RFC3339;
  valid_after: RFC3339;
  expires_at: RFC3339;
  signature: HexSig;
}

export type ScoringProfileUnsignedV2 = Omit<ScoringProfileV2, "signature">;

export interface FeatureDefinitionV2 {
  type: "tsl.feature_definition.v2";
  feature_id: string;
  name: string;
  family: string;
  value_type: string;
  unit: string;
  range: { min: number; max: number };
  normalization_method: string;
  privacy_class: string;
  spoofing_cost_class: string;
  missing_value_policy: string;
  attack_notes: string[];
}

export interface DomainPolicyV1 {
  type: "tsl.domain_policy.v1";
  domain: string;
  policy_version: string;
  requires_settlement: boolean;
  requires_delegation_check?: boolean;
  requires_content_opening?: boolean;
  min_coverage_bps: number;
  max_assessment_age_seconds: number;
  false_positive_cost_class: string;
  false_negative_cost_class: string;
  sparse_identity_default: string;
  thresholds: {
    trusted_bps: number;
    likely_trusted_bps: number;
    medium_bps: number;
    suspicious_bps: number;
    high_risk_bps: number;
  };
}

export interface EvidenceCoverageV1 {
  type: "tsl.evidence_coverage.v1";
  subject: TrustID;
  computed_at: RFC3339;
  valid_signed_event_count: number;
  valid_receipt_count: number;
  unique_counterparty_count: number;
  distinct_community_count: number;
  attestation_count: number;
  recent_revocation_count: number;
  coverage_bps: number;
  coverage_label: "insufficient" | "low" | "medium" | "high";
  missing_evidence: string[];
  evidence_commitment?: Hex32;
}

export interface TrustAssessmentV2 {
  type: "tsl.trust_assessment.v2";
  assessment_id: Hex32;
  subject: TrustID;
  issuer: TrustID;
  domain: string;
  scoring_profile_id: string;
  model_version: string;
  gate_result: {
    schema_valid: boolean;
    canonicalization_valid?: boolean;
    signature_valid: boolean;
    key_active: boolean;
    not_revoked: boolean;
    included_in_log?: boolean;
    checkpoint_valid?: boolean;
    settlement_satisfied?: boolean;
    delegation_valid?: boolean;
  };
  score_bps?: number;
  confidence_interval_bps?: [number, number];
  coverage_bps: number;
  label:
    | "trusted"
    | "likely_trusted"
    | "medium_trust"
    | "unknown_caution"
    | "insufficient_evidence"
    | "suspicious"
    | "high_risk"
    | "cryptographic_failure"
    | "revoked_or_compromised"
    | "settlement_missing"
    | "unsettled_or_unproven"
    | "delegation_missing";
  reason_codes: string[];
  risk_codes: string[];
  feature_vector_commitment?: Hex32;
  evidence_coverage_commitment?: Hex32;
  privacy_disclosure_level?: "none" | "aggregate_only" | "pairwise" | "selective" | "public";
  appeal_uri?: string;
  issued_at: RFC3339;
  expires_at: RFC3339;
  signature: HexSig;
}

export type TrustAssessmentUnsignedV2 = Omit<TrustAssessmentV2, "signature">;

export interface MetadataFingerprintCommitmentV1 {
  type: "tsl.metadata_fingerprint_commitment.v1";
  subject: TrustID;
  scope_class: "local_only" | "pairwise_verifier" | "provider_ephemeral" | "public_commitment";
  scope_commitment: Hex32;
  bucket_profile: string;
  fingerprint_commitment: Hex32;
  salt_commitment?: Hex32;
  created_at_bucket: string;
  expires_at: RFC3339;
  disclosure_policy: "local_only" | "selective" | "zk_only" | "public_commitment_only";
  signature: HexSig;
}

export type MetadataFingerprintCommitmentUnsignedV1 = Omit<MetadataFingerprintCommitmentV1, "signature">;

export interface DisclosureConsentV1 {
  type: "tsl.disclosure_consent.v1";
  subject: TrustID;
  verifier_or_provider: TrustID;
  allowed_field_classes: string[];
  forbidden_field_classes: string[];
  purpose: string;
  issued_at: RFC3339;
  expires_at: RFC3339;
  revocation_pointer: string;
  signature: HexSig;
}

export interface GraphProfileV2 {
  type: "tsl.graph_profile.v2";
  profile_id: string;
  edge_weight_profile: string;
  temporal_decay_profile: string;
  community_detection: {
    algorithm:
      | "connected_components"
      | "connected_components_v0"
      | "louvain"
      | "leiden"
      | "louvain_modularity_v0"
      | "leiden_refinement_v0"
      | "louvain_modularity_v1"
      | "leiden_refinement_v1"
      | "none";
    resolution_bps: number;
    min_cluster_size: number;
    edge_weight_floor_bps?: number;
    deterministic_ordering?: "node_id_lexicographic";
    max_passes?: number;
    approximation_tolerance_bps?: number;
    refinement_threshold_bps?: number;
    projection?: "undirected_sum" | "directed_outbound";
    negative_edge_treatment?: "ignore" | "cap" | "signed";
  };
  seed_sets: {
    trusted_seed_commitment: Hex32;
    adversarial_seed_commitment: Hex32;
    trusted_seed_governance_commitment?: Hex32;
    adversarial_seed_governance_commitment?: Hex32;
  };
  negative_edge_policy: {
    requires_evidence_commitment: boolean;
    requires_appeal_uri: boolean;
    max_single_negative_weight_bps: number;
    decay_days: number;
  };
  privacy_policy: {
    raw_counterparty_upload_required: boolean;
    allows_pairwise_private_features: boolean;
  };
  edge_weights?: Record<string, number>;
  half_life_days?: Record<string, number>;
  issuer_quality_bps?: Record<string, number>;
  pagerank?: {
    iterations: number;
    damping_bps: number;
    personalization?: "trusted_seeds" | "subject" | "uniform";
  };
  manifold_profile?: {
    algorithm: "seed_distance_proxy_v1" | "centroid_covariance_v1";
    trusted_centroid_commitment?: Hex32;
    adversarial_centroid_commitment?: Hex32;
    cluster_centroid_commitment?: Hex32;
    covariance_commitment?: Hex32;
    seed_commitment?: Hex32;
  };
}

export interface SeedGovernanceProfileV1 {
  type: "tsl.seed_governance_profile.v1";
  profile_id: string;
  issuer: TrustID;
  review_state: "draft" | "reviewed" | "approved" | "rejected" | "revoked";
  source_class: "protocol_reference" | "auditor_curated" | "provider_curated" | "enterprise_private";
  seed_class: "trusted" | "adversarial";
  seeds: TrustID[];
  seed_set_commitment: Hex32;
  governance_policy_commitment: Hex32;
  reviewed_at: RFC3339;
  signature?: HexSig;
}

export interface GraphFeatureVectorV1 {
  type: "tsl.graph_feature_vector.v1";
  subject: TrustID;
  graph_profile_id: string;
  computed_at: RFC3339;
  weighted_degree_bps: number;
  reciprocity_bps: number;
  counterparty_hhi_bps: number;
  counterparty_entropy_bps: number;
  effective_counterparty_count_milli: number;
  seed_escape_bps: number;
  adversarial_proximity_bps: number;
  community_algorithm_id?: string;
  community_escape_bps?: number;
  community_diversity_bps?: number;
  conductance_bps?: number;
  trusted_neighbor_mass_bps?: number;
  trusted_seed_distance_bps?: number;
  adversarial_seed_distance_bps?: number;
  pagerank_bps?: number;
  ppr_lite_bps?: number;
  ppr_distance_bps?: number;
  trusted_manifold_distance_bps?: number;
  adversarial_manifold_distance_bps?: number;
  cluster_distance_bps?: number;
  modularity_bps?: number;
  community_pass_count?: number;
  cluster_concentration_bps?: number;
  feature_commitment?: Hex32;
  recomputation_commitment?: Hex32;
  privacy_disclosure_level: "aggregate_only" | "pairwise" | "local_only" | "public";
  signature: HexSig;
}

export type GraphFeatureVectorUnsignedV1 = Omit<GraphFeatureVectorV1, "signature">;

export interface SybilAssessmentV1 {
  type: "tsl.sybil_assessment.v1";
  subject: TrustID;
  issuer: TrustID;
  sybil_profile_id: string;
  graph_profile_id: string;
  seed_set_commitment: Hex32;
  evidence_commitment: Hex32;
  cluster_id_commitment: Hex32;
  computed_at: RFC3339;
  adversary_tier_assumed: "B0" | "B1" | "B2" | "B3" | "B4" | "B5";
  cluster_size_bucket?: string;
  cluster_concentration_bps: number;
  trusted_escape_bps: number;
  internal_receipt_ratio_bps: number;
  creation_sync_bps?: number;
  issuer_reuse_bps?: number;
  external_diversity_bps?: number;
  seed_contamination_bps?: number;
  receipt_symmetry_bps?: number;
  attack_cost_minor_units: number;
  cost_components: {
    identity_cost_minor_units: number;
    time_aging_cost_minor_units: number;
    external_receipt_cost_minor_units: number;
    attestation_cost_minor_units: number;
    compromise_cost_minor_units: number;
    evasion_cost_minor_units: number;
    issuer_collusion_cost_minor_units?: number;
    infrastructure_consistency_cost_minor_units?: number;
  };
  expected_benefit_minor_units: number;
  attack_scenario: string;
  compromise_signals?: SybilCompromiseSignalsV1;
  issuer_collusion_signals?: SybilIssuerCollusionSignalsV1;
  infrastructure_collusion_signals?: SybilInfrastructureCollusionSignalsV1;
  compromise_evidence?: SybilCompromiseEvidenceV1;
  issuer_collusion_evidence?: SybilIssuerCollusionEvidenceV1;
  infrastructure_collusion_evidence?: SybilInfrastructureCollusionEvidenceV1;
  scenario_evidence_checks?: string[];
  risk_score_bps: number;
  risk_label: "low" | "medium" | "elevated" | "high" | "insufficient_evidence";
  privacy_level: "cluster_commitment_only" | "aggregate_only" | "local_only";
  signature: HexSig;
}

export type SybilAssessmentUnsignedV1 = Omit<SybilAssessmentV1, "signature">;

export interface SybilCompromiseSignalsV1 {
  key_revocation_bps?: number;
  severe_drift_bps?: number;
  recovery_anomaly_bps?: number;
}

export interface SybilIssuerCollusionSignalsV1 {
  issuer_reversal_bps?: number;
  issuer_reuse_bps?: number;
  low_quality_issuer_bps?: number;
  collusion_indicator_bps?: number;
}

export interface SybilInfrastructureCollusionSignalsV1 {
  checkpoint_conflict_bps?: number;
  provider_auditor_disagreement_bps?: number;
  settlement_anomaly_bps?: number;
}

export interface SybilCompromiseEvidenceV1 {
  evidence_commitment: Hex32;
  key_revocation_count?: number;
  severe_drift_count?: number;
  recovery_anomaly_count?: number;
}

export interface SybilIssuerCollusionEvidenceV1 {
  evidence_commitment: Hex32;
  issuer_reversal_count?: number;
  low_quality_issuer_count?: number;
  false_attestation_count?: number;
  collusion_indicator_count?: number;
}

export interface SybilInfrastructureCollusionEvidenceV1 {
  evidence_commitment: Hex32;
  checkpoint_conflict_count?: number;
  provider_auditor_disagreement_count?: number;
  settlement_anomaly_count?: number;
  selective_visibility_count?: number;
}

export interface DriftReportV1 {
  type: "tsl.drift_report.v1";
  subject: TrustID;
  issuer?: TrustID;
  drift_profile_id?: string;
  computed_at: RFC3339;
  baseline_window_days: number;
  observation_window_days: number;
  coverage_bps?: number;
  dcrit_bps?: number;
  dormant_penalty_bps?: number;
  key_penalty_bps?: number;
  feature_history_commitment?: Hex32;
  baseline_profile_commitment?: Hex32;
  covariance_profile_commitment?: Hex32;
  robust_covariance_commitment?: Hex32;
  mahalanobis_bps?: number;
  cohort_baseline_profile_commitment?: Hex32;
  uncertainty_widening_bps?: number;
  last_verified_event_at?: RFC3339;
  days_since_last_verified_event?: number;
  sparse_mode?: "none" | "insufficient_baseline" | "cohort_baseline";
  recomputation_status?: "not_supplied" | "recomputed_match" | "recomputed_mismatch" | "provider_claim";
  drift_score_bps: number;
  drift_label: "stable" | "minor" | "moderate" | "high" | "severe" | "dormant_reactivation" | "insufficient_baseline";
  action: "none" | "lower_confidence" | "step_up" | "human_review" | "temporary_block";
  reason_codes: string[];
  component_scores_bps?: Partial<Record<"key" | "graph" | "action" | "cadence" | "claim" | "agent" | "local", number>>;
  signature: HexSig;
}

export type DriftReportUnsignedV1 = Omit<DriftReportV1, "signature">;

export interface AttestationV2 {
  type: "tsl.attestation.v2";
  attestation_id: Hex32;
  issuer: TrustID;
  signing_key_id: string;
  subject: TrustID;
  claim_class: string;
  claim_polarity: "positive" | "negative" | "neutral";
  severity: "none" | "low" | "medium" | "high" | "critical";
  claim_commitment: Hex32;
  evidence_commitment: Hex32;
  evidence_policy: "public" | "selective_disclosure_or_auditor_review" | "private_commitment" | "zk_only";
  visibility: "public" | "selective" | "private";
  appeal_uri: string;
  issued_at: RFC3339;
  valid_after: RFC3339;
  expires_at: RFC3339;
  revocation_pointer: string;
  appeal_status?: "none" | "submitted" | "under_review" | "upheld" | "reversed" | "expired" | "escalated";
  signature: HexSig;
}

export interface DelegationPolicyV2 {
  type: "tsl.delegation_policy.v2";
  policy_id: Hex32;
  principal: TrustID;
  delegate: TrustID;
  effect: "allow" | "deny";
  actions: string[];
  resources: string[];
  constraints: Record<string, unknown>;
  subdelegation?: Record<string, unknown>;
  parent_policy_id?: Hex32 | null;
  valid_from: RFC3339;
  valid_until: RFC3339;
  revocation_pointer: string;
  nonce?: Hex32;
  signature: HexSig;
}

export type DelegationPolicyUnsignedV2 = Omit<DelegationPolicyV2, "signature">;

export interface AgentActionV2 {
  type: "tsl.agent_action.v2";
  action_id: Hex32;
  agent: TrustID;
  principal: TrustID;
  action: string;
  resource: string;
  tool?: string;
  parameters_commitment: Hex32;
  parameter_disclosure_policy?: "commitment_only" | "selective" | "zk_only" | "public";
  delegation_chain_root: Hex32;
  nonce: Hex32;
  value_minor_units?: number;
  human_approval_proof?: string;
  issued_at: RFC3339;
  signature: HexSig;
}

export type AgentActionUnsignedV2 = Omit<AgentActionV2, "signature">;

export interface ZkThresholdProofV1 {
  type: "tsl.zk.threshold_proof.v1";
  claim:
    | "identity_age_days"
    | "reciprocal_receipt_count"
	    | "organization_membership"
	    | "set_membership"
	    | "dispute_rate_bound"
	    | "revocation_set_non_membership"
	    | "agent_scope_compliance"
	    | "private_graph_distance";
  subject: TrustID;
  threshold: number;
  witness_commitment: Hex32;
  public_input_hash: Hex32;
  proof: Hex32;
  circuit_id?: string;
  verification_key_id?: string;
  public_signal_commitment?: Hex32;
  release_manifest_hash?: Hex32;
  groth16?: {
    protocol: "groth16";
    curve: "bn128";
    proof: unknown;
    public_signals: string[];
    verification_key?: unknown;
  };
  issued_at: RFC3339;
}

export interface ZkCircuitReleaseManifestV1 {
  type: "tsl.zk.circuit_release_manifest.v1";
  circuit_id: string;
  claim: ZkThresholdProofV1["claim"];
	  version: string;
	  hash_suite?: string;
	  witness_interface?: string;
	  circuit_hash: Hex32;
  r1cs_hash: Hex32;
  wasm_hash: Hex32;
  zkey_hash: Hex32;
  verification_key_id: string;
  verification_key_hash: Hex32;
  verification_key?: unknown;
  public_signal_schema?: Record<string, unknown>;
  private_witness_schema?: Record<string, unknown>;
  soundness_bits?: number;
  privacy_notes?: string[];
  ceremony_transcript_hash: Hex32;
  auditor: TrustID;
  reviewer: TrustID;
  status: "dev" | "candidate" | "active" | "revoked";
  issued_at: RFC3339;
  signature?: HexSig;
}

export interface ZkVerificationKeyRegistryV1 {
  type: "tsl.zk.verification_key_registry.v1";
  registry_id: string;
  active_manifest_hashes: Hex32[];
  revoked_manifest_hashes: Hex32[];
  issued_at: RFC3339;
  signature?: HexSig;
}

export interface SetNonMembershipProofV1 {
  type: "tsl.zk.non_membership_proof.v1";
  claim: "revocation_set_non_membership";
  subject: TrustID;
  set_root: Hex32;
  value_commitment: Hex32;
  tree_id?: string;
  tree_depth?: number;
  leaf_index_commitment?: Hex32;
  leaf_value_commitment?: Hex32;
  empty_leaf_commitment?: Hex32;
  root?: Hex32;
  root_checkpoint?: Hex32;
  lower_neighbor?: Hex32;
  upper_neighbor?: Hex32;
  leaf_index?: number;
  sibling_path?: Array<{ side: "left" | "right"; hash: Hex32 }>;
  proof: Hex32;
  issued_at: RFC3339;
}

export interface FeatureRegistryV1 {
  type: "tsl.feature_registry.v1";
  registry_id: string;
  feature_ids: string[];
  feature_definitions?: Array<{
    feature_id: string;
    value_type: "bps" | "boolean" | "count" | "duration" | "commitment";
    privacy_class: "public" | "aggregate" | "pairwise" | "local_only" | "private";
    attack_model?: string[];
    source: "verified_event" | "receipt" | "attestation" | "graph" | "sybil" | "drift" | "local_context";
  }>;
  issued_at: RFC3339;
  signature?: HexSig;
}

export interface NormalizationProfileV1 {
  type: "tsl.normalization_profile.v1";
  profile_id: string;
  feature_ranges_bps: Record<string, { min_bps: number; max_bps: number; missing_bps: number }>;
  training_window?: { start: RFC3339; end: RFC3339 };
  percentiles_bps?: Record<string, { p05_bps: number; p50_bps: number; p95_bps: number }>;
  missing_value_policy?: "impute_zero_with_coverage_penalty" | "impute_median_with_uncertainty" | "reject";
  time_split_fit_status?: "not_declared" | "train_validation_test_split" | "rolling_window_validated";
  issued_at: RFC3339;
  signature?: HexSig;
}

export interface WeightProfileV1 {
  type: "tsl.weight_profile.v1";
  profile_id: string;
  weights_bps: Record<string, number>;
  feature_directions?: Record<string, "positive" | "penalty">;
  issued_at: RFC3339;
  signature?: HexSig;
}

export interface CalibrationProfileV1 {
  type: "tsl.calibration_profile.v1";
  profile_id: string;
  points: Array<{ raw_bps: number; calibrated_bps: number }>;
  issued_at: RFC3339;
  signature?: HexSig;
}

export interface ConfidenceProfileV1 {
  type: "tsl.confidence_profile.v1";
  profile_id: string;
  method?: "analytic_profile_v1" | "deterministic_bootstrap_v1" | "dev_heuristic_v0";
  bootstrap_unit?: "feature" | "edge_counterparty_attestation";
  min_width_bps: number;
  max_width_bps: number;
  coverage_weight_bps: number;
  evidence_weight_bps?: number;
  bootstrap_seed?: Hex32;
  bootstrap_rounds?: number;
  issued_at: RFC3339;
  signature?: HexSig;
}

export interface ProviderGovernanceStatusV1 {
  type: "tsl.provider_governance_status.v1";
  provider: TrustID;
  status: "sandbox" | "active" | "probation" | "research_only" | "revoked";
  model_registered: boolean;
  evaluation_report_commitment: Hex32;
  red_team_result: "pass" | "fail" | "not_run";
  privacy_leakage_bps: number;
  promotion_gate_result: "pass" | "fail" | "conditional" | "research_only";
  issued_at: RFC3339;
  signature?: HexSig;
}

export interface AgentDelegationUnsignedV1 {
  type: "tsl.agent_delegation.v1";
  controller: TrustID;
  controller_key_id: string;
  agent: TrustID;
  agent_key_id: string;
  scope: string[];
  session_key?: string;
  max_uses?: number;
  spending_limit_commitment?: Hex32;
  issued_at: RFC3339;
  expires_at: RFC3339;
  nonce: Hex32;
}

export interface AgentDelegationV1 extends AgentDelegationUnsignedV1 {
  controller_signature: HexSig;
  agent_signature: HexSig;
}

export interface AuditFindingUnsignedV1 {
  type: "tsl.audit.finding.v1";
  auditor: TrustID;
  checkpoint_hash?: Hex32;
  epoch_start_ms?: number;
  shard?: string;
  finding_class:
    | "checkpoint_valid"
    | "checkpoint_conflict"
    | "previous_checkpoint_broken"
    | "settlement_mismatch"
    | "settlement_missing"
    | "root_mismatch";
  severity: "info" | "warning" | "critical";
  evidence_commitment: Hex32;
  issued_at: RFC3339;
}

export interface AuditFindingV1 extends AuditFindingUnsignedV1 {
  signature: HexSig;
}

export interface GovernancePolicyUnsignedV1 {
  type: "tsl.governance_policy.v1";
  policy_id: string;
  authority: TrustID;
  authority_key_id: string;
  protocol_schema_commitment: Hex32;
  provider_rules_commitment: Hex32;
  appeal_policy_commitment: Hex32;
  model_card_commitment?: Hex32;
  emergency_pause: boolean;
  issued_at: RFC3339;
  expires_at?: RFC3339;
}

export interface GovernancePolicyV1 extends GovernancePolicyUnsignedV1 {
  signature: HexSig;
}

export interface ProofBundleV1 {
  type: "tsl.proof_bundle.v1";
  bundle_id: Hex32;
  created_at: RFC3339;
  identity: IdentityDocumentV1;
  envelope: EventCommitmentV1;
	  proof: InclusionProofV1;
	  checkpoint: BatchCheckpointV1;
	  receipts?: ReceiptCommitmentV1[];
	  attestations?: AttestationV1[];
	  attestations_v2?: AttestationV2[];
	  receipt_disputes?: Record<Hex32, ReceiptDisputeMetadataV1>;
	  revocations?: RevocationV1[];
	  settlement_evidence?: SettlementEvidenceV1[];
	  assessment?: TrustAssessmentV1 | null;
  assessment_v2?: TrustAssessmentV2 | null;
  scoring_profile?: ScoringProfileV2;
  domain_policy?: DomainPolicyV1;
  evidence_coverage?: EvidenceCoverageV1;
  feature_registry?: FeatureRegistryV1;
  normalization_profile?: NormalizationProfileV1;
  weight_profile?: WeightProfileV1;
  calibration_profile?: CalibrationProfileV1;
  confidence_profile?: ConfidenceProfileV1;
  provider_governance_status?: ProviderGovernanceStatusV1;
  metadata_fingerprints?: MetadataFingerprintCommitmentV1[];
  graph_profile?: GraphProfileV2;
  graph_feature_vector?: GraphFeatureVectorV1;
  trusted_seeds?: TrustID[];
  adversarial_seeds?: TrustID[];
  trusted_seed_governance?: SeedGovernanceProfileV1;
  adversarial_seed_governance?: SeedGovernanceProfileV1;
  event_receivers?: Record<Hex32, TrustID>;
  sybil_assessment?: SybilAssessmentV1;
  sybil_profile?: VerifyTSLInput["sybil_profile"];
  drift_report?: DriftReportV1;
  drift_feature_history?: VerifyTSLInput["drift_feature_history"];
  drift_cohort_baseline_components?: VerifyTSLInput["drift_cohort_baseline_components"];
  zk_proofs?: ZkThresholdProofV1[];
  zk_circuit_manifests?: ZkCircuitReleaseManifestV1[];
  zk_verification_key_registry?: ZkVerificationKeyRegistryV1;
  delegations?: AgentDelegationV1[];
  delegation_policies?: DelegationPolicyV2[];
  agent_actions?: AgentActionV2[];
  audit_findings?: AuditFindingV1[];
  consistency_proofs?: ConsistencyProofV1[];
  non_membership_proofs?: SetNonMembershipProofV1[];
  governance_policy?: GovernancePolicyV1;
  redaction_manifest: {
    raw_content_included: boolean;
    content_salt_included?: boolean;
    exact_counterparties_included: boolean;
    metadata_fields_redacted: string[];
  };
  appeal_metadata?: Record<string, unknown>;
  local_disclosure_warnings?: string[];
  message_disclosure?: MessageDisclosure;
  disclosure_consents?: DisclosureConsentV1[];
}

export interface MessageDisclosure {
  raw_message?: string;
  content_salt?: string;
}

export interface VerifierPolicy {
  require_inclusion?: boolean;
  require_checkpoint?: boolean;
  require_settlement?: boolean;
  require_provider_registry?: boolean;
  require_chain_revocation?: boolean;
  require_zk_claims?: Array<ZkThresholdProofV1["claim"]>;
  require_consistency_proof?: boolean;
  require_non_membership_proof?: boolean;
  require_governance_policy?: boolean;
  require_agent_scope?: string;
  require_audit_consistency?: boolean;
  accepted_scoring_profiles?: string[];
  required_domain_policy?: string;
  require_v2_assessment?: boolean;
  require_metadata_fingerprint_policy?: boolean;
  require_graph_artifacts?: boolean;
  require_registered_zk_circuit?: boolean;
  require_sparse_merkle_revocation_root?: boolean;
  require_research_graph_algorithm?: boolean;
  require_provider_governance_active?: boolean;
  production_scoring_required?: boolean;
  require_sybil_provider_issuer?: boolean;
  require_seed_governance_opening?: boolean;
  require_full_covariance_drift?: boolean;
  require_manifest_verification_key_hash?: boolean;
  reject_dev_zk_circuits?: boolean;
  reject_unsigned_local_proof_bundles?: boolean;
  require_authorized_relay?: boolean;
  authorized_relays?: TrustID[];
  require_receipt_inclusion_for_disclosed_receipts?: boolean;
  require_disclosure_consent_for_private_fields?: boolean;
  require_profile_derived_scoring?: boolean;
  require_behavioral_sybil_tiers?: boolean;
  require_fixed_point_drift?: boolean;
  require_four_root_checkpoint?: boolean;
  require_exact_graph_formulas?: boolean;
  require_core_drift_formula?: boolean;
  require_profile_signed_scoring?: boolean;
  reject_unsafe_fixtures_on_mainnet?: boolean;
  accepted_auditors?: TrustID[];
  accepted_governance_policy?: string;
  accepted_scoring_providers?: TrustID[];
  verifier_or_provider?: TrustID;
  disclosure_purpose?: string;
  revoked_disclosure_pointers?: string[];
  disclosure_checked_at?: RFC3339;
  max_assessment_age_ms?: number;
}

export interface VerificationChecks {
  schema_valid: boolean;
  signature_valid: boolean;
  key_found: boolean;
  key_active: boolean;
  not_revoked: boolean;
  content_commitment_matches?: boolean;
  included_in_log: boolean;
  checkpoint_valid: boolean;
  checkpoint_matches_proof: boolean;
  checkpoint_settled: boolean;
  settlement_evidence_valid?: boolean;
  receipt_valid?: boolean;
  attestation_valid?: boolean;
  revocation_state_valid?: boolean;
  assessment_valid?: boolean;
  provider_active?: boolean;
  model_registered?: boolean;
  chain_revocation_checked?: boolean;
  zk_valid?: boolean;
  agent_scope_valid?: boolean;
  audit_consistency_valid?: boolean;
  consistency_proof_valid?: boolean;
  non_membership_proof_valid?: boolean;
  zk_circuit_registered?: boolean;
  research_graph_algorithm_valid?: boolean;
  provider_governance_valid?: boolean;
  seed_governance_valid?: boolean;
  full_covariance_drift_valid?: boolean;
  governance_policy_valid?: boolean;
  trust_assessment_v2_valid?: boolean;
  scoring_profile_valid?: boolean;
  domain_policy_valid?: boolean;
  evidence_coverage_valid?: boolean;
  metadata_fingerprint_valid?: boolean;
  disclosure_consent_valid?: boolean;
  redaction_manifest_valid?: boolean;
  checkpoint_signature_valid?: boolean;
  graph_artifacts_valid?: boolean;
  sybil_assessment_valid?: boolean;
  drift_report_valid?: boolean;
  delegated_action_valid?: boolean;
  receipt_included?: boolean;
  authorized_relay_valid?: boolean;
  attestation_included?: boolean;
  revocation_included?: boolean;
}

export interface VerificationResult {
  verified: boolean;
  commitment_hash?: Hex32;
  event_hash?: Hex32;
  checks: VerificationChecks;
  settlement_status?: "not_required" | "pending" | "settled" | "unavailable" | "mismatch";
  risk_label: "not_assessed" | TrustAssessmentV1["label"];
  explanation: string[];
  errors: string[];
}

export interface VerifyTSLInput {
  proof_bundle?: ProofBundleV1;
  envelope: EventCommitmentV1;
  proof?: InclusionProofV1;
	  receipt_proofs?: InclusionProofV1[];
	  checkpoint?: BatchCheckpointV1;
	  receipts?: ReceiptCommitmentV1[];
	  attestations?: AttestationV1[];
	  attestations_v2?: AttestationV2[];
	  receipt_disputes?: Record<Hex32, ReceiptDisputeMetadataV1>;
	  revocations?: RevocationV1[];
	  settlement_evidence?: SettlementEvidenceV1[];
	  assessment?: TrustAssessmentV1;
  assessment_v2?: TrustAssessmentV2;
  scoring_profile?: ScoringProfileV2;
  domain_policy?: DomainPolicyV1;
  evidence_coverage?: EvidenceCoverageV1;
  feature_registry?: FeatureRegistryV1;
  normalization_profile?: NormalizationProfileV1;
  weight_profile?: WeightProfileV1;
  calibration_profile?: CalibrationProfileV1;
  confidence_profile?: ConfidenceProfileV1;
  provider_governance_status?: ProviderGovernanceStatusV1;
  metadata_fingerprints?: MetadataFingerprintCommitmentV1[];
  graph_profile?: GraphProfileV2;
  graph_feature_vector?: GraphFeatureVectorV1;
  trusted_seeds?: TrustID[];
  adversarial_seeds?: TrustID[];
  trusted_seed_governance?: SeedGovernanceProfileV1;
  adversarial_seed_governance?: SeedGovernanceProfileV1;
  event_receivers?: Record<Hex32, TrustID>;
  sybil_assessment?: SybilAssessmentV1;
  sybil_profile?: {
    profile_id: string;
    adversary_tier?: SybilAssessmentV1["adversary_tier_assumed"];
    min_evidence_mass?: number;
    base_identity_cost_minor_units?: number;
    time_aging_cost_minor_units?: number;
    external_receipt_cost_minor_units?: number;
    attestation_cost_minor_units?: number;
    compromise_cost_minor_units?: number;
    evasion_cost_minor_units?: number;
    internal_edge_cost_minor_units?: number;
    expected_benefit_minor_units?: number;
    attack_scenario?: string;
    compromise_signals?: SybilCompromiseSignalsV1;
    issuer_collusion_signals?: SybilIssuerCollusionSignalsV1;
    infrastructure_collusion_signals?: SybilInfrastructureCollusionSignalsV1;
    compromise_evidence?: SybilCompromiseEvidenceV1;
    issuer_collusion_evidence?: SybilIssuerCollusionEvidenceV1;
    infrastructure_collusion_evidence?: SybilInfrastructureCollusionEvidenceV1;
  };
  drift_report?: DriftReportV1;
  drift_feature_history?: Array<{
    timestamp: RFC3339;
    components: Partial<Record<"key" | "graph" | "action" | "cadence" | "claim" | "agent" | "local", number>>;
    verified_event?: boolean;
    high_value_action?: boolean;
    new_delegation_pattern?: boolean;
    adverse_evidence?: boolean;
  }>;
  drift_cohort_baseline_components?: Array<Partial<Record<"key" | "graph" | "action" | "cadence" | "claim" | "agent" | "local", number>>>;
  zk_proofs?: ZkThresholdProofV1[];
  zk_circuit_manifests?: ZkCircuitReleaseManifestV1[];
  zk_verification_key_registry?: ZkVerificationKeyRegistryV1;
  delegations?: AgentDelegationV1[];
  delegation_policies?: DelegationPolicyV2[];
  agent_actions?: AgentActionV2[];
  audit_findings?: AuditFindingV1[];
  consistency_proofs?: ConsistencyProofV1[];
  non_membership_proofs?: SetNonMembershipProofV1[];
  governance_policy?: GovernancePolicyV1;
  redaction_manifest?: ProofBundleV1["redaction_manifest"];
  message_disclosure?: MessageDisclosure;
  disclosure_consents?: DisclosureConsentV1[];
}

export interface TrustResolver {
  resolveTrustID(trustId: TrustID, atTime?: RFC3339): IdentityDocumentV1 | null | Promise<IdentityDocumentV1 | null>;
}
