CREATE TABLE IF NOT EXISTS trust_identities (
    trust_id TEXT PRIMARY KEY,
    controller TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    identity_document JSONB NOT NULL,
    identity_hash TEXT NOT NULL CHECK (identity_hash ~ '^0x[0-9a-f]{64}$'),
    latest_checkpoint_hash TEXT,
    created_block_number BIGINT,
    created_tx_hash TEXT,
    inserted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS verification_keys (
    trust_id TEXT NOT NULL REFERENCES trust_identities(trust_id) ON DELETE CASCADE,
    key_id TEXT NOT NULL,
    key_type TEXT NOT NULL,
    public_key TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active','revoked','expired')),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT,
    PRIMARY KEY (trust_id, key_id)
);

CREATE TABLE IF NOT EXISTS revocations (
    revocation_hash TEXT PRIMARY KEY CHECK (revocation_hash ~ '^0x[0-9a-f]{64}$'),
    trust_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    reason_class TEXT NOT NULL,
    effective_at TIMESTAMPTZ NOT NULL,
    replacement_key_id TEXT,
    canonical_body BYTEA NOT NULL,
    signature TEXT NOT NULL,
    relay_id TEXT NOT NULL DEFAULT 'did:tsl:relay:unknown',
    shard TEXT NOT NULL DEFAULT '0000',
    epoch_start_ms BIGINT NOT NULL DEFAULT 0,
    log_index BIGINT,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS event_commitments (
    commitment_hash TEXT PRIMARY KEY CHECK (commitment_hash ~ '^0x[0-9a-f]{64}$'),
    sender_trust_id TEXT NOT NULL,
    signing_key_id TEXT NOT NULL,
    event_class TEXT NOT NULL,
    content_commitment TEXT NOT NULL,
    receiver_commitment TEXT,
    metadata_commitment TEXT,
    previous_event_commitment TEXT,
    event_timestamp TIMESTAMPTZ NOT NULL,
    nonce TEXT NOT NULL,
    disclosure_policy TEXT NOT NULL,
    canonical_body BYTEA NOT NULL,
    signature TEXT NOT NULL,
    relay_id TEXT NOT NULL,
    shard TEXT NOT NULL,
    epoch_start_ms BIGINT NOT NULL,
    log_index BIGINT,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(sender_trust_id, signing_key_id, nonce)
);

CREATE INDEX IF NOT EXISTS idx_event_commitments_sender_time ON event_commitments(sender_trust_id, event_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_event_commitments_epoch_shard ON event_commitments(epoch_start_ms, shard, log_index);

CREATE TABLE IF NOT EXISTS receipt_commitments (
    receipt_hash TEXT PRIMARY KEY CHECK (receipt_hash ~ '^0x[0-9a-f]{64}$'),
    event_commitment TEXT NOT NULL,
    receiver_trust_id TEXT NOT NULL,
    signing_key_id TEXT NOT NULL,
    receipt_class TEXT NOT NULL,
    receipt_timestamp TIMESTAMPTZ NOT NULL,
    metadata_commitment TEXT,
    canonical_body BYTEA NOT NULL,
    signature TEXT NOT NULL,
    relay_id TEXT NOT NULL,
    shard TEXT NOT NULL,
    epoch_start_ms BIGINT NOT NULL,
    log_index BIGINT,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS attestations (
    attestation_hash TEXT PRIMARY KEY CHECK (attestation_hash ~ '^0x[0-9a-f]{64}$'),
    issuer_trust_id TEXT NOT NULL,
    subject_trust_id TEXT NOT NULL,
    attestation_class TEXT NOT NULL,
    visibility TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    claim_commitment TEXT NOT NULL,
    canonical_body BYTEA NOT NULL,
    signature TEXT NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    relay_id TEXT NOT NULL DEFAULT 'did:tsl:relay:unknown',
    shard TEXT NOT NULL DEFAULT '0000',
    epoch_start_ms BIGINT NOT NULL DEFAULT 0,
    log_index BIGINT
);

CREATE TABLE IF NOT EXISTS checkpoints (
    checkpoint_hash TEXT PRIMARY KEY CHECK (checkpoint_hash ~ '^0x[0-9a-f]{64}$'),
    epoch_start_ms BIGINT NOT NULL,
    epoch_duration_ms BIGINT NOT NULL,
    shard TEXT NOT NULL,
    event_root TEXT NOT NULL,
    receipt_root TEXT NOT NULL,
    attestation_root TEXT NOT NULL,
    revocation_root TEXT NOT NULL,
    event_count BIGINT NOT NULL,
    receipt_count BIGINT NOT NULL,
    previous_checkpoint TEXT NOT NULL,
    relay_id TEXT NOT NULL,
    relay_signature TEXT NOT NULL,
    settlement_backend TEXT,
    settlement_tx TEXT,
    settlement_status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    settled_at TIMESTAMPTZ,
    UNIQUE(epoch_start_ms, shard)
);

CREATE TABLE IF NOT EXISTS merkle_nodes (
    epoch_start_ms BIGINT NOT NULL,
    shard TEXT NOT NULL,
    tree_kind TEXT NOT NULL CHECK (tree_kind IN ('event','receipt','attestation','revocation')),
    level INTEGER NOT NULL,
    node_index BIGINT NOT NULL,
    node_hash TEXT NOT NULL CHECK (node_hash ~ '^0x[0-9a-f]{64}$'),
    PRIMARY KEY (epoch_start_ms, shard, tree_kind, level, node_index)
);

CREATE TABLE IF NOT EXISTS provider_registry_cache (
    provider_id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    policy_commitment TEXT NOT NULL,
    status TEXT NOT NULL,
    latest_model_id TEXT,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS trust_assessments (
    assessment_hash TEXT PRIMARY KEY CHECK (assessment_hash ~ '^0x[0-9a-f]{64}$'),
    subject_trust_id TEXT NOT NULL,
    issuer_provider_id TEXT NOT NULL,
    score_bps INTEGER NOT NULL CHECK (score_bps BETWEEN 0 AND 10000),
    label TEXT NOT NULL,
    model_version TEXT NOT NULL,
    evidence_commitment TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    canonical_body BYTEA NOT NULL,
    signature TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scoring_profiles_v2 (
    profile_id TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    model_version TEXT NOT NULL,
    profile_hash TEXT NOT NULL CHECK (profile_hash ~ '^0x[0-9a-f]{64}$'),
    evaluation_report_commitment TEXT NOT NULL CHECK (evaluation_report_commitment ~ '^0x[0-9a-f]{64}$'),
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    canonical_body BYTEA NOT NULL,
    signature TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS feature_definitions_v2 (
    feature_id TEXT PRIMARY KEY,
    profile_id TEXT NOT NULL REFERENCES scoring_profiles_v2(profile_id) ON DELETE CASCADE,
    feature_name TEXT NOT NULL,
    feature_family TEXT NOT NULL,
    value_unit TEXT NOT NULL,
    normalization_rule JSONB NOT NULL,
    privacy_class TEXT NOT NULL,
    canonical_body BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS domain_policies_v1 (
    policy_id TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    min_coverage_bps INTEGER NOT NULL CHECK (min_coverage_bps BETWEEN 0 AND 10000),
    threshold_policy JSONB NOT NULL,
    false_positive_cost_bps INTEGER,
    false_negative_cost_bps INTEGER,
    canonical_body BYTEA NOT NULL,
    signature TEXT
);

CREATE TABLE IF NOT EXISTS evidence_coverage_v1 (
    coverage_hash TEXT PRIMARY KEY CHECK (coverage_hash ~ '^0x[0-9a-f]{64}$'),
    subject_trust_id TEXT NOT NULL,
    signed_event_count BIGINT NOT NULL,
    reciprocal_receipt_count BIGINT NOT NULL,
    unique_counterparty_count BIGINT NOT NULL,
    trusted_counterparty_mass_bps INTEGER NOT NULL CHECK (trusted_counterparty_mass_bps BETWEEN 0 AND 10000),
    coverage_bps INTEGER NOT NULL CHECK (coverage_bps BETWEEN 0 AND 10000),
    computed_at TIMESTAMPTZ NOT NULL,
    canonical_body BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS trust_assessments_v2 (
    assessment_hash TEXT PRIMARY KEY CHECK (assessment_hash ~ '^0x[0-9a-f]{64}$'),
    subject_trust_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    score_bps INTEGER CHECK (score_bps BETWEEN 0 AND 10000),
    confidence_low_bps INTEGER,
    confidence_high_bps INTEGER,
    risk_label TEXT NOT NULL,
    evidence_coverage_hash TEXT,
    evidence_commitment TEXT CHECK (evidence_commitment IS NULL OR evidence_commitment ~ '^0x[0-9a-f]{64}$'),
    feature_vector_commitment TEXT CHECK (feature_vector_commitment IS NULL OR feature_vector_commitment ~ '^0x[0-9a-f]{64}$'),
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    canonical_body BYTEA NOT NULL,
    signature TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS metadata_fingerprint_commitments_v1 (
    fingerprint_commitment TEXT PRIMARY KEY CHECK (fingerprint_commitment ~ '^0x[0-9a-f]{64}$'),
    subject_trust_id TEXT NOT NULL,
    scope_class TEXT NOT NULL,
    scope_commitment TEXT NOT NULL CHECK (scope_commitment ~ '^0x[0-9a-f]{64}$'),
    bucket_profile TEXT NOT NULL,
    created_at_bucket TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    disclosure_policy TEXT NOT NULL,
    canonical_body BYTEA NOT NULL,
    signature TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS graph_feature_vectors_v1 (
    feature_vector_hash TEXT PRIMARY KEY CHECK (feature_vector_hash ~ '^0x[0-9a-f]{64}$'),
    subject_trust_id TEXT NOT NULL,
    graph_profile_id TEXT NOT NULL,
    computed_at TIMESTAMPTZ NOT NULL,
    reciprocity_bps INTEGER,
    counterparty_diversity_bps INTEGER,
    effective_counterparty_count_milli BIGINT,
    community_escape_bps INTEGER,
    trusted_neighbor_mass_bps INTEGER,
    adversarial_proximity_bps INTEGER,
    privacy_level TEXT NOT NULL,
    canonical_body BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS sybil_assessments_v1 (
    sybil_assessment_hash TEXT PRIMARY KEY CHECK (sybil_assessment_hash ~ '^0x[0-9a-f]{64}$'),
    subject_trust_id TEXT NOT NULL,
    cluster_id_commitment TEXT NOT NULL CHECK (cluster_id_commitment ~ '^0x[0-9a-f]{64}$'),
    adversary_tier_assumed TEXT NOT NULL,
    risk_score_bps INTEGER NOT NULL CHECK (risk_score_bps BETWEEN 0 AND 10000),
    risk_label TEXT NOT NULL,
    computed_at TIMESTAMPTZ NOT NULL,
    canonical_body BYTEA NOT NULL,
    signature TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS drift_reports_v1 (
    drift_report_hash TEXT PRIMARY KEY CHECK (drift_report_hash ~ '^0x[0-9a-f]{64}$'),
    subject_trust_id TEXT NOT NULL,
    drift_score_bps INTEGER NOT NULL CHECK (drift_score_bps BETWEEN 0 AND 10000),
    drift_label TEXT NOT NULL,
    action TEXT NOT NULL,
    computed_at TIMESTAMPTZ NOT NULL,
    canonical_body BYTEA NOT NULL,
    signature TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS model_cards_v2 (
    model_id TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL,
    model_version TEXT NOT NULL,
    model_card_hash TEXT NOT NULL CHECK (model_card_hash ~ '^0x[0-9a-f]{64}$'),
    evaluation_report_commitment TEXT NOT NULL CHECK (evaluation_report_commitment ~ '^0x[0-9a-f]{64}$'),
    privacy_report_commitment TEXT NOT NULL CHECK (privacy_report_commitment ~ '^0x[0-9a-f]{64}$'),
    issued_at TIMESTAMPTZ NOT NULL,
    canonical_body BYTEA NOT NULL,
    signature TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evaluation_reports_v1 (
    report_id TEXT PRIMARY KEY,
    model_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    auroc_bps INTEGER,
    auprc_bps INTEGER,
    ece_bps INTEGER,
    privacy_leakage_bps INTEGER,
    promotion_gate_result TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    canonical_body BYTEA NOT NULL,
    signature TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS delegation_policies_v2 (
    policy_id TEXT PRIMARY KEY,
    principal_trust_id TEXT NOT NULL,
    delegate_trust_id TEXT NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    revocation_pointer TEXT NOT NULL,
    canonical_body BYTEA NOT NULL,
    signature TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_actions_v2 (
    action_id TEXT PRIMARY KEY,
    agent_trust_id TEXT NOT NULL,
    principal_trust_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    tool TEXT,
    parameters_commitment TEXT CHECK (parameters_commitment ~ '^0x[0-9a-f]{64}$'),
    issued_at TIMESTAMPTZ NOT NULL,
    canonical_body BYTEA NOT NULL,
    signature TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_findings (
    finding_hash TEXT PRIMARY KEY CHECK (finding_hash ~ '^0x[0-9a-f]{64}$'),
    auditor TEXT NOT NULL,
    finding_class TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('info','warning','critical')),
    checkpoint_hash TEXT CHECK (checkpoint_hash IS NULL OR checkpoint_hash ~ '^0x[0-9a-f]{64}$'),
    epoch_start_ms BIGINT,
    shard TEXT,
    evidence_commitment TEXT NOT NULL CHECK (evidence_commitment ~ '^0x[0-9a-f]{64}$'),
    canonical_body BYTEA NOT NULL,
    signature TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_findings_checkpoint ON audit_findings(checkpoint_hash, severity);

CREATE TABLE IF NOT EXISTS gossip_peers (
    peer_url TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS abuse_evidence (
    evidence_commitment TEXT PRIMARY KEY CHECK (evidence_commitment ~ '^0x[0-9a-f]{64}$'),
    issuer TEXT,
    subject TEXT,
    claim_class TEXT,
    appeal_pointer TEXT,
    review_state TEXT NOT NULL,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS abuse_appeals (
    appeal_id TEXT PRIMARY KEY,
    subject TEXT,
    evidence_commitment TEXT CHECK (evidence_commitment IS NULL OR evidence_commitment ~ '^0x[0-9a-f]{64}$'),
    appeal_pointer TEXT,
    review_state TEXT NOT NULL,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
