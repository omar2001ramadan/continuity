use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn required_fields_for_type(object_type: &str) -> Option<&'static [&'static str]> {
    match object_type {
        "tsl.identity.v1" => Some(&["type", "id", "controller", "created_at", "verification_methods"]),
        "tsl.event_commitment.v1" => Some(&[
            "type",
            "event_class",
            "sender",
            "signing_key_id",
            "content_commitment",
            "timestamp",
            "nonce",
            "disclosure_policy",
            "signature",
        ]),
        "tsl.receipt_commitment.v1" => Some(&[
            "type",
            "event_commitment",
            "receiver",
            "signing_key_id",
            "receipt_class",
            "timestamp",
            "signature",
        ]),
        "tsl.revocation.v1" => Some(&["type", "trust_id", "revoked_key", "reason_class", "effective_at", "signature"]),
        "tsl.batch_checkpoint.v1" => Some(&[
            "type",
            "epoch_start_ms",
            "epoch_duration_ms",
            "shard",
            "event_root",
            "receipt_root",
            "attestation_root",
            "revocation_root",
            "event_count",
            "receipt_count",
            "previous_checkpoint",
            "relay_id",
            "relay_signature",
        ]),
        "tsl.inclusion_proof.v1" => Some(&[
            "type",
            "tree_kind",
            "commitment",
            "leaf_index",
            "leaf_hash",
            "root",
            "epoch_start_ms",
            "epoch_duration_ms",
            "shard",
            "path",
            "checkpoint_hash",
        ]),
        "tsl.proof_bundle.v1" => Some(&[
            "type",
            "bundle_id",
            "created_at",
            "envelope",
            "proof",
            "checkpoint",
            "identity",
            "redaction_manifest",
        ]),
        "tsl.attestation.v2" => Some(&[
            "type",
            "attestation_id",
            "issuer",
            "subject",
            "claim_class",
            "claim_polarity",
            "severity",
            "claim_commitment",
            "evidence_commitment",
            "evidence_policy",
            "visibility",
            "appeal_uri",
            "issued_at",
            "valid_after",
            "expires_at",
            "revocation_pointer",
            "signature",
        ]),
        "tsl.evidence_coverage.v1" => Some(&[
            "type",
            "subject",
            "computed_at",
            "valid_signed_event_count",
            "valid_receipt_count",
            "unique_counterparty_count",
            "distinct_community_count",
            "attestation_count",
            "recent_revocation_count",
            "coverage_bps",
            "coverage_label",
            "missing_evidence",
        ]),
        "tsl.graph_profile.v2" => Some(&[
            "type",
            "profile_id",
            "edge_weight_profile",
            "temporal_decay_profile",
            "community_detection",
            "seed_sets",
            "negative_edge_policy",
            "privacy_policy",
        ]),
        "tsl.graph_feature_vector.v1" => Some(&[
            "type",
            "subject",
            "graph_profile_id",
            "computed_at",
            "weighted_degree_bps",
            "reciprocity_bps",
            "counterparty_hhi_bps",
            "counterparty_entropy_bps",
            "effective_counterparty_count_milli",
            "seed_escape_bps",
            "adversarial_proximity_bps",
            "privacy_disclosure_level",
            "signature",
        ]),
        "tsl.sybil_assessment.v1" => Some(&[
            "type",
            "subject",
            "cluster_id_commitment",
            "computed_at",
            "adversary_tier_assumed",
            "cluster_concentration_bps",
            "trusted_escape_bps",
            "internal_receipt_ratio_bps",
            "attack_cost_minor_units",
            "risk_score_bps",
            "risk_label",
            "privacy_level",
            "signature",
        ]),
        "tsl.drift_report.v1" => Some(&[
            "type",
            "subject",
            "computed_at",
            "baseline_window_days",
            "observation_window_days",
            "drift_score_bps",
            "drift_label",
            "action",
            "reason_codes",
            "signature",
        ]),
        "tsl.disclosure_consent.v1" => Some(&[
            "type",
            "subject",
            "verifier_or_provider",
            "allowed_field_classes",
            "forbidden_field_classes",
            "purpose",
            "issued_at",
            "expires_at",
            "revocation_pointer",
            "signature",
        ]),
        "tsl.zk.circuit_release_manifest.v1" => Some(&[
            "type",
            "circuit_id",
            "claim",
            "version",
            "circuit_hash",
            "r1cs_hash",
            "wasm_hash",
            "zkey_hash",
            "verification_key_id",
            "verification_key_hash",
            "ceremony_transcript_hash",
            "auditor",
            "reviewer",
            "status",
            "issued_at",
        ]),
        "tsl.zk.verification_key_registry.v1" => Some(&[
            "type",
            "registry_id",
            "active_manifest_hashes",
            "revoked_manifest_hashes",
            "issued_at",
        ]),
        "tsl.feature_registry.v1" => Some(&["type", "registry_id", "feature_ids", "issued_at"]),
        "tsl.normalization_profile.v1" => Some(&["type", "profile_id", "feature_ranges_bps", "issued_at"]),
        "tsl.weight_profile.v1" => Some(&["type", "profile_id", "weights_bps", "issued_at"]),
        "tsl.calibration_profile.v1" => Some(&["type", "profile_id", "points", "issued_at"]),
        "tsl.confidence_profile.v1" => Some(&["type", "profile_id", "min_width_bps", "max_width_bps", "coverage_weight_bps", "issued_at"]),
        "tsl.provider_governance_status.v1" => Some(&[
            "type",
            "provider",
            "status",
            "model_registered",
            "evaluation_report_commitment",
            "red_team_result",
            "privacy_leakage_bps",
            "promotion_gate_result",
            "issued_at",
        ]),
        "tsl.model_card.v2" => Some(&[
            "type",
            "model_id",
            "provider",
            "model_version",
            "supported_domains",
            "feature_registry_commitment",
            "evaluation_report_commitment",
            "privacy_report_commitment",
            "metrics",
            "limitations",
            "issued_at",
            "signature",
        ]),
        "tsl.delegation_policy.v2" => Some(&[
            "type",
            "policy_id",
            "principal",
            "delegate",
            "effect",
            "actions",
            "resources",
            "constraints",
            "valid_from",
            "valid_until",
            "revocation_pointer",
            "signature",
        ]),
        "tsl.agent_action.v2" => Some(&[
            "type",
            "action_id",
            "agent",
            "principal",
            "action",
            "resource",
            "parameters_commitment",
            "delegation_chain_root",
            "issued_at",
            "nonce",
            "signature",
        ]),
        _ => None,
    }
}

pub fn validate_schema_object(value: &Value) -> Result<(), String> {
    let object = value.as_object().ok_or_else(|| "TSL_SCHEMA_INVALID: expected object".to_string())?;
    let object_type = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| "TSL_SCHEMA_INVALID: missing type".to_string())?;
    let required = required_fields_for_type(object_type)
        .ok_or_else(|| format!("TSL_UNSUPPORTED_OBJECT_VERSION: {}", object_type))?;
    for field in required {
        if !object.contains_key(*field) {
            return Err(format!("TSL_SCHEMA_INVALID: missing {}", field));
        }
    }
    Ok(())
}

fn canonicalize_strict(value: &Value) -> Result<String, String> {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            let mut parts: Vec<String> = Vec::new();
            for key in keys {
                parts.push(format!("{}:{}", serde_json::to_string(key).unwrap(), canonicalize_strict(&map[key])?));
            }
            Ok(format!("{{{}}}", parts.join(",")))
        }
        Value::Array(values) => {
            let mut parts: Vec<String> = Vec::new();
            for value in values {
                parts.push(canonicalize_strict(value)?);
            }
            Ok(format!("[{}]", parts.join(",")))
        }
        Value::Number(number) => {
            let integer = number
                .as_i64()
                .map(|n| n as i128)
                .or_else(|| number.as_u64().map(|n| n as i128))
                .ok_or_else(|| "TSL canonicalization only allows integers in signed core objects".to_string())?;
            if integer < -(2_i128.pow(53) - 1) || integer > 2_i128.pow(53) - 1 {
                return Err("TSL canonicalization only allows safe integers in signed core objects".to_string());
            }
            Ok(integer.to_string())
        }
        _ => Ok(serde_json::to_string(value).unwrap()),
    }
}

pub fn canonicalize(value: &Value) -> String {
    canonicalize_strict(value).unwrap()
}

pub fn hash_domain(tag: &str, payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(tag.as_bytes());
    hasher.update([0u8]);
    hasher.update(payload);
    format!("0x{}", hex::encode(hasher.finalize()))
}

fn hex_to_bytes(value: &str) -> Vec<u8> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value)).unwrap()
}

fn uint64be(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

pub fn commitment_hash(event_hash: &str, signature: &str) -> String {
    let mut payload = hex_to_bytes(event_hash);
    payload.extend(hex_to_bytes(signature));
    hash_domain("tsl.commitment.v1", &payload)
}

pub fn legacy_commitment_hash(event_hash: &str, signature: &str) -> String {
    let mut payload = hex_to_bytes(event_hash);
    payload.extend(hex_to_bytes(signature));
    let mut hasher = Sha256::new();
    hasher.update(payload);
    format!("0x{}", hex::encode(hasher.finalize()))
}

pub fn merkle_leaf(index: u64, commitment: &str) -> String {
    let mut payload = uint64be(index).to_vec();
    payload.extend(hex_to_bytes(commitment));
    hash_domain("tsl.merkle.leaf.v1", &payload)
}

pub fn merkle_node(left: &str, right: &str) -> String {
    let mut payload = hex_to_bytes(left);
    payload.extend(hex_to_bytes(right));
    hash_domain("tsl.merkle.node.v1", &payload)
}

pub fn merkle_root(commitments: &[String]) -> String {
    if commitments.is_empty() {
        return "0x0000000000000000000000000000000000000000000000000000000000000000".to_string();
    }
    let mut level: Vec<String> = commitments
        .iter()
        .enumerate()
        .map(|(index, commitment)| merkle_leaf(index as u64, commitment))
        .collect();
    while level.len() > 1 {
        let mut next = Vec::new();
        let mut index = 0;
        while index < level.len() {
            if index + 1 < level.len() {
                next.push(merkle_node(&level[index], &level[index + 1]));
            } else {
                next.push(level[index].clone());
            }
            index += 2;
        }
        level = next;
    }
    level[0].clone()
}

pub fn verify_ed25519(public_key_hex: &str, message_hex: &str, signature_hex: &str) -> bool {
    let public_key_bytes = match <[u8; 32]>::try_from(hex_to_bytes(public_key_hex)) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let signature_bytes = match <[u8; 64]>::try_from(hex_to_bytes(signature_hex)) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let message = hex_to_bytes(message_hex);
    let key = match VerifyingKey::from_bytes(&public_key_bytes) {
        Ok(key) => key,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(&signature_bytes);
    key.verify(&message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const PUBLIC_KEY_HEX: &str = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
    const EVENT_HASH_HEX: &str = "0xcf5cb36e4596ed4c446f2d24504407369a1fc4862928e86c340ec5270fcc3267";
    const SIGNATURE_HEX: &str = "0xd3187ac9861b87a3b5f871c9ae9a6426ce0c1e49cee1978c767bf99eff6c94467b6955cd9821c2a7e3bfcf945b576e49d81deccb4e7c8b0624917fd794f1ff08";
    const COMMITMENT_HASH_HEX: &str = "0xcc680d3c19dbbb9785640355a4756a498fb887c643dc04ef304689955381251d";
    const LEGACY_COMMITMENT_HASH_HEX: &str = "0x174c377613f1fa94acc95d32408095c27330f5dfa088ee40cdcb81a503b25bb5";
    const SINGLE_LEAF_ROOT_HEX: &str = "0x2af3150c9d8e62aac337ef020e3f5d07a7529116e59eba6b152ffb3570e611d7";
    const LEGACY_SINGLE_LEAF_ROOT_HEX: &str = "0xc09632a2beaaf0c4702e673a7a1661673c80be478f1136b60677f38c5bb5914f";

    #[test]
    fn shared_core_vectors_match() {
        assert_eq!(canonicalize(&json!({"b": 2, "a": 1})), "{\"a\":1,\"b\":2}");
        assert!(std::panic::catch_unwind(|| canonicalize(&json!({"invalid_float": 0.5}))).is_err());
        assert!(std::panic::catch_unwind(|| canonicalize(&json!({"unsafe_integer": 9007199254740992u64}))).is_err());

        assert_eq!(commitment_hash(EVENT_HASH_HEX, SIGNATURE_HEX), COMMITMENT_HASH_HEX);
        assert_eq!(legacy_commitment_hash(EVENT_HASH_HEX, SIGNATURE_HEX), LEGACY_COMMITMENT_HASH_HEX);
        assert_eq!(merkle_root(&[COMMITMENT_HASH_HEX.to_string()]), SINGLE_LEAF_ROOT_HEX);
        assert_eq!(merkle_root(&[LEGACY_COMMITMENT_HASH_HEX.to_string()]), LEGACY_SINGLE_LEAF_ROOT_HEX);
        assert!(verify_ed25519(PUBLIC_KEY_HEX, EVENT_HASH_HEX, SIGNATURE_HEX));
        assert!(!verify_ed25519(
            PUBLIC_KEY_HEX,
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            SIGNATURE_HEX
        ));
    }

    #[test]
    fn release_critical_validator_parity() {
        let consent = json!({
            "type": "tsl.disclosure_consent.v1",
            "subject": "did:tsl:test:alice",
            "verifier_or_provider": "did:tsl:provider:verifier",
            "allowed_field_classes": ["raw_content"],
            "forbidden_field_classes": ["ip_address"],
            "purpose": "verification_opening",
            "issued_at": "2026-05-27T00:00:00Z",
            "expires_at": "2026-05-28T00:00:00Z",
            "revocation_pointer": "rev:1",
            "signature": "0x00"
        });
        assert!(validate_schema_object(&consent).is_ok());
        let mut missing_signature = consent.clone();
        missing_signature.as_object_mut().unwrap().remove("signature");
        assert!(validate_schema_object(&missing_signature).is_err());

        let graph_vector = json!({
            "type": "tsl.graph_feature_vector.v1",
            "subject": "did:tsl:test:alice",
            "graph_profile_id": "graph-default-rc4",
            "computed_at": "2026-05-27T00:00:00Z",
            "weighted_degree_bps": 10000,
            "reciprocity_bps": 5000,
            "counterparty_hhi_bps": 5000,
            "counterparty_entropy_bps": 8000,
            "effective_counterparty_count_milli": 2000,
            "seed_escape_bps": 1000,
            "adversarial_proximity_bps": 0,
            "privacy_disclosure_level": "aggregate_only",
            "signature": "0x00"
        });
        assert!(validate_schema_object(&graph_vector).is_ok());

        let zk_manifest = json!({
            "type": "tsl.zk.circuit_release_manifest.v1",
            "circuit_id": "identity-age-threshold-v1",
            "claim": "identity_age_days",
            "version": "1.0.0",
            "circuit_hash": COMMITMENT_HASH_HEX,
            "r1cs_hash": COMMITMENT_HASH_HEX,
            "wasm_hash": COMMITMENT_HASH_HEX,
            "zkey_hash": COMMITMENT_HASH_HEX,
            "verification_key_id": "identity-age-vkey-v1",
            "verification_key_hash": COMMITMENT_HASH_HEX,
            "ceremony_transcript_hash": COMMITMENT_HASH_HEX,
            "auditor": "did:tsl:auditor:test",
            "reviewer": "did:tsl:reviewer:test",
            "status": "active",
            "issued_at": "2026-05-27T00:00:00Z"
        });
        assert!(validate_schema_object(&zk_manifest).is_ok());

        let governance = json!({
            "type": "tsl.provider_governance_status.v1",
            "provider": "did:tsl:provider:test",
            "status": "active",
            "model_registered": true,
            "evaluation_report_commitment": COMMITMENT_HASH_HEX,
            "red_team_result": "pass",
            "privacy_leakage_bps": 100,
            "promotion_gate_result": "pass",
            "issued_at": "2026-05-27T00:00:00Z"
        });
        assert!(validate_schema_object(&governance).is_ok());
    }
}
