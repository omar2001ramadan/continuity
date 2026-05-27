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

pub fn canonicalize(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .into_iter()
                .map(|key| format!("{}:{}", serde_json::to_string(key).unwrap(), canonicalize(&map[key])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(values) => format!("[{}]", values.iter().map(canonicalize).collect::<Vec<_>>().join(",")),
        _ => serde_json::to_string(value).unwrap(),
    }
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

    #[test]
    fn canonicalizes_reordered_objects() {
        assert_eq!(canonicalize(&json!({"b": 2, "a": 1})), "{\"a\":1,\"b\":2}");
    }

    #[test]
    fn event_hash_matches_vector() {
        let payload = json!({
            "content_commitment": "0x50f62d6063e0d92d02fd4fdafb4b10c38bf271ebb5e14afd037d35b0b35f6b95",
            "disclosure_policy": "commitment_only",
            "event_class": "message",
            "nonce": "0x2222222222222222222222222222222222222222222222222222222222222222",
            "sender": "did:tsl:test:alice",
            "signing_key_id": "#test-key-1",
            "timestamp": "2026-05-25T00:01:00Z",
            "type": "tsl.event_commitment.v1"
        });
        assert_eq!(
            hash_domain("tsl.event_commitment.v1", canonicalize(&payload).as_bytes()),
            "0xcf5cb36e4596ed4c446f2d24504407369a1fc4862928e86c340ec5270fcc3267"
        );
    }

    #[test]
    fn commitment_and_merkle_match_vector() {
        let event_hash = "0xcf5cb36e4596ed4c446f2d24504407369a1fc4862928e86c340ec5270fcc3267";
        let signature = concat!(
            "0xd3187ac9861b87a3b5f871c9ae9a6426ce0c1e49cee1978c767bf99eff6c94467",
            "b6955cd9821c2a7e3bfcf945b576e49d81deccb4e7c8b0624917fd794f1ff08"
        );
        let commitment = commitment_hash(event_hash, signature);
        assert_eq!(
            commitment,
            "0x174c377613f1fa94acc95d32408095c27330f5dfa088ee40cdcb81a503b25bb5"
        );
        assert_eq!(
            merkle_root(&[commitment]),
            "0xc09632a2beaaf0c4702e673a7a1661673c80be478f1136b60677f38c5bb5914f"
        );
    }

    #[test]
    fn ed25519_vector_verifies_and_tampering_fails() {
        let public_key = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
        let event_hash = "0xcf5cb36e4596ed4c446f2d24504407369a1fc4862928e86c340ec5270fcc3267";
        let signature = concat!(
            "0xd3187ac9861b87a3b5f871c9ae9a6426ce0c1e49cee1978c767bf99eff6c94467",
            "b6955cd9821c2a7e3bfcf945b576e49d81deccb4e7c8b0624917fd794f1ff08"
        );
        assert!(verify_ed25519(public_key, event_hash, signature));
        assert!(!verify_ed25519(public_key, "0x0000000000000000000000000000000000000000000000000000000000000000", signature));
    }

    #[test]
    fn validates_latex_v2_required_fields() {
        let attestation = json!({
            "type": "tsl.attestation.v2",
            "attestation_id": "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "issuer": "did:tsl:provider:continuity-labs",
            "subject": "did:tsl:test:alice",
            "claim_class": "provider_risk_flag",
            "claim_polarity": "negative",
            "severity": "medium",
            "claim_commitment": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "evidence_commitment": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "evidence_policy": "selective_disclosure_or_auditor_review",
            "visibility": "public",
            "appeal_uri": "https://appeals.tsl.example/att/1",
            "issued_at": "2026-05-25T00:00:00Z",
            "valid_after": "2026-05-25T00:00:00Z",
            "expires_at": "2026-06-25T00:00:00Z",
            "revocation_pointer": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "signature": "0x11"
        });
        assert!(validate_schema_object(&attestation).is_ok());

        let missing_claim_class = json!({
            "type": "tsl.attestation.v2",
            "attestation_id": "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        });
        assert!(validate_schema_object(&missing_claim_class).is_err());
    }
}
