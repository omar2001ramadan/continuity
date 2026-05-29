#!/usr/bin/env python3
import json
import pathlib
import sys
from jsonschema import Draft202012Validator, FormatChecker

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "core-python"))

from tsl_core import (  # noqa: E402
    canonicalize,
    commitment_hash,
    hash_domain,
    legacy_commitment_hash,
    merkle_root,
    verify_ed25519,
)


def assert_equal(actual, expected, message):
    if actual != expected:
        raise AssertionError(f"{message}: expected {expected}, got {actual}")


def assert_raises(fn, message):
    try:
        fn()
    except Exception:
        return
    raise AssertionError(message)


def check_schema_pair(schema_name, example_name):
    schema = json.loads((ROOT / "specs" / "json-schema" / schema_name).read_text())
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    valid_example = json.loads((ROOT / "specs" / "examples" / "valid" / example_name).read_text())
    errors = sorted(validator.iter_errors(valid_example), key=lambda err: list(err.path))
    if errors:
        raise AssertionError(f"{example_name} failed Python validator parity: {errors[0].message}")

    invalid_dir = ROOT / "specs" / "examples" / "invalid" / example_name.replace(".json", "")
    if invalid_dir.exists():
        invalid_files = sorted(invalid_dir.glob("*.json"))
        if not invalid_files:
            raise AssertionError(f"{invalid_dir} has no invalid examples")
        for invalid_file in invalid_files:
            invalid_example = json.loads(invalid_file.read_text())
            if not list(validator.iter_errors(invalid_example)):
                raise AssertionError(f"{invalid_file} unexpectedly passed Python validator parity")


def check_schema_value(schema_name, value):
    schema = json.loads((ROOT / "specs" / "json-schema" / schema_name).read_text())
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(value), key=lambda err: list(err.path))
    if errors:
        raise AssertionError(f"{schema_name} failed Python validator parity: {errors[0].message}")


def main():
    vectors = json.loads((ROOT / "specs" / "test-vectors" / "shared-core-vectors.json").read_text())
    event = vectors["event"]

    assert_equal(canonicalize({"b": 2, "a": 1}), '{"a":1,"b":2}', "canonical object ordering mismatch")
    assert_raises(lambda: canonicalize({"invalid_float": 0.5}), "canonicalization must reject floats")
    assert_raises(lambda: canonicalize({"unsafe": 2**53}), "canonicalization must reject unsafe integers")

    assert_equal(
        commitment_hash(event["event_hash_hex"], event["signature_hex"]),
        event["commitment_hash_hex"],
        "canonical commitment hash mismatch",
    )
    assert_equal(
        legacy_commitment_hash(event["event_hash_hex"], event["signature_hex"]),
        event["legacy_commitment_hash_hex"],
        "legacy commitment hash mismatch",
    )
    assert_equal(
        merkle_root([event["commitment_hash_hex"]]),
        event["single_leaf_merkle_root_hex"],
        "canonical merkle root mismatch",
    )
    assert_equal(
        merkle_root([event["legacy_commitment_hash_hex"]]),
        event["legacy_single_leaf_merkle_root_hex"],
        "legacy merkle root mismatch",
    )
    assert verify_ed25519(event["public_key_hex"], event["event_hash_hex"], event["signature_hex"]), "ed25519 vector failed"
    assert not verify_ed25519(event["public_key_hex"], vectors["failure_cases"]["tampered_event_hash_hex"], event["signature_hex"]), "tampered ed25519 vector passed"

    proof_bundle = json.loads((ROOT / "specs" / "test-vectors" / "proof_bundle.v1" / "valid-offline-bundle" / "input.json").read_text())
    redaction = proof_bundle["redaction_manifest"]
    assert redaction["raw_content_included"] is False, "proof bundle vector must default to redacted raw content"
    assert redaction["exact_counterparties_included"] is False, "proof bundle vector must default to redacted counterparties"
    assert "raw_content" in redaction["metadata_fields_redacted"], "proof bundle vector must declare raw content redaction"

    release_critical_schemas = [
        ("disclosure_consent.v1.schema.json", "disclosure_consent.v1.json"),
        ("graph_profile.v2.schema.json", "graph_profile.v2.json"),
        ("graph_feature_vector.v1.schema.json", "graph_feature_vector.v1.json"),
        ("sybil_assessment.v1.schema.json", "sybil_assessment.v1.json"),
        ("drift_report.v1.schema.json", "drift_report.v1.json"),
        ("trust_assessment.v2.schema.json", "trust_assessment.v2.json"),
    ]
    for schema_name, example_name in release_critical_schemas:
        check_schema_pair(schema_name, example_name)

    hex32 = "0x" + "11" * 32
    check_schema_value("zk_circuit_release_manifest.v1.schema.json", {
        "type": "tsl.zk.circuit_release_manifest.v1",
        "circuit_id": "tsl.identity_age_days.production_interface.v1",
        "claim": "identity_age_days",
        "version": "1.0.0",
        "hash_suite": "poseidon-bn254-v1",
        "witness_interface": "identity_age_days.production_witness.v1",
        "circuit_hash": hex32,
        "r1cs_hash": hex32,
        "wasm_hash": hex32,
        "zkey_hash": hex32,
        "verification_key_id": "identity-age-vkey-v1",
        "verification_key_hash": hex32,
        "ceremony_transcript_hash": hex32,
        "public_signal_schema": {"required": ["subject_hash", "threshold", "registry_root"]},
        "private_witness_schema": {"required": ["creation_proof", "salt", "registry_path"], "properties": {"creation_proof": {}, "salt": {}, "registry_path": {}}},
        "soundness_bits": 128,
        "privacy_notes": ["dev-only parity manifest"],
        "auditor": "did:tsl:auditor:test",
        "reviewer": "did:tsl:reviewer:test",
        "status": "active",
        "issued_at": "2026-05-27T12:00:00Z",
        "signature": "0x" + "22" * 64,
    })
    check_schema_value("zk_verification_key_registry.v1.schema.json", {
        "type": "tsl.zk.verification_key_registry.v1",
        "registry_id": "registry",
        "active_manifest_hashes": [hex32],
        "revoked_manifest_hashes": [],
        "issued_at": "2026-05-27T12:00:00Z",
        "signature": "0x" + "33" * 64,
    })
    for schema_name, value in [
        ("feature_registry.v1.schema.json", {"type": "tsl.feature_registry.v1", "registry_id": "features", "feature_ids": ["a"], "feature_definitions": [{"feature_id": "a", "value_type": "bps", "privacy_class": "aggregate", "source": "verified_event"}], "issued_at": "2026-05-27T12:00:00Z"}),
        ("normalization_profile.v1.schema.json", {"type": "tsl.normalization_profile.v1", "profile_id": "norm", "feature_ranges_bps": {"a": {"min_bps": 0, "max_bps": 10000, "missing_bps": 0}}, "feature_methods": {"a": "bounded"}, "missing_value_policy": "impute_zero_with_coverage_penalty", "time_split_fit_status": "train_validation_test_split", "issued_at": "2026-05-27T12:00:00Z"}),
        ("weight_profile.v1.schema.json", {"type": "tsl.weight_profile.v1", "profile_id": "weights", "weights_bps": {"a": 10000}, "issued_at": "2026-05-27T12:00:00Z"}),
        ("calibration_profile.v1.schema.json", {"type": "tsl.calibration_profile.v1", "profile_id": "cal", "points": [{"raw_bps": 0, "calibrated_bps": 0}, {"raw_bps": 10000, "calibrated_bps": 10000}], "issued_at": "2026-05-27T12:00:00Z"}),
        ("confidence_profile.v1.schema.json", {"type": "tsl.confidence_profile.v1", "profile_id": "conf", "method": "deterministic_bootstrap_v1", "bootstrap_unit": "edge_counterparty_attestation", "min_width_bps": 100, "max_width_bps": 1000, "coverage_weight_bps": 500, "issued_at": "2026-05-27T12:00:00Z"}),
        ("provider_governance_status.v1.schema.json", {"type": "tsl.provider_governance_status.v1", "provider": "did:tsl:provider:test", "status": "active", "model_registered": True, "evaluation_report_commitment": hex32, "red_team_result": "pass", "privacy_leakage_bps": 100, "promotion_gate_result": "pass", "issued_at": "2026-05-27T12:00:00Z"}),
        ("sybil_simulation_profile.v1.schema.json", {"type": "tsl.sybil_simulation_profile.v1", "profile_id": "sim", "issuer": "did:tsl:provider:test", "graph_profile_id": "graph", "scenarios": [{"scenario_id": "b0", "adversary_tier": "B0", "subject": "did:tsl:a", "attack_scenario": "dense_farm", "expected_benefit_minor_units": 100, "evidence_commitment": hex32}], "issued_at": "2026-05-27T12:00:00Z"}),
    ]:
        check_schema_value(schema_name, value)

    print(json.dumps({"parity": "python", "ok": True}, indent=2))


if __name__ == "__main__":
    main()
