# Schema Migration Failure Runbook

Owner: Release manager.
Status: required before `TSL-MAINNET`.

Trigger: schema migration fails validation, breaks canonical hashes, or changes signed semantics unexpectedly.

Steps:
- Halt release promotion.
- Identify affected object types and version discriminators.
- Run traceability and test-vector conformance for old and new versions.
- Roll back new issuance if historical verification remains valid.
- Publish migration advisory with explicit verifier behavior.

Evidence: failed migration logs, conformance output, rollback decision, and advisory.
