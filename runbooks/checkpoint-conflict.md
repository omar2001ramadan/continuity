# Checkpoint Conflict Runbook

Owner: Protocol security lead.
Status: required before `TSL-MAINNET`.

Trigger: two checkpoint roots are observed for the same closed `(epoch_start_ms, shard)`.

Steps:
- Stop new checkpoint submissions for the affected shard.
- Export frozen commitment lists and relay signatures for both roots.
- Ask auditors to verify inclusion and consistency proofs.
- Revoke compromised relay signing key if signature misuse is suspected.
- Publish conflict finding with affected roots, relay IDs, and verifier guidance.

Evidence: conflicting checkpoints, frozen segment exports, auditor finding, key action record, and remediation decision.
