# Checkpoint Delay Runbook

Owner: Relay operations.
Status: required before `TSL-MAINNET`.

Trigger: checkpoint submission exceeds two epoch durations.

Steps:
- Identify delayed `(epoch_start_ms, shard)` segments.
- Verify segment freeze state and immutable commitment list.
- Retry submission with current relay signing key.
- If settlement backend is degraded, mark checkpoint status as pending and continue local verification without claiming settlement.
- Notify auditors and publish delayed checkpoint summary.

Evidence: retry log, relay signature, checkpoint hash, settlement transaction, and auditor acknowledgment.
