# Emergency Rollback Runbook

Owner: Release manager.
Status: required before `TSL-MAINNET`.

Trigger: production release causes critical verification, privacy, scoring, or settlement regression.

Steps:
- Freeze promotion and identify affected services.
- Restore last known good deployment and schema compatibility mode.
- Run RC0-RC4 conformance plus parity checks.
- Verify historical proof bundles still verify under declared versions.
- Publish rollback summary and follow-up remediation ticket.

Evidence: deployment IDs, conformance output, parity output, and rollback sign-off.
