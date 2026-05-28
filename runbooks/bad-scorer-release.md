# Bad Scorer Release Runbook

Owner: Scoring provider lead.
Status: required before `TSL-MAINNET`.

Trigger: scorer release produces miscalibrated, unsafe, privacy-leaking, or policy-violating assessments.

Steps:
- Move scorer status to probation or rejected.
- Stop default issuance for affected profile IDs.
- Roll back to previous recommended profile.
- Recompute or expire affected high-impact assessments.
- Publish model-card and evaluation-report correction.

Evidence: release ID, failed gate, rollback record, affected assessments, and correction notice.
