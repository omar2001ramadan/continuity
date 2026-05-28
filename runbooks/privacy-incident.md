# Privacy Incident Runbook

Owner: Privacy/security lead.
Status: required before `TSL-MAINNET`.

Trigger: raw content, salts, exact counterparties, private metadata, or local context are exposed without valid disclosure consent.

Steps:
- Stop the export or provider-upload path.
- Identify affected proof bundles, users, providers, and field classes.
- Revoke future disclosures where possible and notify impacted parties according to policy.
- Patch allowlist transform and add regression vector.
- Review retention and deletion obligations.

Evidence: incident ticket, affected field inventory, regression test, notification record, and closure review.
