# Provider Key Compromise Runbook

Owner: Provider security lead.
Status: required before `TSL-MAINNET`.

Trigger: scoring-provider signing key is suspected or confirmed compromised.

Steps:
- Stop issuing new assessments.
- Revoke provider key and publish affected model/profile IDs.
- Mark recent assessments for warning or reissue according to policy.
- Rotate provider signing key through ceremony.
- Re-run high-impact assessments after model/profile verification.

Evidence: provider revocation record, affected assessment set, replacement key record, and reissue report.
