# Relay Key Compromise Runbook

Owner: Protocol security lead.
Status: required before `TSL-MAINNET`.

Trigger: relay checkpoint signing key is suspected or confirmed compromised.

Steps:
- Pause relay checkpoint signing.
- Register emergency revocation through governance or registry path.
- Rotate to a ceremony-created replacement key.
- Re-sign only future checkpoints; do not rewrite historical checkpoints.
- Publish affected key ID, revocation time, and verifier policy update.

Evidence: revocation transaction, ceremony record, new key registration, and verifier regression output.
