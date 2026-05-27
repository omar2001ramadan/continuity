# Key Custody

TSL services sign relay checkpoints, provider assessments, auditor findings, and deployment artifacts through a `SigningAdapter`.

## Adapter URIs

```text
env:TSL_AUDITOR_SEED_HEX
file:/secure/dev-only/seed.hex
kms:aws-kms:key-id
hsm:key-id
```

`env:` and `file:` are development-only adapters. They read raw Ed25519 seed material and should not be used in production.

`kms:` and `hsm:` are fail-closed production boundaries. They intentionally throw `TSL_SIGNING_ADAPTER_UNAVAILABLE` until a vendor-specific implementation is configured.

## Service Variables

```text
TSL_AUDITOR_PRIVATE_KEY_URI=env:TSL_AUDITOR_SEED_HEX
TSL_RELAY_PRIVATE_KEY_URI=env:TSL_RELAY_SEED_HEX
TSL_PROVIDER_PRIVATE_KEY_URI=env:TSL_PROVIDER_SEED_HEX
```

Prefer URI variables over direct seed variables. Direct seed variables remain only for backward-compatible local development.
