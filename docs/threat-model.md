# TSL Threat Model

Primary threats covered by the local reference stack:

- forged signatures,
- replayed event nonces,
- revoked key usage,
- checkpoint root conflicts,
- missing settlement when settlement is required,
- tampered inclusion proofs,
- trust assessment provider/model mismatch when registry validation is required.

Remaining production hardening:

- distributed equivocation monitoring,
- adversarial graph/model poisoning defenses,
- production key custody and HSM/KMS signing,
- privacy review for proof bundle disclosure.

