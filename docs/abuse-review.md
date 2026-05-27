# Abuse Review Workflow

Negative or high-impact trust labels require:

- signed issuer identity,
- evidence commitment,
- expiration,
- appeal pointer or policy pointer,
- issuer rate limit,
- review state for public high-impact labels.

Default states are `private_warning`, `provider_risk_flag`, and `public_negative_claim`. Production clients should display warnings as probabilistic risk, not final accusation.
