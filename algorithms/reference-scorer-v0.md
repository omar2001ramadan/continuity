# TSL Open Reference Scoring Algorithm v0

Status: RC4 executable baseline, not mainnet governance.

The implementation source of truth is the semantic test suite and `packages/core-ts/src/v2.ts`. The v0 scorer enforces hard gates before numeric scoring, computes evidence coverage in basis points, abstains on low coverage without adverse evidence, and signs `tsl.trust_assessment.v2` objects with fixed-point fields only.

