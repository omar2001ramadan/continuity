# Implementation Notes

The current MVP intentionally implements the protocol substrate first:

- `packages/core-ts` is the canonical library for serialization, hashing, signing, Merkle proofs, identity resolution, and verification.
- `clients/cli` is a local proof generator/verifier.
- `services/relay-node` accepts event, receipt, attestation, revocation, rotation, and assessment submissions, then persists canonical bytes to Postgres when `TSL_DATABASE_URL` is configured.
- `services/log-node` consumes Redis Streams, dead-letters failed queue messages, exposes queue metrics, closes Postgres-backed epochs, assigns log indexes, persists Merkle nodes, links `previous_checkpoint`, and exposes proof lookup for event, receipt, attestation, and revocation trees.
- `services/checkpoint-submitter` submits pending checkpoints to the configured local EVM `CheckpointRegistry`.
- `services/resolver-node`, `services/verifier-api`, `services/scoring-provider`, and `services/auditor-node` are split service wrappers around the same protocol library.
- `contracts/src` contains token-free local EVM registry contracts for checkpoint settlement and minimal identity/provider/revocation facts.
- `packages/verifier-ts` exposes a verifier-facing package split for browser and Node clients.
- `packages/core-python` and `packages/core-rust` contain parity packages for canonicalization, domain hashing, commitment hashing, Merkle roots, and deterministic vectors.
- `packages/client-sdk-ts` exposes proof-link helpers plus encrypted local-store adapters for Node SQLite and browser IndexedDB contexts.
- `clients/browser-extension` detects proof links/envelope signals, opens the verifier UI, and warns before message disclosure.
- `clients/agent-sidecar` enforces scoped delegation before signing agent actions. `packages/agent-sdk-python` remains a first agent integration surface.
- `packages/core-ts` has optional verifier policy gates for threshold proof objects, agent delegations, and signed audit findings.
- `circuits/identity_age_threshold.circom` is the first real Groth16 threshold circuit for `identity_age_days >= threshold`; the witness age remains private.

The implementation follows the deterministic event vector in the spec:

- Ed25519 seed: `000102...1f`
- public key: `03a107...31b8`
- event hash: `0xcf5c...3267`
- signature: `0xd318...ff08`
- commitment hash: `0x174c...5bb5`
- single-leaf Merkle root: `0xc096...914f`

## Remaining Reference Constraints

- The TypeScript stack remains the canonical reference implementation. Python and Rust parity currently cover deterministic canonicalization, hashing, commitment, and Merkle vectors. Rust tests run with local `cargo` when present and fall back to Docker otherwise.
- Settlement is real for a local Hardhat chain when `TSL_CHECKPOINT_REGISTRY_ADDRESS` is configured. Base Sepolia deployment scripts and env templates exist, but they have not been exercised against a public RPC in this workspace.
- Registry-backed verification exists for local EVM identity, revocation, and provider registries when the relevant contract addresses are configured. The offline bundle path still depends on the bundle carrying enough registry state.
- Scoring has a reference feature extractor, weighted provider, Sybil/anomaly heuristics, and signed assessment object. Advanced ML graph models are not implemented.
- `web-verifier` bundles the verifier into the browser and performs local proof-bundle verification, with optional RPC-backed checkpoint settlement checks.
- The local client store exposes encrypted Node SQLite and browser IndexedDB adapters. The Node adapter uses `node:sqlite`, so runtime support depends on the installed Node version.
- The MVP checkpoint contract authorizes by EVM submitter address, authorized protocol `relay_id`, and an EVM-native relay signer signature over the checkpoint hash. It does not attempt Ed25519 verification on-chain.
- `load-test:events` has been exercised with 1,000,000 synthetic event commitments, 1,000,000 Postgres rows, and 100/100 sampled Merkle proof verifications.
- `load-test:full-path` drives relay HTTP intake, Redis Streams, log-node consume, Postgres, checkpoint close, proof fetch, and sampled verification. It has been smoke-tested locally at 25 commitments with 5/5 sampled proof verifications.
- The threshold proof module supports both legacy deterministic local proofs and Groth16 proofs generated from the Circom circuit. The local setup ceremony is development-only and not production trusted setup.
