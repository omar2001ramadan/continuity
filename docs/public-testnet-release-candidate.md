# Public Testnet Release Candidate

This milestone moves the local TSL reference stack toward a Base Sepolia release candidate while keeping the protocol token-free and verifiable without trusting a hosted API.

## Base Sepolia Flow

Required environment:

```bash
BASE_SEPOLIA_RPC_URL=https://...
TSL_BASE_SEPOLIA_PRIVATE_KEY=0x...
TSL_RELAY_ID=did:tsl:relay:base-sepolia
```

Commands:

```bash
npm run deploy:base-sepolia
npm run deploy:base-sepolia:e2e
```

The deployment command writes `deployments/base-sepolia.json`. The E2E command submits a checkpoint through the public RPC and writes `reports/base-sepolia-e2e-report.json` with chain ID, checkpoint registry address, relay ID, settlement transaction hash, checkpoint hash, and verifier result.

## ZK Artifact Reproducibility

Two Groth16 circuits are included for the LaTeX selective-disclosure roadmap:

- `identity_age_days >= threshold`
- `reciprocal_receipt_count >= threshold`

Commands:

```bash
npm run zk:setup
npm run zk:test
npm run zk:manifest
```

`npm run zk:manifest` writes `docs/zk-artifact-manifest.json` with hashes for circuit source, R1CS, WASM, zkey, and verification-key artifacts.

The current Groth16 setup is development-only. The zkeys are produced by local `snarkjs` contributions and must be replaced by an externally governed setup before production use.

## Audit and Gossip

Audit findings and gossip peers are persisted in Postgres when `TSL_DATABASE_URL` is configured. Nodes expose:

- `POST /v1/gossip/checkpoint-summary`
- `POST /v1/gossip/sync`
- `GET /v1/audit/findings`
- existing checkpoint and audit-finding gossip endpoints

Verifier policy `require_audit_consistency` now requires accepted auditor identity, valid auditor signature, checkpoint-hash binding, and no critical finding.

## Key Custody

Signing adapters are addressed by URI:

- `env:VAR_NAME`
- `file:/path/to/seed.hex`
- `kms:provider:key-id`
- `hsm:key-id`

`env:` and `file:` are development adapters. `kms:` and `hsm:` fail closed until a production implementation is installed.

## Release Check

```bash
npm run release:rc
```

This runs the local release checks plus ZK manifest generation and a small full-path load smoke by default. Set `TSL_RELEASE_RC_RUN_FULL_PATH_SMOKE=0` to skip the smoke when Postgres/Redis services are not running.

## Known Limitations

- Base Sepolia deployment requires external RPC and funded key material.
- ZK setup is development-only.
- KMS/HSM adapters are interface-complete but intentionally non-operational.
- The 1M full-path load test remains manual: `npm run load-test:full-path:1m`.
- Advanced ML graph scoring and full production abuse-review workflows remain outside this milestone.
