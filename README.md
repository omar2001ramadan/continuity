# Trust Signature Layer Reference MVP

This workspace contains an executable MVP slice of the Trust Signature Layer (TSL) specification in `Core_architecture.md`.

It implements:

- canonical deterministic JSON serialization,
- domain-separated SHA-256 commitments,
- Ed25519 identity keys, event signing, and verification,
- v1 JSON schemas with unknown-field rejection,
- event commitment hashing and salted content commitments,
- append-only Merkle trees with inclusion proofs,
- token-free local EVM checkpoint settlement contracts,
- RPC-backed checkpoint settlement verification,
- Postgres-backed canonical object persistence and Merkle checkpoint building,
- Redis Stream topic publishing for accepted protocol objects,
- receipt, attestation, revocation, rotation, and signed trust assessment object flows,
- a pure verifier that does not trust hosted APIs,
- a CLI for deterministic demos and file verification,
- split local reference services and a bundled proof-link web verifier.

## Quick Start

```bash
npm install
npm test
npm run contracts:test
npm run demo
```

Compile contracts:

```bash
npm run contracts:compile
```

Run the relay prototype:

```bash
npm run relay
```

Run the split local services:

```bash
npm run log
npm run resolver
npm run verifier
npm run scoring-provider
npm run auditor
npm run checkpoint-submitter
npm run web-verifier
```

Run the hosted verifier wrapper:

```bash
npm run verifier
```

## CLI

Generate the deterministic compliance vector:

```bash
npm run cli -- vector
```

Sign a message:

```bash
npm run cli -- sign-message --message "hello-tsl" --seed-hex 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

Verify a JSON bundle:

```bash
npm run cli -- verify-file ./proof.json
```

Service-backed protocol commands:

```bash
npm run cli -- create-identity --relay http://localhost:8080 --public-key 0x...
npm run cli -- submit-event --relay http://localhost:8080 --file ./event.json
npm run cli -- submit-receipt --relay http://localhost:8080 --file ./receipt.json
npm run cli -- submit-attestation --relay http://localhost:8080 --file ./attestation.json
npm run cli -- revoke-key --relay http://localhost:8080 --file ./revocation.json
npm run cli -- close-epoch --log http://localhost:8081 --epoch <epochStartMs> --shard <shard>
npm run cli -- fetch-proof --relay http://localhost:8080 --commitment 0x...
npm run cli -- verify-proof --verifier http://localhost:8083 --file ./proof-bundle.json
```

Create and inspect a portable proof link:

```bash
npm run cli -- proof-link:create --message "hello-tsl" --seed-hex 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
npm run cli -- proof-link:inspect <proof-link>
```

## Durable Local Stack

The local reference stack has Postgres migrations in `infra/db/migrations`, Redis Stream queue topics, split service entrypoints, and `docker-compose.yml` for the MVP topology.

```bash
docker compose up
```

The compose stack starts Postgres on host port `15432`, Redis, a local Hardhat chain, a local contract deployer, relay/log/resolver/verifier services, checkpoint submitter, scoring provider, auditor, and `web-verifier` on port `8090`.

Run the 1M synthetic event/log/proof scale target against compose Postgres:

```bash
docker compose up -d postgres
TSL_DATABASE_URL=postgres://tsl:tsl_dev_only@127.0.0.1:15432/tsl \
TSL_LOAD_TEST_COUNT=1000000 \
npm run load-test:events
```

## Local Blockchain Settlement

Start a local Hardhat chain:

```bash
npm run chain
```

In another terminal, deploy the token-free registries:

```bash
npm run contracts:deploy:local
```

The deployment writes `deployments/local.json`. Use its `checkpointRegistry` address to run a settlement demo:

```bash
npm run cli -- demo-settlement --registry-address <checkpointRegistry>
```

For relay/verifier services with settlement enabled, set:

```bash
export TSL_SETTLEMENT_RPC_URL=http://127.0.0.1:8545
export TSL_CHECKPOINT_REGISTRY_ADDRESS=<checkpointRegistry>
export TSL_TRUST_ID_REGISTRY_ADDRESS=<trustIDRegistry>
export TSL_REVOCATION_REGISTRY_ADDRESS=<revocationRegistry>
export TSL_PROVIDER_REGISTRY_ADDRESS=<providerRegistry>
```

When `require_settlement` is true, verification now requires the checkpoint to exist in the configured `CheckpointRegistry` with matching roots and counts.
Checkpoint submission also requires an authorized EVM relay signature over the checkpoint hash for the declared `relay_id`.

## Scope

This is not a monolithic application. It is a protocol-first reference implementation: the hosted HTTP services are wrappers around the same pure library used by the CLI and tests.
