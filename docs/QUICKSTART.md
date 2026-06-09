# Quickstart

This path is for a local developer preview of Continuity Protocol. It does not produce production or mainnet readiness.

## Requirements

- Node.js 20 or newer
- npm
- Docker Desktop or Docker Engine for `npm run release:check` and `docker compose`
- Python 3.11 and the root `requirements-dev.txt` dependencies for Python parity checks

## Fresh Clone

```bash
git clone https://github.com/omar2001ramadan/contin.git
cd contin
npm ci
python3 -m pip install -r requirements-dev.txt
npm run demo
```

The demo prints a deterministic proof bundle and verifier result. The important field is:

```json
"verified": true
```

## Public Launch Gate

```bash
npm run release:check
```

This runs the local public-launch gate: TypeScript build, tests, contracts, dev ZK, production-interface ZK compile, ZK conformance, settlement conformance, spec conformance, web verifier build, Python/Rust parity, and Docker Compose config validation.

`conformance:mainnet` is not part of this gate. It is intentionally blocked until real external production evidence is approved.

## Optional Local Stack

```bash
docker compose up
```

The Compose stack starts local Postgres, Redis, Hardhat, contracts, relay, log node, resolver, verifier API, scoring provider, auditor, checkpoint submitter, and web verifier. All credentials and keys in this stack are dev-only.

## Useful Commands

```bash
npm run build
npm test
npm run conformance:spec
npm run conformance:zk-production
npm run conformance:settlement-offline
npm run contracts:compile
npm run contracts:test
```

## Known Non-Goals

- No npm publishing from the root package.
- No mainnet deployment.
- No production ZK ceremony.
- No external audit claim.
- No production use of negative attestations or trust labels.
