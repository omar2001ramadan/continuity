# Continuity Protocol

[![CI](https://github.com/omar2001ramadan/contin/actions/workflows/ci.yml/badge.svg)](https://github.com/omar2001ramadan/contin/actions/workflows/ci.yml)
[![Release candidate](https://github.com/omar2001ramadan/contin/actions/workflows/release-candidate.yml/badge.svg)](https://github.com/omar2001ramadan/contin/actions/workflows/release-candidate.yml)

Continuity Protocol is a developer-preview implementation of the Trust Signature Layer (TSL): a protocol for portable trust evidence, signed claims, Merkle-backed receipts, verifier APIs, settlement evidence, and conformance-tested protocol objects.

This repository is public-launch ready as a developer preview. It is not production-ready, not audited, and not approved for mainnet use.

![Continuity Protocol CLI demo](docs/assets/demo-screenshot.svg)

## What This Is Not

- Not a production identity, reputation, credit, legal, or safety decision system.
- Not audited security software or audited ZK infrastructure.
- Not a mainnet deployment, mainnet release, or evidence-approved production registry.
- Not an npm package launch; the root package intentionally remains private.

## 30-Second Architecture

![Continuity Protocol architecture diagram](docs/assets/architecture-30s.svg)

## What Works Today

- Canonical JSON bytes, domain-separated hashes, Ed25519 signatures, and deterministic test vectors.
- Identity, event, receipt, attestation, revocation, checkpoint, proof bundle, and verifier schema validation.
- Merkle inclusion and non-membership proofs.
- TypeScript core verifier, CLI demo, service wrappers, web verifier bundle, Python/Rust parity checks, Solidity contracts, and Hardhat local deployment.
- Production-interface ZK circuits and conformance gates for ZK and offline settlement proof behavior.

## Quickstart

Requirements: Node.js 20+, npm, Docker for the full release check, and Python 3.11 for parity checks.

```bash
git clone https://github.com/omar2001ramadan/contin.git
cd contin
npm ci
python3 -m pip install -r requirements-dev.txt
npm run demo
```

Expected demo output includes a deterministic proof bundle and:

```json
"verified": true
```

Run the public launch gate:

```bash
npm run release:check
```

Optional local service stack:

```bash
docker compose up
```

See [docs/QUICKSTART.md](docs/QUICKSTART.md) for the longer path and expected checks.

## Copy-Paste Example

The first command shows the signed event shape. The demo command creates the complete deterministic proof bundle used by the verifier.

```bash
SEED=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
npm run --silent cli -- sign-message --message "hello-tsl" --seed-hex "$SEED" > /tmp/continuity-signed-event.json
npm run --silent demo > /tmp/continuity-proof-bundle.json
npm run --silent cli -- verify-proof /tmp/continuity-proof-bundle.json
```

Expected verifier output:

```json
{
  "verified": true,
  "errors": []
}
```

## Maturity Map

| Area | Status |
| --- | --- |
| Canonicalization, signatures, commitments, Merkle proofs | Developer-preview stable |
| Core verifier, proof bundles, schema validation | Developer-preview stable |
| CLI demo, local services, web verifier | Developer-preview |
| Scoring, graph features, Sybil and drift analysis | Experimental |
| Production ZK circuits and manifests | Candidate pipeline only |
| Offline settlement proof | Implemented and vector-tested locally |
| Mainnet operation and public risk labels | Not production-ready |

## Safety Warnings

- Do not use this repository for production identity, legal trust, financial risk scoring, irreversible negative claims, or mainnet settlement.
- The project has not completed external security or ZK audit.
- `conformance:mainnet` is intentionally evidence-gated and should remain blocked until real ceremony, audit, deployment, legal, security, ops, governance, and release approvals exist.
- Docker Compose and example environment files use public dev-only Hardhat keys and local passwords.

## Documentation

- [Quickstart](docs/QUICKSTART.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Protocol overview](docs/PROTOCOL.md)
- [Protocol status](docs/PROTOCOL_STATUS.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Production warning](docs/PRODUCTION_WARNING.md)
- [Roadmap](docs/ROADMAP.md)
- [Local dev-only configuration](docs/LOCAL_DEV_ONLY.md)
- [Formal architecture/spec artifact](Core_architecture.md)

## Examples

- [Simple signed message](examples/simple-signed-message/README.md)
- [Verify proof bundle](examples/verify-proof-bundle/README.md)

## License And Contributions

Continuity Protocol is released under the [Apache-2.0 license](LICENSE).

Please read [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md), and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing or reporting sensitive issues.
