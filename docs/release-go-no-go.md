# Release Go / No-Go Checklist

## Required Local Gates

```bash
npm run build
npm test
npm run contracts:compile
npm run contracts:test
npm run zk:test
npm run zk:manifest
npm run build:web-verifier
npm run parity:python
npm run parity:rust
docker compose config
```

## Public Testnet Gate

```bash
npm run deploy:base-sepolia
npm run deploy:base-sepolia:e2e
```

## Manual Acceptance

- `npm run load-test:full-path:1m` completes with 100/100 sampled proofs verified.
- Audit gossip detects a conflicting checkpoint between two local log nodes.
- ZK artifact manifest is reviewed and dev-ceremony warning is accepted.
- NPM audit findings from Circom/snarkjs are accepted as dev-tooling risk only.
- The production-runtime `ethers -> ws` moderate advisory is explicitly reviewed, accepted for testnet, or remediated before mainnet.
- Incident response and rollback docs are current.
