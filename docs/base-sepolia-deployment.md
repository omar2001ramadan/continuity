# Base Sepolia Deployment

Base Sepolia is the only public-chain target for the current release-candidate milestone.

## Required Environment

```bash
BASE_SEPOLIA_RPC_URL=https://...
TSL_BASE_SEPOLIA_PRIVATE_KEY=0x...
TSL_RELAY_ID=did:tsl:relay:base-sepolia
```

## Deploy

```bash
npm run deploy:base-sepolia
```

Expected artifact:

```text
deployments/base-sepolia.json
```

## Verify Settlement

```bash
npm run deploy:base-sepolia:e2e
```

Expected report:

```text
reports/base-sepolia-e2e-report.json
```

The E2E script submits a checkpoint to `CheckpointRegistry`, then verifies the proof with `require_settlement: true` over public RPC.

## Go / No-Go

- Contracts deployed and artifact addresses recorded.
- Checkpoint submit transaction mined.
- Verifier returns `verified: true`.
- Settlement status is `settled`.
- No token balance, staking tier, fee module, or subscription state is checked by the verifier.
