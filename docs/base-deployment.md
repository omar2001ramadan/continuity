# Base Sepolia Deployment Runbook

1. Copy `.env.base-sepolia.example` to `.env.base-sepolia` and fill `TSL_BASE_SEPOLIA_PRIVATE_KEY`.
2. Run `npm run contracts:compile`.
3. Deploy with `set -a; source .env.base-sepolia; set +a; npm run deploy:base-sepolia`.
4. Copy addresses from `deployments/base-sepolia.json` into service env.
5. Start services with `TSL_SETTLEMENT_BACKEND=eip155:84532` and a public Base Sepolia RPC URL.
6. Submit a checkpoint and verify with `require_settlement: true`.
7. Run `npm run deploy:base-sepolia:e2e` to submit a sample checkpoint and verify it over public RPC.

The contracts remain token-free. Verification must not depend on balances, subscriptions, staking tiers, or fee state.

Base mainnet is intentionally not a runnable default. Promote only after local, Docker, and Base Sepolia release checks pass.
