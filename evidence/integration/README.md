# Integration Evidence

Smoke scripts write release evidence JSON here. Generated evidence is not mainnet approval by itself; it must be reviewed and linked from `conformance/production-readiness-evidence.json`.

Railway Postgres may be used as a reference-backend test database for relay/resolver/log/scoring persistence. It is not protocol infrastructure and does not change the decentralized protocol model.

Run the Railway-backed smokes without printing credentials:

```sh
railway run sh -lc 'TSL_TEST_DATABASE_URL="${DATABASE_PUBLIC_URL:-$DATABASE_URL}" npm run integration:postgres'
railway run sh -lc 'TSL_TEST_DATABASE_URL="${DATABASE_PUBLIC_URL:-$DATABASE_URL}" TSL_CHECKPOINT_REGISTRY_ADDRESS= TSL_TRUST_ID_REGISTRY_ADDRESS= TSL_REVOCATION_REGISTRY_ADDRESS= TSL_PROVIDER_REGISTRY_ADDRESS= npm run integration:hosted-service'
```

`npm run conformance:mainnet` is expected to fail until production-readiness evidence is reviewed and approved by the required owners.
