# NPM Audit Risk

Last checked with full development dependencies:

```bash
npm audit --omit=optional
```

Current result: 27 vulnerabilities from development tooling dependency chains.

Last checked with production dependencies only:

```bash
npm audit --omit=dev
```

Current production-runtime result: 2 moderate vulnerabilities through `ethers -> ws`.
The advisory is `ws: Uninitialized memory disclosure` and npm's automatic fix
would force a breaking downgrade to `ethers@5.8.0`, so it is not applied
automatically in this release candidate.

## Accepted For This Release Candidate

The findings are accepted only as local development/tooling risk for this milestone. The affected dependency chains are primarily:

- Hardhat / contract tooling: `hardhat`, `@nomicfoundation/hardhat-ethers`, `solc`, `mocha`, `undici`, `ethers` transitive packages.
- Circom/snark tooling: `circom`, `circom_tester`, `mocha`, `diff`, `js-yaml`, `minimatch`, `nanoid`, `serialize-javascript`, `tmp`.

These packages must not be part of the production verifier runtime path. Production services should run compiled application code without Circom setup tooling or Hardhat development dependencies installed.

The remaining production-runtime `ethers -> ws` advisory must be reviewed before
mainnet. The current runtime uses `ethers` for settlement RPC adapters; the
release candidate accepts this as a tracked dependency risk, not as a cryptographic
protocol exception.

## Production Requirement

Before mainnet or production deployment:

- Split dev-only circuit/contract tooling from runtime images.
- Re-run audit on production image dependencies only.
- Replace local dev Groth16 ceremony artifacts with externally governed setup artifacts.
- Review or replace the `ethers` / `ws` runtime dependency before mainnet.
