# Audit Prep Package

Release-candidate audit inputs:

- LaTeX/core architecture spec,
- JSON schemas and deterministic vectors,
- TypeScript, Rust, and Python parity test outputs,
- contract tests and deployment artifacts,
- threat-model matrix,
- service data-flow diagram,
- load-test report,
- Base Sepolia deployment report,
- known limitations list.

Known current limitations:

- Groth16 threshold circuits exist for identity age and reciprocal receipt count, but the local setup is development-only until an external ceremony is selected.
- Production key custody adapters for `kms:` and `hsm:` fail closed until vendor-specific implementations are configured.
- The 1M full-path load test is a manual acceptance run and is not part of the default release check.
- Mainnet deployment is documented as a dry run only; Base Sepolia remains the public release-candidate target.
