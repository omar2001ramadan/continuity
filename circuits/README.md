# TSL ZK Circuits

`identity_age_threshold.circom` proves `identity_age_days >= threshold` without exposing the exact age.

The circuit public inputs are:

- `threshold`
- `subject_hash`

The private witness is:

- `identity_age_days`

The TypeScript wrapper stores the Groth16 proof and verification key in `zk_proofs[].groth16` while keeping the existing `tsl.zk.threshold_proof.v1` object compatible.
