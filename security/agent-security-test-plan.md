# Agent Security Test Plan

Status: mainnet-gated checklist.

Tests must cover delegation scope bypass, parameter commitment mismatch, tool denial, value limits, revocation, replay, and human approval thresholds.

Required evidence:
- Owner: Security lead.
- Status: required before `TSL-MAINNET`.
- Evidence links: delegation vectors, `/v1/verify` integration logs, sidecar verification logs, and release checklist entry.
- Blocking criteria: any unsigned action acceptance, scope bypass, stale revocation acceptance, or missing canonical error code blocks promotion.
