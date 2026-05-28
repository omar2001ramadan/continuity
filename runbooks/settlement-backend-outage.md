# Settlement Backend Outage Runbook

Status: draft
Owner: protocol-ops

Detection signals: checkpoint submission delay, failed settlement adapter calls, finality lag, or chain RPC disagreement.

Immediate response: pause settled-status promotion, keep accepting log commitments with pending status, route reads to latest verified checkpoint, and publish outage status.

Recovery evidence required for approval: delayed-checkpoint list, adapter logs, settlement reconciliation report, and operator sign-off.
