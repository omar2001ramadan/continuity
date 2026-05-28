# Relay Outage Runbook

Owner: Operations lead.
Status: required before `TSL-MAINNET`.

Trigger: relay intake or proof retrieval availability falls below SLO.

Steps:
- Confirm blast radius from health checks, queue lag, database errors, and relay logs.
- Pause non-critical intake if queue pressure threatens checkpoint integrity.
- Route clients to healthy relays or read-only proof retrieval when available.
- Publish status update with affected shards, start time, and expected recovery window.
- After recovery, verify no closed epoch accepted late writes and run checkpoint consistency checks.

Evidence: incident ticket, metrics screenshot, consistency check output, and post-incident review.
