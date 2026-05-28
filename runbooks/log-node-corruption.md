# Log Node Corruption Runbook

Status: draft
Owner: protocol-ops

Detection signals: checkpoint root mismatch, auditor consistency finding, storage checksum mismatch, or replay divergence.

Immediate response: remove the affected node from serving proof traffic, preserve disk snapshots and process logs, promote a healthy replica, and publish an auditor notice if any public checkpoint may be affected.

Recovery evidence required for approval: replay transcript, root comparison, operator sign-off, auditor sign-off, and incident timeline.
