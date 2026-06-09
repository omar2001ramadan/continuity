import "../../../scripts/load-env.cjs";
import express from "express";
import { rateLimit } from "express-rate-limit";
import {
  createPostgresRepositoryFromEnv,
  createQueueFromEnv,
  receiptCommitmentHash,
  validateCheckpointImport,
  type AttestationV1,
  QUEUE_TOPICS,
  type QueueTopic,
  type EventCommitmentV1,
  type BatchCheckpointV1,
  type IdentityDocumentV1,
  type ReceiptCommitmentV1,
  type RevocationV1
} from "../../../packages/core-ts/src/index";
import { buildGossipUrl, GossipPeerError, initialGossipPeers, registerRequestedGossipPeer, selectKnownGossipPeers } from "../../shared/gossip-peers";

export function createLogNode() {
  const repo = createPostgresRepositoryFromEnv();
  const queue = createQueueFromEnv();
  const lastStreamIds = new Map<string, string>();
  const peers = initialGossipPeers();
  let migrated = false;
  async function requireRepo() {
    if (!repo) throw new Error("TSL_DATABASE_URL or DATABASE_URL is required");
    if (!migrated) {
      await repo.migrate();
      for (const peer of peers) await repo.upsertGossipPeer(peer);
      migrated = true;
    }
    return repo;
  }

  async function listPeers(): Promise<string[]> {
    return repo ? (await requireRepo()).listGossipPeers() : [...peers];
  }

  function authorizedRelays(): string[] | undefined {
    const relays = (process.env.TSL_AUTHORIZED_RELAYS ?? "").split(",").map((relay) => relay.trim()).filter(Boolean);
    return relays.length ? relays : undefined;
  }

  async function validateAndInsertCheckpoint(db: Awaited<ReturnType<typeof requireRepo>>, checkpoint: BatchCheckpointV1, body: Record<string, unknown>): Promise<string> {
    const identities = [
      body.identity,
      body.relay_identity,
      ...(Array.isArray(body.identities) ? body.identities : [])
    ].filter(Boolean) as IdentityDocumentV1[];
    const identityMap = new Map(identities.map((identity) => [identity.id, identity]));
    const existing = await db.getCheckpoint(checkpoint.epoch_start_ms, checkpoint.shard);
    const previous = await db.getLatestCheckpointBefore(checkpoint.epoch_start_ms, checkpoint.shard);
    const validation = await validateCheckpointImport({
      checkpoint,
      existing_checkpoint: existing,
      previous_checkpoint: previous,
      authorized_relays: authorizedRelays(),
      require_authorized_relay: process.env.TSL_REQUIRE_AUTHORIZED_RELAY === "true",
      require_settlement_evidence_for_settled: true,
      settlement_evidence: (body.settlement_evidence ?? body.settlement_evidences) as never,
      resolver: {
        resolveTrustID: async (trustId: string, atTime?: string) => identityMap.get(trustId) ?? db.getIdentity(trustId)
      },
      at_time: new Date(checkpoint.epoch_start_ms).toISOString()
    });
    if (!validation.ok) {
      throw new Error(`${validation.error_code ?? "TSL_CHECKPOINT_IMPORT_INVALID"}:${validation.errors.join(",")}`);
    }
    await db.insertCheckpoint(checkpoint, checkpoint.settlement_tx ? "settled" : "pending");
    return validation.checkpoint_hash!;
  }

  const app = express();
  app.use(express.json({ limit: "1mb" }));
  app.use(rateLimit({
    windowMs: Number(process.env.TSL_HTTP_RATE_LIMIT_WINDOW_MS ?? 60_000),
    limit: Number(process.env.TSL_HTTP_RATE_LIMIT_MAX ?? 1000),
    standardHeaders: true,
    legacyHeaders: false
  }));

  app.get("/health", (_req, res) => res.json({ ok: true, service: "tsl-log-node" }));

  async function consumeQueueOnce(limit = 100): Promise<Record<string, number>> {
    if (!queue) return {};
    const db = await requireRepo();
    const counts: Record<string, number> = {};
    const topics: QueueTopic[] = [
      QUEUE_TOPICS.commitmentsAccepted,
      QUEUE_TOPICS.receiptsAccepted,
      QUEUE_TOPICS.attestationsAccepted,
      QUEUE_TOPICS.revocationsAccepted
    ];
    for (const topic of topics) {
      const messages = await queue.read(topic, lastStreamIds.get(topic) ?? "0", limit, 50);
      counts[topic] = messages.length;
      for (const message of messages) {
        try {
          lastStreamIds.set(topic, message.id);
          if (topic === QUEUE_TOPICS.commitmentsAccepted && message.values.event) {
            const event = JSON.parse(message.values.event) as EventCommitmentV1;
            await db.insertEvent(
              event,
              message.values.relay_id ?? process.env.TSL_RELAY_ID ?? "did:tsl:relay:dev",
              Number(message.values.epoch_start_ms),
              Number(message.values.epoch_duration_ms ?? process.env.TSL_EPOCH_MS ?? 300000)
            );
          }
          if (topic === QUEUE_TOPICS.receiptsAccepted && message.values.receipt) {
            const receipt = JSON.parse(message.values.receipt) as ReceiptCommitmentV1;
            const epochStartMs = Math.floor(Date.parse(receipt.timestamp) / Number(process.env.TSL_EPOCH_MS ?? 300000)) * Number(process.env.TSL_EPOCH_MS ?? 300000);
            await db.insertReceipt(receipt, receiptCommitmentHash(receipt), process.env.TSL_RELAY_ID ?? "did:tsl:relay:dev", epochStartMs);
          }
          if (topic === QUEUE_TOPICS.attestationsAccepted && message.values.attestation) {
            const attestation = JSON.parse(message.values.attestation) as AttestationV1;
            const epochStartMs = Math.floor(Date.parse(attestation.issued_at) / Number(process.env.TSL_EPOCH_MS ?? 300000)) * Number(process.env.TSL_EPOCH_MS ?? 300000);
            await db.insertAttestation(attestation, process.env.TSL_RELAY_ID ?? "did:tsl:relay:dev", epochStartMs);
          }
          if (topic === QUEUE_TOPICS.revocationsAccepted && message.values.revocation) {
            const revocation = JSON.parse(message.values.revocation) as RevocationV1;
            await db.insertRevocation(revocation, process.env.TSL_RELAY_ID ?? "did:tsl:relay:dev", Number(process.env.TSL_EPOCH_MS ?? 300000));
          }
        } catch (error) {
          await queue.deadLetter(topic, message, error);
        }
      }
    }
    return counts;
  }

  app.post("/v1/log/consume-once", async (req, res) => {
    try {
      const counts = await consumeQueueOnce(Number(req.body.limit ?? 100));
      res.json({ status: "accepted", counts });
    } catch (error) {
      sendError(res, "TSL_LOG_CONSUME_FAILED", error);
    }
  });

  app.get("/v1/log/metrics", async (_req, res) => {
    try {
      if (!queue) {
        res.json({ queue_enabled: false, last_stream_ids: Object.fromEntries(lastStreamIds) });
        return;
      }
      const topics: QueueTopic[] = [
        QUEUE_TOPICS.commitmentsAccepted,
        QUEUE_TOPICS.receiptsAccepted,
        QUEUE_TOPICS.attestationsAccepted,
        QUEUE_TOPICS.revocationsAccepted,
        QUEUE_TOPICS.checkpointsReady,
        QUEUE_TOPICS.checkpointsSettled,
        QUEUE_TOPICS.auditFindings
      ];
      const stream_lengths: Record<string, number> = {};
      const dead_letter_lengths: Record<string, number> = {};
      for (const topic of topics) {
        stream_lengths[topic] = await queue.length(topic);
        dead_letter_lengths[`${topic}.dead.v1`] = await queue.length(`${topic}.dead.v1`);
      }
      res.json({
        queue_enabled: true,
        consumer_group: process.env.TSL_LOG_CONSUMER_GROUP ?? "tsl-log-node-local",
        last_stream_ids: Object.fromEntries(lastStreamIds),
        stream_lengths,
        dead_letter_lengths
      });
    } catch (error) {
      sendError(res, "TSL_LOG_METRICS_FAILED", error);
    }
  });

  app.post("/v1/log/close-epoch", async (req, res) => {
    try {
      const db = await requireRepo();
      const checkpoint = await db.buildCheckpoint(
        Number(req.body.epoch_start_ms),
        String(req.body.shard),
        Number(req.body.epoch_duration_ms ?? process.env.TSL_EPOCH_MS ?? 300000),
        String(req.body.relay_id ?? process.env.TSL_RELAY_ID ?? "did:tsl:relay:dev"),
        String(req.body.relay_signature ?? process.env.TSL_RELAY_SIGNATURE ?? "0x01"),
        req.body.settlement_backend !== undefined
          ? String(req.body.settlement_backend)
          : process.env["TSL_" + "SETTLEMENT_BACKEND"]
      );
      await db.insertCheckpoint(checkpoint, "pending");
      await queue?.publish(QUEUE_TOPICS.checkpointsReady, { checkpoint });
      res.json({ status: "checkpointed", checkpoint });
    } catch (error) {
      sendError(res, "TSL_LOG_CLOSE_FAILED", error);
    }
  });

  app.post("/v1/gossip/checkpoint", async (req, res) => {
    try {
      const db = await requireRepo();
      const checkpoint = req.body.checkpoint as BatchCheckpointV1;
      const checkpoint_hash = await validateAndInsertCheckpoint(db, checkpoint, req.body);
      res.json({ status: "accepted", checkpoint_hash });
    } catch (error) {
      sendError(res, "TSL_GOSSIP_CHECKPOINT_REJECTED", error);
    }
  });

  app.post("/v1/gossip/checkpoint-summary", async (req, res) => {
    try {
      const db = await requireRepo();
      const incoming = req.body.checkpoint as BatchCheckpointV1;
      const checkpoint_hash = await validateAndInsertCheckpoint(db, incoming, req.body);
      res.json({ status: "accepted", conflict: false, checkpoint_hash });
    } catch (error) {
      sendError(res, "TSL_GOSSIP_CHECKPOINT_SUMMARY_REJECTED", error);
    }
  });

  app.post("/v1/gossip/audit-finding", async (req, res) => {
    try {
      if (repo) await (await requireRepo()).insertAuditFinding(req.body.finding);
      await queue?.publish(QUEUE_TOPICS.auditFindings, { finding: req.body.finding });
      res.json({ status: "accepted" });
    } catch (error) {
      sendError(res, "TSL_GOSSIP_AUDIT_FINDING_REJECTED", error);
    }
  });

  app.get("/v1/gossip/audit-findings", async (req, res) => {
    try {
      const db = await requireRepo();
      res.json({ findings: await db.listAuditFindings(Number(req.query.limit ?? 100), req.query.checkpoint_hash as `0x${string}` | undefined) });
    } catch (error) {
      sendError(res, "TSL_GOSSIP_AUDIT_FINDINGS_LOOKUP_FAILED", error);
    }
  });

  app.post("/v1/gossip/peers", async (req, res) => {
    try {
      if (req.body.peer_url) {
        const peerUrl = registerRequestedGossipPeer(req.body.peer_url);
        peers.add(peerUrl);
        if (repo) await (await requireRepo()).upsertGossipPeer(peerUrl);
      }
      res.json({ status: "accepted", peers: await listPeers() });
    } catch (error) {
      sendError(res, error instanceof GossipPeerError ? error.code : "TSL_GOSSIP_PEER_REJECTED", error, error instanceof GossipPeerError ? error.status : 400);
    }
  });

  app.get("/v1/gossip/peers", async (_req, res) => {
    res.json({ peers: await listPeers() });
  });

  app.post("/v1/gossip/sync", async (req, res) => {
    try {
      const db = await requireRepo();
      const peerUrls = selectKnownGossipPeers(req.body.peer_url, await listPeers());
      let imported_checkpoints = 0;
      let imported_findings = 0;
      const conflicts: unknown[] = [];
      for (const peerUrl of peerUrls) {
        const summaryResponse = await fetch(buildGossipUrl(peerUrl, "/v1/gossip/checkpoint-summaries"));
        if (summaryResponse.ok) {
          const payload = await summaryResponse.json() as { checkpoints?: Array<Record<string, unknown>> };
          for (const row of payload.checkpoints ?? []) {
            const epochStartMs = Number(row.epoch_start_ms);
            const shard = String(row.shard ?? "");
            if (!Number.isSafeInteger(epochStartMs) || !/^[A-Za-z0-9._:-]{1,128}$/.test(shard)) continue;
            const checkpoint = await fetch(buildGossipUrl(peerUrl, `/v1/gossip/checkpoints/${epochStartMs}/${encodeURIComponent(shard)}`));
            if (!checkpoint.ok) continue;
            const checkpointPayload = await checkpoint.json() as Record<string, unknown>;
            const imported = (checkpointPayload.checkpoint ?? checkpointPayload) as BatchCheckpointV1;
            try {
              await validateAndInsertCheckpoint(db, imported, checkpointPayload);
            } catch {
              conflicts.push({ peer: peerUrl, epoch_start_ms: imported.epoch_start_ms, shard: imported.shard });
              continue;
            }
            imported_checkpoints += 1;
          }
        }
        const findingsResponse = await fetch(buildGossipUrl(peerUrl, "/v1/gossip/audit-findings"));
        if (findingsResponse.ok) {
          const payload = await findingsResponse.json() as { findings?: Array<unknown> };
          for (const finding of payload.findings ?? []) {
            await db.insertAuditFinding(finding as never);
            imported_findings += 1;
          }
        }
      }
      res.json({ status: "accepted", peers: peerUrls, imported_checkpoints, imported_findings, conflicts });
    } catch (error) {
      sendError(res, "TSL_GOSSIP_SYNC_FAILED", error);
    }
  });

  app.get("/v1/gossip/checkpoint-summaries", async (_req, res) => {
    try {
      const db = await requireRepo();
      const result = await db.pool.query(
        `SELECT checkpoint_hash, epoch_start_ms, shard, event_root, receipt_root, attestation_root, revocation_root,
                previous_checkpoint, settlement_status, settlement_tx
         FROM checkpoints
         ORDER BY epoch_start_ms DESC
         LIMIT 100`
      );
      res.json({ checkpoints: result.rows });
    } catch (error) {
      sendError(res, "TSL_GOSSIP_SUMMARY_FAILED", error);
    }
  });

  app.get("/v1/audit/findings", async (req, res) => {
    try {
      const db = await requireRepo();
      res.json({ findings: await db.listAuditFindings(Number(req.query.limit ?? 100), req.query.checkpoint_hash as `0x${string}` | undefined) });
    } catch (error) {
      sendError(res, "TSL_AUDIT_FINDINGS_LOOKUP_FAILED", error);
    }
  });

  app.get("/v1/gossip/checkpoints/:epoch/:shard", async (req, res) => {
    try {
      const checkpoint = await (await requireRepo()).getCheckpoint(Number(req.params.epoch), req.params.shard);
      if (!checkpoint) {
        res.status(404).json({ error: { code: "TSL_CHECKPOINT_NOT_FOUND", message: "Checkpoint not found" } });
        return;
      }
      res.json(checkpoint);
    } catch (error) {
      sendError(res, "TSL_CHECKPOINT_LOOKUP_FAILED", error);
    }
  });

  app.get("/v1/proofs/:treeKind/:commitment", async (req, res) => {
    try {
      const treeKind = req.params.treeKind as "event" | "receipt" | "attestation" | "revocation";
      if (!["event", "receipt", "attestation", "revocation"].includes(treeKind)) {
        res.status(400).json({ error: { code: "TSL_TREE_KIND_INVALID", message: "Unsupported tree kind" } });
        return;
      }
      const proof = await (await requireRepo()).buildInclusionProofFor(treeKind, req.params.commitment as `0x${string}`);
      if (!proof) {
        res.status(404).json({ error: { code: "TSL_PROOF_NOT_FOUND", message: "Proof not found" } });
        return;
      }
      res.json(proof);
    } catch (error) {
      sendError(res, "TSL_PROOF_LOOKUP_FAILED", error);
    }
  });

  app.get("/v1/consistency/:epoch/:shard", async (req, res) => {
    try {
      const proof = await (await requireRepo()).buildConsistencyProofFor(Number(req.params.epoch), req.params.shard);
      if (!proof) {
        res.status(404).json({ error: { code: "TSL_CONSISTENCY_PROOF_NOT_FOUND", message: "Not enough checkpoint history for consistency proof" } });
        return;
      }
      res.json({ proof });
    } catch (error) {
      sendError(res, "TSL_CONSISTENCY_PROOF_FAILED", error);
    }
  });

  if (process.env.TSL_LOG_CONSUME_STREAMS === "true") {
    const intervalMs = Number(process.env.TSL_LOG_CONSUME_INTERVAL_MS ?? 1000);
    setInterval(() => {
      void consumeQueueOnce(Number(process.env.TSL_LOG_CONSUME_BATCH ?? 100)).catch((error) => {
        process.stderr.write(`tsl log-node consume failed: ${error instanceof Error ? error.message : String(error)}\n`);
      });
    }, intervalMs).unref();
  }

  return app;
}

function sendError(res: express.Response, code: string, error: unknown, status = 400): void {
  res.status(status).json({ error: { code, message: error instanceof Error ? error.message : String(error) } });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT ?? 8081);
  const app = createLogNode();
  app.listen(port, () => process.stdout.write(`tsl log-node listening on http://localhost:${port}\n`));
}
