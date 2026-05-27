import "../../../scripts/load-env.cjs";
import express from "express";
import {
  createPostgresRepositoryFromEnv,
  createQueueFromEnv,
  createSettlementBackendFromEnv,
  checkpointHash,
  signAuditFinding,
  auditFindingHash,
  createSigningAdapter,
  ZERO_HASH,
  QUEUE_TOPICS,
  type AuditFindingV1,
  type Hex32
} from "../../../packages/core-ts/src/index";

export function createAuditorNode() {
  const repo = createPostgresRepositoryFromEnv();
  const queue = createQueueFromEnv();
  const settlement = createSettlementBackendFromEnv();
  const findings: AuditFindingV1[] = [];
  const peers = new Set<string>((process.env.TSL_GOSSIP_PEERS ?? "").split(",").map((peer) => peer.trim()).filter(Boolean));
  let migrated = false;
  async function ensureRepo() {
    if (!repo) return null;
    if (!migrated) {
      await repo.migrate();
      for (const peer of peers) await repo.upsertGossipPeer(peer);
      migrated = true;
    }
    return repo;
  }
  const app = express();
  app.use(express.json({ limit: "1mb" }));
  app.get("/health", (_req, res) => res.json({ ok: true, service: "tsl-auditor-node" }));

  async function rememberFinding(finding: AuditFindingV1): Promise<void> {
    findings.push(finding);
    await (await ensureRepo())?.insertAuditFinding(finding);
    await queue?.publish(QUEUE_TOPICS.auditFindings, { finding });
  }

  async function signedFinding(input: Omit<AuditFindingV1, "type" | "auditor" | "issued_at" | "signature">): Promise<AuditFindingV1> {
    const auditor = process.env.TSL_AUDITOR_ID ?? "did:tsl:auditor:local";
    const unsigned = {
      type: "tsl.audit.finding.v1" as const,
      auditor,
      issued_at: new Date().toISOString(),
      ...input
    };
    const adapterUri = process.env.TSL_AUDITOR_PRIVATE_KEY_URI;
    if (adapterUri) {
      return { ...unsigned, signature: await createSigningAdapter(adapterUri).sign(auditFindingHash(unsigned)) };
    }
    const seed = process.env.TSL_AUDITOR_SEED_HEX;
    if (!seed) throw new Error("TSL_AUDITOR_PRIVATE_KEY_URI or TSL_AUDITOR_SEED_HEX is required to sign audit findings");
    return signAuditFinding(unsigned, seed);
  }

  app.post("/v1/audit/checkpoint", async (req, res) => {
    try {
      const checkpoint = req.body.checkpoint;
      const settlementResult = settlement ? await settlement.verifyCheckpointSettlement(checkpoint) : { settled: false, error: "TSL_SETTLEMENT_BACKEND_MISSING" };
      const finding = await signedFinding({
        checkpoint_hash: req.body.checkpoint_hash ?? checkpointHash(checkpoint),
        epoch_start_ms: checkpoint.epoch_start_ms,
        shard: checkpoint.shard,
        finding_class: settlementResult.settled ? "checkpoint_valid" : settlementResult.error === "TSL_SETTLEMENT_MISMATCH" ? "settlement_mismatch" : "settlement_missing",
        severity: settlementResult.settled ? "info" : "warning",
        evidence_commitment: (req.body.evidence_commitment ?? ZERO_HASH) as Hex32
      });
      await rememberFinding(finding);
      res.json({ status: settlementResult.settled ? "accepted" : "rejected", finding });
    } catch (error) {
      res.status(400).json({ error: { code: "TSL_AUDIT_FAILED", message: error instanceof Error ? error.message : String(error) } });
    }
  });

  app.post("/v1/audit/conflict", async (req, res) => {
    try {
      const finding = await signedFinding({
        checkpoint_hash: req.body.checkpoint_hash,
        epoch_start_ms: req.body.epoch_start_ms,
        shard: req.body.shard,
        finding_class: "checkpoint_conflict",
        severity: "critical",
        evidence_commitment: req.body.evidence_commitment ?? ZERO_HASH
      });
      await rememberFinding(finding);
      res.json({ status: "accepted", finding });
    } catch (error) {
      res.status(400).json({ error: { code: "TSL_AUDIT_CONFLICT_FAILED", message: error instanceof Error ? error.message : String(error) } });
    }
  });

  app.post("/v1/audit/checkpoint-conflict", async (req, res) => {
    try {
      if (!repo) throw new Error("TSL_DATABASE_URL or DATABASE_URL is required");
      const incoming = req.body.checkpoint;
      const existing = await repo.getCheckpoint(Number(incoming.epoch_start_ms), String(incoming.shard));
      const conflict =
        existing &&
        (existing.event_root !== incoming.event_root ||
          existing.receipt_root !== incoming.receipt_root ||
          existing.attestation_root !== incoming.attestation_root ||
          existing.revocation_root !== incoming.revocation_root ||
          existing.previous_checkpoint !== incoming.previous_checkpoint);
      if (!conflict) {
        res.json({ status: "accepted", conflict: false });
        return;
      }
      const finding = await signedFinding({
        checkpoint_hash: req.body.checkpoint_hash ?? checkpointHash(incoming),
        epoch_start_ms: incoming.epoch_start_ms,
        shard: incoming.shard,
        finding_class: "checkpoint_conflict",
        severity: "critical",
        evidence_commitment: req.body.evidence_commitment ?? ZERO_HASH
      });
      await rememberFinding(finding);
      res.status(409).json({ status: "rejected", conflict: true, finding });
    } catch (error) {
      res.status(400).json({ error: { code: "TSL_AUDIT_CONFLICT_FAILED", message: error instanceof Error ? error.message : String(error) } });
    }
  });

  app.post("/v1/gossip/audit-finding", async (req, res) => {
    try {
      await rememberFinding(req.body.finding);
      res.json({ status: "accepted" });
    } catch (error) {
      res.status(400).json({ error: { code: "TSL_GOSSIP_AUDIT_FINDING_REJECTED", message: error instanceof Error ? error.message : String(error) } });
    }
  });

  app.get("/v1/gossip/audit-findings", async (req, res) => {
    const db = await ensureRepo();
    const persisted = db ? await db.listAuditFindings(Number(req.query.limit ?? 100), req.query.checkpoint_hash as `0x${string}` | undefined) : findings;
    res.json({ findings: persisted });
  });

  app.get("/v1/audit/findings", async (req, res) => {
    const db = await ensureRepo();
    const persisted = db ? await db.listAuditFindings(Number(req.query.limit ?? 100), req.query.checkpoint_hash as `0x${string}` | undefined) : findings;
    res.json({ findings: persisted });
  });

  app.post("/v1/gossip/peers", async (req, res) => {
    if (req.body.peer_url) {
      peers.add(String(req.body.peer_url));
      await (await ensureRepo())?.upsertGossipPeer(String(req.body.peer_url));
    }
    const db = await ensureRepo();
    res.json({ status: "accepted", peers: db ? await db.listGossipPeers() : [...peers] });
  });

  app.get("/v1/gossip/peers", async (_req, res) => {
    const db = await ensureRepo();
    res.json({ peers: db ? await db.listGossipPeers() : [...peers] });
  });

  app.post("/v1/gossip/sync", async (req, res) => {
    try {
      const db = await ensureRepo();
      const peerUrls = req.body.peer_url ? [String(req.body.peer_url)] : db ? await db.listGossipPeers() : [...peers];
      let imported_findings = 0;
      for (const peerUrl of peerUrls) {
        const response = await fetch(`${peerUrl.replace(/\/$/, "")}/v1/gossip/audit-findings`);
        if (!response.ok) continue;
        const payload = await response.json() as { findings?: AuditFindingV1[] };
        for (const finding of payload.findings ?? []) {
          await rememberFinding(finding);
          imported_findings += 1;
        }
      }
      res.json({ status: "accepted", peers: peerUrls, imported_findings });
    } catch (error) {
      res.status(400).json({ error: { code: "TSL_GOSSIP_SYNC_FAILED", message: error instanceof Error ? error.message : String(error) } });
    }
  });

  app.get("/v1/audit/checkpoints/:epoch/:shard", async (req, res) => {
    try {
      if (!repo) throw new Error("TSL_DATABASE_URL or DATABASE_URL is required");
      const checkpoint = await repo.getCheckpoint(Number(req.params.epoch), req.params.shard);
      res.json({ checkpoint, present: Boolean(checkpoint) });
    } catch (error) {
      res.status(400).json({ error: { code: "TSL_AUDIT_LOOKUP_FAILED", message: error instanceof Error ? error.message : String(error) } });
    }
  });

  return app;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT ?? 8085);
  createAuditorNode().listen(port, () => process.stdout.write(`tsl auditor-node listening on http://localhost:${port}\n`));
}
