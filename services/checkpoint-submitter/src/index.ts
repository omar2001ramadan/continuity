import express from "express";
import "../../../scripts/load-env.cjs";
import {
  createPostgresRepositoryFromEnv,
  createQueueFromEnv,
  createSettlementBackendFromEnv,
  QUEUE_TOPICS
} from "../../../packages/core-ts/src/index";

export function createCheckpointSubmitter() {
  const repo = createPostgresRepositoryFromEnv();
  const settlement = createSettlementBackendFromEnv();
  const queue = createQueueFromEnv();
  let migrated = false;
  async function requireReady() {
    if (!repo) throw new Error("TSL_DATABASE_URL or DATABASE_URL is required");
    if (!settlement) throw new Error("TSL_CHECKPOINT_REGISTRY_ADDRESS is required");
    if (!migrated) {
      await repo.migrate();
      migrated = true;
    }
    return { repo, settlement };
  }

  const app = express();
  app.use(express.json({ limit: "1mb" }));
  app.get("/health", (_req, res) => res.json({ ok: true, service: "tsl-checkpoint-submitter" }));

  app.post("/v1/checkpoints/submit-pending", async (req, res) => {
    try {
      const { repo, settlement } = await requireReady();
      const pending = await repo.listPendingCheckpoints(Number(req.body.limit ?? 100));
      const settled = [];
      for (const checkpoint of pending) {
        const settledCheckpoint = await settlement.submitCheckpoint(checkpoint);
        await repo.markCheckpointSettled(settledCheckpoint);
        await queue?.publish(QUEUE_TOPICS.checkpointsSettled, { checkpoint: settledCheckpoint });
        settled.push(settledCheckpoint);
      }
      res.json({ status: "settled", count: settled.length, checkpoints: settled });
    } catch (error) {
      res.status(400).json({ error: { code: "TSL_CHECKPOINT_SUBMIT_FAILED", message: error instanceof Error ? error.message : String(error) } });
    }
  });

  return app;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT ?? 8086);
  createCheckpointSubmitter().listen(port, () => process.stdout.write(`tsl checkpoint-submitter listening on http://localhost:${port}\n`));
}
