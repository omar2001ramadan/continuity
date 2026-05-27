import "../../../scripts/load-env.cjs";
import express from "express";
import { createPostgresRepositoryFromEnv } from "../../../packages/core-ts/src/index";

export function createResolverNode() {
  const repo = createPostgresRepositoryFromEnv();
  let migrated = false;
  async function requireRepo() {
    if (!repo) throw new Error("TSL_DATABASE_URL or DATABASE_URL is required");
    if (!migrated) {
      await repo.migrate();
      migrated = true;
    }
    return repo;
  }

  const app = express();
  app.use(express.json({ limit: "1mb" }));
  app.get("/health", (_req, res) => res.json({ ok: true, service: "tsl-resolver-node" }));

  app.get("/v1/identity/:trustId", async (req, res) => {
    try {
      const identity = await (await requireRepo()).getIdentity(req.params.trustId);
      if (!identity) {
        res.status(404).json({ error: { code: "TSL_KEY_NOT_FOUND", message: "TrustID not found" } });
        return;
      }
      res.json(identity);
    } catch (error) {
      res.status(400).json({ error: { code: "TSL_RESOLVE_FAILED", message: error instanceof Error ? error.message : String(error) } });
    }
  });

  app.get("/v1/revocation/:trustId", async (req, res) => {
    try {
      const revocations = await (await requireRepo()).getRevocations(req.params.trustId);
      res.json({ trust_id: req.params.trustId, revocations });
    } catch (error) {
      res.status(400).json({ error: { code: "TSL_REVOCATION_LOOKUP_FAILED", message: error instanceof Error ? error.message : String(error) } });
    }
  });

  app.get("/v1/identity/:trustId/revocations", async (req, res) => {
    try {
      const revocations = await (await requireRepo()).getRevocations(req.params.trustId);
      res.json({ trust_id: req.params.trustId, revocations });
    } catch (error) {
      res.status(400).json({ error: { code: "TSL_REVOCATION_LOOKUP_FAILED", message: error instanceof Error ? error.message : String(error) } });
    }
  });

  return app;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT ?? 8082);
  createResolverNode().listen(port, () => process.stdout.write(`tsl resolver-node listening on http://localhost:${port}\n`));
}
