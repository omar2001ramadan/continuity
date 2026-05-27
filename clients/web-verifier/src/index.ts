import express from "express";
import { readFileSync } from "node:fs";
import { join } from "node:path";

export function createWebVerifier() {
  const app = express();
  const publicDir = join(process.cwd(), "clients/web-verifier/public");
  const index = readFileSync(join(publicDir, "index.html"), "utf8");
  app.use(express.static(publicDir));
  app.get(["/", "/p/:payload"], (_req, res) => res.type("html").send(index));
  return app;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT ?? 8090);
  createWebVerifier().listen(port, () => process.stdout.write(`tsl web-verifier listening on http://localhost:${port}\n`));
}
