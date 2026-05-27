import "./load-env.cjs";
import { createPostgresRepositoryFromEnv } from "../packages/core-ts/src/index";

const repo = createPostgresRepositoryFromEnv();
if (!repo) throw new Error("TSL_DATABASE_URL or DATABASE_URL is required");
await repo.migrate();
await repo.close();
process.stdout.write("migrations applied\n");
