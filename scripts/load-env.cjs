const { existsSync, readFileSync } = require("node:fs");

const envPath = process.env.TSL_ENV_FILE || ".env";
const runningTests = process.env.VITEST === "true" || process.env.NODE_ENV === "test";

if (!runningTests || process.env.TSL_LOAD_ENV_IN_TESTS === "true") {
if (existsSync(envPath)) {
  for (const rawLine of readFileSync(envPath, "utf8").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith("\"") && value.endsWith("\"")) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (process.env[key] === undefined) process.env[key] = value;
  }
}
}
