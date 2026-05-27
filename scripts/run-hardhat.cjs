#!/usr/bin/env node
const { existsSync } = require("node:fs");
const { join } = require("node:path");
const { spawnSync } = require("node:child_process");

const node20Candidates = [
  "/opt/homebrew/opt/node@20/bin/node",
  "/usr/local/opt/node@20/bin/node",
  "/opt/homebrew/bin/node20",
  "/usr/local/bin/node20"
];

function major(version) {
  const match = /^v?(\d+)/.exec(version);
  return match ? Number(match[1]) : 0;
}

const currentMajor = major(process.version);
const nodeBinary =
  currentMajor > 22 ? node20Candidates.find((candidate) => existsSync(candidate)) ?? process.execPath : process.execPath;
const hardhatCli = join(process.cwd(), "node_modules", "hardhat", "internal", "cli", "cli.js");
const result = spawnSync(nodeBinary, [hardhatCli, ...process.argv.slice(2)], {
  cwd: process.cwd(),
  env: process.env,
  stdio: "inherit"
});

if (result.error) {
  throw result.error;
}
process.exit(result.status ?? 1);
