#!/usr/bin/env node
const { spawnSync } = require("node:child_process");
const { existsSync } = require("node:fs");
const { join } = require("node:path");

function hasCommand(command) {
  const result = spawnSync("sh", ["-lc", `command -v ${command}`], { stdio: "ignore" });
  return result.status === 0;
}

const crateDir = join(process.cwd(), "packages", "core-rust");
const command = hasCommand("cargo")
  ? { bin: "cargo", args: ["test"], cwd: crateDir }
  : hasCommand("docker")
    ? {
        bin: "docker",
        args: [
          "run",
          "--rm",
          "-v",
          `${crateDir}:/work`,
          "-w",
          "/work",
          "-e",
          "CARGO_HOME=/tmp/cargo",
          "rust:1.85-bookworm",
          "cargo",
          "test"
        ],
        cwd: process.cwd()
      }
    : null;

if (!command) {
  console.error("Rust parity requires either cargo or docker. Install Rust or start Docker Desktop and retry.");
  process.exit(127);
}

if (!existsSync(crateDir)) {
  console.error(`Missing Rust crate directory: ${crateDir}`);
  process.exit(1);
}

const result = spawnSync(command.bin, command.args, {
  cwd: command.cwd,
  env: process.env,
  stdio: "inherit"
});

if (result.error) {
  throw result.error;
}
process.exit(result.status ?? 1);
