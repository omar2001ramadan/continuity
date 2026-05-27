const { execFileSync } = require("node:child_process");

const commands = [
  ["npm", ["run", "build"]],
  ["npm", ["test"]],
  ["npm", ["run", "contracts:compile"]],
  ["npm", ["run", "contracts:test"]],
  ["npm", ["run", "zk:test"]],
  ["npm", ["run", "build:web-verifier"]],
  ["npm", ["run", "parity:python"]],
  ["npm", ["run", "parity:rust"]],
  ["docker", ["compose", "config"]]
];

for (const [command, args] of commands) {
  process.stderr.write(`$ ${command} ${args.join(" ")}\n`);
  execFileSync(command, args, { stdio: "inherit" });
}
