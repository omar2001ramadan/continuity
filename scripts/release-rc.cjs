const { execFileSync } = require("node:child_process");

const commands = [
  ["npm", ["run", "release:check"]],
  ["npm", ["run", "zk:manifest"]]
];

if (process.env.TSL_RELEASE_RC_RUN_FULL_PATH_SMOKE !== "0") {
  commands.push(["npm", ["run", "load-test:full-path"]]);
}

for (const [command, args] of commands) {
  process.stderr.write(`$ ${command} ${args.join(" ")}\n`);
  const env = {
    ...process.env,
    TSL_FULL_PATH_COUNT: process.env.TSL_FULL_PATH_COUNT ?? "25",
    TSL_FULL_PATH_SAMPLES: process.env.TSL_FULL_PATH_SAMPLES ?? "5",
    TSL_FULL_PATH_CONCURRENCY: process.env.TSL_FULL_PATH_CONCURRENCY ?? "5"
  };
  execFileSync(command, args, { stdio: "inherit", env });
}
