const { existsSync, mkdirSync } = require("node:fs");
const { execFileSync } = require("node:child_process");
const path = require("node:path");

const root = process.cwd();
const buildDir = path.join(root, "circuits", "build");
mkdirSync(buildDir, { recursive: true });

const pot0 = path.join(buildDir, "pot8_0000.ptau");
const pot1 = path.join(buildDir, "pot8_0001.ptau");
const potFinal = path.join(buildDir, "pot8_final.ptau");
const circuits = [
  "identity_age_threshold",
  "reciprocal_receipt_count_threshold"
];

function run(command, args) {
  process.stderr.write(`$ ${command} ${args.join(" ")}\n`);
  execFileSync(command, args, { stdio: "inherit" });
}

if (!existsSync(potFinal)) {
  run("npx", ["snarkjs", "powersoftau", "new", "bn128", "8", pot0]);
  run("npx", ["snarkjs", "powersoftau", "contribute", pot0, pot1, "--name=TSL dev contribution", "-e=tsl-dev"]);
  run("npx", ["snarkjs", "powersoftau", "prepare", "phase2", pot1, potFinal]);
}

const artifacts = {};
for (const name of circuits) {
  const circuit = path.join(root, "circuits", `${name}.circom`);
  const r1cs = path.join(buildDir, `${name}.r1cs`);
  const wasm = path.join(buildDir, `${name}_js`, `${name}.wasm`);
  const zkey0 = path.join(buildDir, `${name}_0000.zkey`);
  const zkey = path.join(buildDir, `${name}.zkey`);
  const vkey = path.join(buildDir, `${name}.vkey.json`);
  run("npx", ["circom2", circuit, "--r1cs", "--wasm", "--sym", "-o", buildDir]);
  run("npx", ["snarkjs", "groth16", "setup", r1cs, potFinal, zkey0]);
  run("npx", ["snarkjs", "zkey", "contribute", zkey0, zkey, "--name=TSL circuit contribution", "-e=tsl-circuit"]);
  run("npx", ["snarkjs", "zkey", "export", "verificationkey", zkey, vkey]);
  artifacts[name] = { r1cs, wasm, zkey, vkey };
}

process.stdout.write(JSON.stringify(artifacts, null, 2) + "\n");
