import "./load-env.cjs";
import { existsSync, readFileSync } from "node:fs";
import { ethers } from "ethers";

const file = process.argv[2] ?? "deployments/base-sepolia.json";
if (!existsSync(file)) throw new Error(`Deployment artifact not found: ${file}`);
const deployment = JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>;
const required = ["chainId", "deployer", "checkpointRegistry", "trustIDRegistry", "revocationRegistry", "providerRegistry", "governanceRegistry", "authorizedRelays"];
for (const key of required) {
  if (deployment[key] === undefined) throw new Error(`Deployment artifact missing ${key}`);
}
for (const key of ["deployer", "checkpointRegistry", "trustIDRegistry", "revocationRegistry", "providerRegistry", "governanceRegistry"]) {
  if (!ethers.isAddress(String(deployment[key]))) throw new Error(`Invalid address for ${key}`);
}
if (!Array.isArray(deployment.authorizedRelays) || deployment.authorizedRelays.length === 0) {
  throw new Error("Deployment artifact must include at least one authorized relay id");
}
process.stdout.write(JSON.stringify({ valid: true, file, deployment }, null, 2) + "\n");
