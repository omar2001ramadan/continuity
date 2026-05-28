import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  buildIdentityFromSeed,
  type AgentActionV2,
  type DelegationPolicyV2,
  type IdentityDocumentV1
} from "../packages/core-ts/src/index";
import { createAgentSidecar } from "../clients/agent-sidecar/src/index";

const evidencePath = path.join("evidence", "integration", "cli-sidecar-v2-smoke.json");
const principalSeed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const agentSeed = "1111111111111111111111111111111111111111111111111111111111111111";
const principal = "did:tsl:mainnet-smoke:principal";
const agent = "did:tsl:mainnet-smoke:agent";

function writeJson(file: string, value: unknown): void {
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function runCli(args: string[], allowFailure = false): { ok: boolean; output: Record<string, unknown> } {
  try {
    const stdout = execFileSync("npx", ["tsx", "clients/cli/src/index.ts", ...args], {
      cwd: process.cwd(),
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"]
    });
    return { ok: true, output: JSON.parse(stdout) as Record<string, unknown> };
  } catch (error) {
    if (!allowFailure) throw error;
    const stderr = error && typeof error === "object" && "stderr" in error ? String((error as { stderr?: unknown }).stderr ?? "") : "";
    const stdout = error && typeof error === "object" && "stdout" in error ? String((error as { stdout?: unknown }).stdout ?? "") : "";
    return { ok: false, output: stdout.trim() ? JSON.parse(stdout) as Record<string, unknown> : { stderr } };
  }
}

async function postJson(url: string, body: unknown): Promise<{ status: number; payload: Record<string, unknown> }> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  return { status: response.status, payload: await response.json() as Record<string, unknown> };
}

async function main(): Promise<void> {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "tsl-mainnet-agent-v2-"));
  const principalIdentity = buildIdentityFromSeed({ trust_id: principal, key_id: "#p", seed_hex: principalSeed, created_at: "2026-05-28T00:00:00Z" });
  const agentIdentity = buildIdentityFromSeed({ trust_id: agent, key_id: "#a", seed_hex: agentSeed, created_at: "2026-05-28T00:00:00Z" });
  const principalFile = path.join(tmp, "principal.json");
  const agentFile = path.join(tmp, "agent.json");
  const chainFile = path.join(tmp, "chain.json");
  const actionFile = path.join(tmp, "action.json");
  writeJson(principalFile, principalIdentity);
  writeJson(agentFile, agentIdentity);

  const policyResult = runCli([
    "delegation:v2:create",
    "--principal", principal,
    "--principal-seed-hex", principalSeed,
    "--delegate", agent,
    "--actions", "invoice.pay",
    "--resources", "invoice/*",
    "--valid-from", "2026-05-28T00:00:00Z",
    "--valid-until", "2026-05-29T00:00:00Z",
    "--revocation-pointer", "rev:mainnet-smoke",
    "--constraints", JSON.stringify({ max_value_minor_units: 1000, allowed_tools: ["stripe"], currency: "USD" })
  ]);
  const policy = policyResult.output.policy as DelegationPolicyV2;
  writeJson(chainFile, { delegation_chain: [policy] });

  const parameters = { value_minor_units: 900, currency: "USD" };
  const actionResult = runCli([
    "agent:v2:sign-action",
    "--agent", agent,
    "--principal", principal,
    "--agent-seed-hex", agentSeed,
    "--action", "invoice.pay",
    "--resource", "invoice/123",
    "--tool", "stripe",
    "--value-minor-units", "900",
    "--issued-at", "2026-05-28T12:00:00Z",
    "--delegation-chain-file", chainFile,
    "--parameters", JSON.stringify(parameters)
  ]);
  const action = actionResult.output.action as AgentActionV2;
  writeJson(actionFile, { action });

  const inside = runCli([
    "agent:v2:verify",
    "--action-file", actionFile,
    "--delegation-chain-file", chainFile,
    "--identity-file", principalFile,
    "--identity-file", agentFile,
    "--parameters", JSON.stringify(parameters)
  ]);
  if (inside.output.status !== "agent_inside_scope") throw new Error("CLI inside-scope verification failed");

  const outside = runCli([
    "agent:v2:verify",
    "--action-file", actionFile,
    "--delegation-chain-file", chainFile,
    "--identity-file", principalFile,
    "--identity-file", agentFile,
    "--parameters", JSON.stringify({ value_minor_units: 1500, currency: "USD" })
  ], true);
  const outsideResult = outside.output.result as { error_code?: string } | undefined;
  if (outside.ok || outside.output.status !== "agent_outside_scope" || outsideResult?.error_code !== "TSL_DELEGATION_CONSTRAINT_VIOLATION") {
    throw new Error("CLI outside-scope verification did not fail with TSL_DELEGATION_CONSTRAINT_VIOLATION");
  }

  const app = createAgentSidecar();
  const server = app.listen(0);
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Could not bind sidecar smoke server");
  const base = `http://127.0.0.1:${address.port}`;
  try {
    const sidecarPolicy = await postJson(`${base}/v1/agent/delegation-policies/v2`, {
      principal,
      delegate: agent,
      principal_seed_hex: principalSeed,
      actions: ["invoice.pay"],
      resources: ["invoice/*"],
      constraints: { max_value_minor_units: 1000, allowed_tools: ["stripe"], currency: "USD" },
      valid_from: "2026-05-28T00:00:00Z",
      valid_until: "2026-05-29T00:00:00Z",
      revocation_pointer: "rev:sidecar-smoke"
    });
    if (sidecarPolicy.status !== 200) throw new Error("Sidecar policy creation failed");
    const sidecarChain = [(sidecarPolicy.payload.policy as DelegationPolicyV2)];
    const sidecarAction = await postJson(`${base}/v1/agent/actions/v2`, {
      principal,
      agent,
      agent_seed_hex: agentSeed,
      action: "invoice.pay",
      resource: "invoice/456",
      tool: "stripe",
      value_minor_units: 900,
      parameters,
      delegation_chain: sidecarChain,
      issued_at: "2026-05-28T12:00:00Z"
    });
    if (sidecarAction.status !== 200) throw new Error("Sidecar action signing failed");
    const sidecarVerify = await postJson(`${base}/v1/agent/actions/v2/verify`, {
      action: sidecarAction.payload.action,
      delegation_chain: sidecarChain,
      identities: [principalIdentity, agentIdentity],
      parameters
    });
    if (sidecarVerify.status !== 200 || sidecarVerify.payload.status !== "agent_inside_scope") throw new Error("Sidecar inside-scope verification failed");
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }

  fs.mkdirSync(path.dirname(evidencePath), { recursive: true });
  writeJson(evidencePath, {
    type: "tsl.integration_evidence.cli_sidecar_v2_smoke.v1",
    status: "passed",
    generated_at: new Date().toISOString(),
    cli: {
      policy_hash: policyResult.output.policy_hash,
      action_hash: actionResult.output.action_hash,
      inside_status: inside.output.status,
      outside_status: outside.output.status,
      outside_error_code: outsideResult?.error_code
    },
    sidecar: {
      inside_status: "agent_inside_scope"
    }
  });
  process.stdout.write(`${JSON.stringify({ ok: true, evidence: evidencePath }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
  process.exitCode = 1;
});
