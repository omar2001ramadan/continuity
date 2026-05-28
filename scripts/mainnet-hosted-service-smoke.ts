import fs from "node:fs";
import path from "node:path";
import {
  buildIdentityFromSeed,
  sha256Hex,
  signMessageEvent,
  type IdentityDocumentV1
} from "../packages/core-ts/src/index";
import { createRelayNode } from "../services/relay-node/src/index";
import { createVerifierApi } from "../services/verifier-api/src/index";
import { createScoringProvider } from "../services/scoring-provider/src/index";

const evidencePath = path.join("evidence", "integration", "hosted-service-smoke.json");
const seedHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const providerSeedHex = "1111111111111111111111111111111111111111111111111111111111111111";
const relaySeedHex = "2222222222222222222222222222222222222222222222222222222222222222";

function requireDatabase(): void {
  if (!process.env.TSL_TEST_DATABASE_URL) {
    throw new Error("TSL_TEST_DATABASE_URL is required for the hosted service mainnet-readiness smoke");
  }
  process.env.TSL_DATABASE_URL = process.env.TSL_TEST_DATABASE_URL;
  process.env.TSL_TIMESTAMP_WINDOW_MS = process.env.TSL_TIMESTAMP_WINDOW_MS ?? String(Number.MAX_SAFE_INTEGER);
  if (!process.env.TSL_SCORING_PROVIDER_SEED_HEX) process.env.TSL_SCORING_PROVIDER_SEED_HEX = providerSeedHex;
  if (!process.env.TSL_SCORING_PROVIDER_ID) process.env.TSL_SCORING_PROVIDER_ID = "did:tsl:provider:hosted-smoke";
  if (!process.env.TSL_RELAY_ID) process.env.TSL_RELAY_ID = "did:tsl:relay:hosted-smoke";
  if (!process.env.TSL_RELAY_SIGNING_KEY_ID) process.env.TSL_RELAY_SIGNING_KEY_ID = "#relay-checkpoint";
  if (!process.env.TSL_RELAY_SIGNING_SEED_HEX) process.env.TSL_RELAY_SIGNING_SEED_HEX = relaySeedHex;
  if (process.env.HOSTED_SMOKE_ENABLE_SETTLEMENT !== "true") {
    process.env.TSL_CHECKPOINT_REGISTRY_ADDRESS = "";
    process.env.TSL_TRUST_ID_REGISTRY_ADDRESS = "";
    process.env.TSL_REVOCATION_REGISTRY_ADDRESS = "";
    process.env.TSL_PROVIDER_REGISTRY_ADDRESS = "";
  }
}

async function postJson(base: string, pathName: string, body: unknown): Promise<Record<string, unknown>> {
  const response = await fetch(`${base}${pathName}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  const payload = await response.json() as Record<string, unknown>;
  if (!response.ok) throw new Error(`${pathName} failed: ${JSON.stringify(payload)}`);
  return payload;
}

async function getJson(base: string, pathName: string): Promise<Record<string, unknown>> {
  const response = await fetch(`${base}${pathName}`);
  const payload = await response.json() as Record<string, unknown>;
  if (!response.ok) throw new Error(`${pathName} failed: ${JSON.stringify(payload)}`);
  return payload;
}

function listen(app: ReturnType<typeof createVerifierApi>): Promise<{ base: string; close: () => Promise<void> }> {
  const server = app.listen(0);
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.once("listening", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("Could not bind service"));
        return;
      }
      resolve({
        base: `http://127.0.0.1:${address.port}`,
        close: () => new Promise<void>((done, fail) => server.close((error) => error ? fail(error) : done()))
      });
    });
  });
}

async function main(): Promise<void> {
  requireDatabase();
  const relay = await listen(createRelayNode().app);
  const verifier = await listen(createVerifierApi());
  const scoring = await listen(createScoringProvider());
  const runId = `hosted-smoke-${Date.now()}`;
  const now = new Date().toISOString();
  const trustId = `did:tsl:hosted-smoke:${runId}`;
  const identity: IdentityDocumentV1 = buildIdentityFromSeed({ trust_id: trustId, key_id: "#key-1", seed_hex: seedHex, created_at: now });
  try {
    await postJson(relay.base, "/v1/identity/create", { identity });
    const signed = signMessageEvent({
      sender: trustId,
      signing_key_id: "#key-1",
      seed_hex: seedHex,
      message: "hosted-service-mainnet-readiness-smoke",
      timestamp: now,
      nonce: sha256Hex(new TextEncoder().encode(`${runId}:nonce`))
    });
    await postJson(relay.base, "/v1/commitments", { event: signed.envelope });
    const proofPayload = await getJson(relay.base, `/v1/proofs/${signed.commitment_hash}`);
    const proof = (proofPayload.proof ?? proofPayload) as Record<string, unknown>;
    const checkpoint = proofPayload.checkpoint as Record<string, unknown>;
    const verification = await postJson(verifier.base, "/v1/verify", {
      identity,
      envelope: signed.envelope,
      proof,
      checkpoint,
      policy: { require_inclusion: true, require_checkpoint: true, require_settlement: false }
    });
    if (verification.verified !== true) throw new Error(`Hosted verifier did not verify: ${JSON.stringify(verification)}`);
    const assessment = await postJson(scoring.base, "/v1/assessments/v2", {
      identity,
      envelope: signed.envelope,
      proof,
      checkpoint,
      subject: trustId,
      domain: "local_verifier",
      min_coverage_bps: 0,
      valid_signed_event_count: 1,
      provider_governance_status: {
        type: "tsl.provider_governance_status.v1",
        provider: process.env.TSL_SCORING_PROVIDER_ID,
        status: "active",
        model_registered: true,
        evaluation_report_commitment: sha256Hex(new TextEncoder().encode(`${runId}:evaluation-report`)),
        red_team_result: "pass",
        privacy_leakage_bps: 0,
        promotion_gate_result: "pass",
        issued_at: now
      }
    });
    fs.mkdirSync(path.dirname(evidencePath), { recursive: true });
    fs.writeFileSync(
      evidencePath,
      `${JSON.stringify(
        {
          type: "tsl.integration_evidence.hosted_service_smoke.v1",
          status: "passed",
          run_id: runId,
          generated_at: new Date().toISOString(),
          services: {
            relay: relay.base,
            verifier: verifier.base,
            scoring_provider: scoring.base
          },
          trust_id: trustId,
          commitment: signed.commitment_hash,
          verification: { verified: verification.verified, checks: verification.checks },
          assessment: { status: assessment.status, assessment_id: (assessment.assessment as { assessment_id?: string } | undefined)?.assessment_id }
        },
        null,
        2
      )}\n`
    );
    process.stdout.write(`${JSON.stringify({ ok: true, evidence: evidencePath, run_id: runId }, null, 2)}\n`);
  } finally {
    await scoring.close();
    await verifier.close();
    await relay.close();
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
    process.exit(1);
  });
