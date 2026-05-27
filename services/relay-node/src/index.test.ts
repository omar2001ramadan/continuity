import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import {
  buildIdentityFromSeed,
  signMessageEvent,
  signReceiptCommitment
} from "../../../packages/core-ts/src/index";
import { createRelayNode } from "./index";

const seedHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const trustId = "did:tsl:test:relay";
const keyId = "#test-key-1";

describe("relay-node validation", () => {
  let server: Server;
  let baseUrl: string;

  beforeEach(async () => {
    delete process.env.TSL_DATABASE_URL;
    delete process.env.DATABASE_URL;
    process.env.TSL_TIMESTAMP_WINDOW_MS = String(Number.MAX_SAFE_INTEGER);
    const app = createRelayNode().app;
    server = createServer(app);
    await new Promise<void>((resolve) => server.listen(0, resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("No server address");
    baseUrl = `http://127.0.0.1:${address.port}`;
  });

  afterEach(async () => {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  });

  it("rejects malformed receipt signatures after accepting a valid event", async () => {
    const identity = buildIdentityFromSeed({ trust_id: trustId, key_id: keyId, seed_hex: seedHex });
    await post("/v1/identity/create", { identity });
    const signed = signMessageEvent({ sender: trustId, signing_key_id: keyId, seed_hex: seedHex, message: "relay-test" });
    await post("/v1/commitments", { event: signed.envelope });
    const receipt = signReceiptCommitment({
      event_commitment: signed.commitment_hash,
      receiver: trustId,
      signing_key_id: keyId,
      receipt_class: "received",
      seed_hex: seedHex
    }).receipt;

    const response = await fetch(`${baseUrl}/v1/receipts`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ receipt: { ...receipt, signature: "0x00" } })
    });
    const body = await response.json() as { error?: { code: string } };

    expect(response.status).toBe(422);
    expect(body.error?.code).toBe("TSL_RECEIPT_SIGNATURE_INVALID");
  });

  async function post(path: string, body: unknown): Promise<unknown> {
    const response = await fetch(`${baseUrl}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body)
    });
    if (!response.ok) throw new Error(await response.text());
    return response.json();
  }
});
