import { afterEach, describe, expect, it } from "vitest";
import type express from "express";
import type { Server } from "node:http";
import { createVerifierApi } from "./verifier-api/src/index";
import { GossipPeerError, normalizeGossipPeerUrl, registerRequestedGossipPeer, selectKnownGossipPeers } from "./shared/gossip-peers";

const savedEnv = {
  TSL_HTTP_RATE_LIMIT_MAX: process.env.TSL_HTTP_RATE_LIMIT_MAX,
  TSL_HTTP_RATE_LIMIT_WINDOW_MS: process.env.TSL_HTTP_RATE_LIMIT_WINDOW_MS,
  TSL_ALLOW_DYNAMIC_GOSSIP_PEERS: process.env.TSL_ALLOW_DYNAMIC_GOSSIP_PEERS,
  TSL_ALLOW_PRIVATE_GOSSIP_PEERS: process.env.TSL_ALLOW_PRIVATE_GOSSIP_PEERS
};

afterEach(() => {
  restoreEnv("TSL_HTTP_RATE_LIMIT_MAX", savedEnv.TSL_HTTP_RATE_LIMIT_MAX);
  restoreEnv("TSL_HTTP_RATE_LIMIT_WINDOW_MS", savedEnv.TSL_HTTP_RATE_LIMIT_WINDOW_MS);
  restoreEnv("TSL_ALLOW_DYNAMIC_GOSSIP_PEERS", savedEnv.TSL_ALLOW_DYNAMIC_GOSSIP_PEERS);
  restoreEnv("TSL_ALLOW_PRIVATE_GOSSIP_PEERS", savedEnv.TSL_ALLOW_PRIVATE_GOSSIP_PEERS);
});

describe("public API security hardening", () => {
  it("applies HTTP rate limiting to verifier API routes", async () => {
    process.env.TSL_HTTP_RATE_LIMIT_MAX = "1";
    process.env.TSL_HTTP_RATE_LIMIT_WINDOW_MS = "60000";
    const server = await listen(createVerifierApi());
    try {
      expect((await fetch(`${server.base}/health`)).status).toBe(200);
      expect((await fetch(`${server.base}/health`)).status).toBe(429);
    } finally {
      await server.close();
    }
  });

  it("rejects unregistered or unsafe gossip peer URLs", () => {
    expect(selectKnownGossipPeers(undefined, ["https://peer.example/"])).toEqual(["https://peer.example"]);
    expect(() => selectKnownGossipPeers("https://evil.example", ["https://peer.example"])).toThrow(GossipPeerError);
    expect(() => registerRequestedGossipPeer("https://peer.example")).toThrow(/Dynamic gossip peer registration is disabled/);
    expect(() => normalizeGossipPeerUrl("http://127.0.0.1:8080", { allowPrivateHosts: false })).toThrow(/host must be public/);
    expect(() => normalizeGossipPeerUrl("http://[::ffff:127.0.0.1]:8080", { allowPrivateHosts: false })).toThrow(/host must be public/);
    expect(() => normalizeGossipPeerUrl("http://[::]:8080", { allowPrivateHosts: false })).toThrow(/host must be public/);
  });
});

async function listen(app: express.Express): Promise<{ base: string; close: () => Promise<void> }> {
  const server: Server = app.listen(0);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("test server did not bind to a TCP address");
  return {
    base: `http://127.0.0.1:${address.port}`,
    close: () => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()))
  };
}

function restoreEnv(key: keyof typeof savedEnv, value: string | undefined): void {
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
}
