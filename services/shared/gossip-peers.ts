import { isIP } from "node:net";

export class GossipPeerError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status = 400
  ) {
    super(message);
  }
}

export function initialGossipPeers(): Set<string> {
  return new Set(
    (process.env.TSL_GOSSIP_PEERS ?? "")
      .split(",")
      .map((peer) => peer.trim())
      .filter(Boolean)
      .map((peer) => normalizeGossipPeerUrl(peer, { allowPrivateHosts: allowPrivateGossipPeers() }))
  );
}

export function listNormalizedGossipPeers(peers: Iterable<string>): string[] {
  return [...new Set([...peers].map((peer) => normalizeGossipPeerUrl(peer, { allowPrivateHosts: allowPrivateGossipPeers() })))];
}

export function selectKnownGossipPeers(peerUrl: unknown, knownPeers: Iterable<string>): string[] {
  const normalizedKnownPeers = listNormalizedGossipPeers(knownPeers);
  if (peerUrl === undefined || peerUrl === null || peerUrl === "") return normalizedKnownPeers;
  const requested = normalizeGossipPeerUrl(peerUrl, { allowPrivateHosts: allowPrivateGossipPeers() });
  const matched = normalizedKnownPeers.find((peer) => peer === requested);
  if (!matched) {
    throw new GossipPeerError("TSL_GOSSIP_PEER_NOT_REGISTERED", "peer_url must match a configured or registered gossip peer", 403);
  }
  return [matched];
}

export function registerRequestedGossipPeer(peerUrl: unknown): string {
  if (process.env.TSL_ALLOW_DYNAMIC_GOSSIP_PEERS !== "true") {
    throw new GossipPeerError("TSL_GOSSIP_DYNAMIC_PEERS_DISABLED", "Dynamic gossip peer registration is disabled", 403);
  }
  return normalizeGossipPeerUrl(peerUrl, { allowPrivateHosts: allowPrivateGossipPeers() });
}

export function buildGossipUrl(peerUrl: string, pathname: string): URL {
  const url = new URL(normalizeGossipPeerUrl(peerUrl, { allowPrivateHosts: allowPrivateGossipPeers() }));
  url.pathname = pathname.startsWith("/") ? pathname : `/${pathname}`;
  url.search = "";
  url.hash = "";
  return url;
}

export function normalizeGossipPeerUrl(peerUrl: unknown, options: { allowPrivateHosts: boolean }): string {
  if (typeof peerUrl !== "string") {
    throw new GossipPeerError("TSL_GOSSIP_PEER_URL_INVALID", "Gossip peer URL must be a string");
  }
  let url: URL;
  try {
    url = new URL(peerUrl);
  } catch {
    throw new GossipPeerError("TSL_GOSSIP_PEER_URL_INVALID", "Gossip peer URL is not parseable");
  }
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new GossipPeerError("TSL_GOSSIP_PEER_URL_INVALID", "Gossip peer URL must use http or https");
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new GossipPeerError("TSL_GOSSIP_PEER_URL_INVALID", "Gossip peer URL must not include credentials, query, or fragment");
  }
  if (!options.allowPrivateHosts && privateOrLocalHost(url.hostname)) {
    throw new GossipPeerError("TSL_GOSSIP_PEER_URL_INVALID", "Gossip peer URL host must be public unless private gossip peers are explicitly enabled");
  }
  return url.origin;
}

function allowPrivateGossipPeers(): boolean {
  return process.env.TSL_ALLOW_PRIVATE_GOSSIP_PEERS === "true";
}

function privateOrLocalHost(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  const ipVersion = isIP(host);
  if (ipVersion === 4) {
    const octets = host.split(".").map(Number);
    const [a, b] = octets;
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      a >= 224
    );
  }
  if (ipVersion === 6) {
    return host === "::1" || host === "::" || host.startsWith("::ffff:") || host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe80:");
  }
  return false;
}
