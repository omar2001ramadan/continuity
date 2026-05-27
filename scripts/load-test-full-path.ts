import {
  buildIdentityFromSeed,
  signMessageEvent,
  shardForTrustID,
  verifyInclusion,
  type Hex32,
  type InclusionProofV1
} from "../packages/core-ts/src/index";

const count = Number(process.env.TSL_FULL_PATH_COUNT ?? process.argv[2] ?? 100);
const samples = Number(process.env.TSL_FULL_PATH_SAMPLES ?? 10);
const concurrency = Number(process.env.TSL_FULL_PATH_CONCURRENCY ?? 25);
const maxRetries = Number(process.env.TSL_FULL_PATH_RETRIES ?? 3);
const fastUnsafe = process.env.TSL_LOAD_TEST_FAST_UNSAFE === "1";
const relayUrl = (process.env.TSL_RELAY_URL ?? "http://127.0.0.1:8080").replace(/\/$/, "");
const logUrl = (process.env.TSL_LOG_URL ?? "http://127.0.0.1:8081").replace(/\/$/, "");
const seedHex = process.env.TSL_FULL_PATH_SEED_HEX ?? "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const runId = process.env.TSL_FULL_PATH_RUN_ID ?? `${Date.now().toString(36)}`;
const trustId = process.env.TSL_FULL_PATH_TRUST_ID ?? `did:tsl:fullpath:${runId}`;
const keyId = "#full-path-key-1";
const epochDurationMs = Number(process.env.TSL_EPOCH_MS ?? 300000);
const epochStartMs = Math.floor(Date.now() / epochDurationMs) * epochDurationMs;
const timestamp = new Date(epochStartMs + 1000).toISOString();
const shard = shardForTrustID(trustId);

async function withRetries<T>(fn: () => Promise<T>): Promise<T> {
  let lastError: unknown;
  for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      if (attempt === maxRetries) break;
      await new Promise((resolve) => setTimeout(resolve, 100 * (attempt + 1)));
    }
  }
  throw lastError;
}

async function postJson<T>(url: string, body: unknown): Promise<T> {
  return withRetries(async () => {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  const payload = await response.json() as T;
  if (!response.ok) throw new Error(`${response.status} ${JSON.stringify(payload)}`);
  return payload;
  });
}

async function getJson<T>(url: string): Promise<T> {
  return withRetries(async () => {
  const response = await fetch(url);
  const payload = await response.json() as T;
  if (!response.ok) throw new Error(`${response.status} ${JSON.stringify(payload)}`);
  return payload;
  });
}

async function mapLimited<T, U>(items: T[], limit: number, fn: (item: T) => Promise<U>): Promise<U[]> {
  const results: U[] = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const index = next++;
      results[index] = await fn(items[index]);
      if ((index + 1) % Math.max(1000, Math.floor(count / 10)) === 0) {
        process.stderr.write(`submitted ${index + 1}/${count}\n`);
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

const identity = buildIdentityFromSeed({
  trust_id: trustId,
  key_id: keyId,
  seed_hex: seedHex,
  created_at: new Date(epochStartMs).toISOString()
});
await postJson(`${relayUrl}/v1/identity/create`, { identity });

const indexes = Array.from({ length: count }, (_, index) => index);
const startedAt = Date.now();
const accepted = await mapLimited(indexes, concurrency, async (index) => {
  if (fastUnsafe) {
    throw new Error("TSL_LOAD_TEST_FAST_UNSAFE is not supported on the relay-validated full path; use load-test:events for direct DB profiling");
  }
  const signed = signMessageEvent({
    sender: trustId,
    signing_key_id: keyId,
    seed_hex: seedHex,
    message: `full-path-load:${runId}:${index}`,
    timestamp,
    nonce: `0x${index.toString(16).padStart(64, "0")}` as Hex32,
    disclosure_policy: "commitment_only"
  });
  const response = await postJson<{
    status: string;
    commitment_hash: Hex32;
    epoch_start_ms: number;
    shard: string;
  }>(`${relayUrl}/v1/commitments`, { event: signed.envelope });
  return { ...response, envelope: signed.envelope };
});

let consumed = 0;
for (let attempt = 0; attempt < 200 && consumed < count; attempt += 1) {
  const response = await postJson<{ counts: Record<string, number> }>(`${logUrl}/v1/log/consume-once`, { limit: 1000 });
  consumed += response.counts["tsl.commitments.accepted.v1"] ?? 0;
  if (consumed >= count) break;
  await new Promise((resolve) => setTimeout(resolve, 100));
}

const checkpointResponse = await postJson<{ checkpoint: unknown }>(`${logUrl}/v1/log/close-epoch`, {
  epoch_start_ms: epochStartMs,
  epoch_duration_ms: epochDurationMs,
  shard
});

const sampleEvery = Math.max(1, Math.floor(count / samples));
const sampleIndexes = indexes.filter((index) => index % sampleEvery === 0).slice(0, samples);
let verifiedSamples = 0;
for (const index of sampleIndexes) {
  const proofPayload = await getJson<InclusionProofV1 | { proof: InclusionProofV1 }>(`${logUrl}/v1/proofs/event/${accepted[index].commitment_hash}`);
  const proof = "proof" in proofPayload ? proofPayload.proof : proofPayload;
  if (verifyInclusion(proof)) verifiedSamples += 1;
}

let metrics: unknown = null;
try {
  metrics = await getJson(`${logUrl}/v1/log/metrics`);
} catch {
  metrics = null;
}
const deadLetterTotal = metrics && typeof metrics === "object" && "dead_letter_lengths" in metrics
  ? Object.values((metrics as { dead_letter_lengths: Record<string, number> }).dead_letter_lengths).reduce((sum, value) => sum + Number(value), 0)
  : null;

if (deadLetterTotal !== null && deadLetterTotal > 0) {
  throw new Error(`Full-path load test produced ${deadLetterTotal} dead-letter messages`);
}

process.stdout.write(
  JSON.stringify(
    {
      count,
      accepted: accepted.length,
      consumed,
      samples: sampleIndexes.length,
      verified_samples: verifiedSamples,
      relay_url: relayUrl,
      log_url: logUrl,
      shard,
      epoch_start_ms: epochStartMs,
      checkpoint: checkpointResponse.checkpoint,
      metrics,
      dead_letter_total: deadLetterTotal,
      retries: maxRetries,
      fast_unsafe: fastUnsafe,
      seconds: Number(((Date.now() - startedAt) / 1000).toFixed(3))
    },
    null,
    2
  ) + "\n"
);
