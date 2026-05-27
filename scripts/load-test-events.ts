import { canonicalBytes } from "../packages/core-ts/src/canonicalize";
import {
  commitmentHashFromParts,
  DOMAIN_TAGS,
  hashDomain,
  sha256Hex,
  ZERO_HASH
} from "../packages/core-ts/src/crypto";
import { buildIdentityFromSeed, signMessageEvent } from "../packages/core-ts/src/commitments";
import { buildMerkleTree, verifyInclusion } from "../packages/core-ts/src/merkle";
import { createPostgresRepositoryFromEnv } from "../packages/core-ts/src/persistence/postgres";
import { checkpointHash, shardForTrustID } from "../packages/core-ts/src/relayStore";
import type { BatchCheckpointV1, EventCommitmentV1, Hex32, HexSig, InclusionProofStep, InclusionProofV1, TreeKind } from "../packages/core-ts/src/types";

const count = Number(process.env.TSL_LOAD_TEST_COUNT ?? process.argv[2] ?? 1000);
const requestedSamples = Number(process.env.TSL_LOAD_TEST_SAMPLES ?? 100);
const sampleEvery = Math.max(1, Math.floor(count / requestedSamples));
const batchSize = Number(process.env.TSL_LOAD_TEST_BATCH_SIZE ?? 2000);
const strictSigning = process.env.TSL_LOAD_TEST_SIGN === "1";
const seedHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const runId = process.env.TSL_LOAD_TEST_RUN_ID ?? `${Date.now().toString(36)}`;
const trustId = process.env.TSL_LOAD_TEST_TRUST_ID ?? `did:tsl:load:${runId}`;
const keyId = "#load-key-1";
const relayId = "did:tsl:relay:load";
const epochDurationMs = 300000;
const epochStartMs = Math.floor(Date.now() / epochDurationMs) * epochDurationMs;
const eventTimestamp = new Date(epochStartMs + 1000).toISOString();
const shard = shardForTrustID(trustId);

const repo = createPostgresRepositoryFromEnv();
if (!repo) throw new Error("TSL_DATABASE_URL is required for load test");

function syntheticSignature(index: number): HexSig {
  const left = sha256Hex(`tsl-load-signature:${runId}:${index}`).slice(2);
  const right = sha256Hex(`tsl-load-signature:${runId}:${index}:right`).slice(2);
  return `0x${left}${right}` as HexSig;
}

function buildFastSyntheticEvent(index: number): { envelope: EventCommitmentV1; commitment_hash: Hex32 } {
  const unsignedEvent = {
    type: "tsl.event_commitment.v1",
    event_class: "message",
    sender: trustId,
    signing_key_id: keyId,
    content_commitment: hashDomain(DOMAIN_TAGS.CONTENT_V1, `load-test:${runId}:${index}`),
    timestamp: eventTimestamp,
    nonce: `0x${index.toString(16).padStart(64, "0")}` as Hex32,
    disclosure_policy: "commitment_only"
  } as const;
  const eventHash = hashDomain(DOMAIN_TAGS.EVENT_V1, canonicalBytes(unsignedEvent));
  const envelope = {
    ...unsignedEvent,
    signature: syntheticSignature(index)
  };
  return {
    envelope,
    commitment_hash: commitmentHashFromParts(eventHash, envelope.signature)
  };
}

function buildLoadEvent(index: number): { envelope: EventCommitmentV1; commitment_hash: Hex32 } {
  if (!strictSigning) return buildFastSyntheticEvent(index);
  const signed = signMessageEvent({
    sender: trustId,
    signing_key_id: keyId,
    seed_hex: seedHex,
    message: `load-test-${runId}-${index}`,
    timestamp: eventTimestamp,
    nonce: `0x${index.toString(16).padStart(64, "0")}` as Hex32
  });
  return { envelope: signed.envelope, commitment_hash: signed.commitment_hash };
}

function buildProofFromTree(input: {
  tree: ReturnType<typeof buildMerkleTree>;
  commitments: Hex32[];
  leaf_index: number;
  tree_kind: TreeKind;
  epoch_start_ms: number;
  epoch_duration_ms: number;
  shard: string;
  checkpoint_hash: Hex32;
}): InclusionProofV1 {
  const path: InclusionProofStep[] = [];
  let index = input.leaf_index;
  for (const level of input.tree.levels.slice(0, -1)) {
    const isRight = index % 2 === 1;
    const siblingIndex = isRight ? index - 1 : index + 1;
    const sibling = level[siblingIndex];
    if (sibling) {
      path.push({ side: isRight ? "left" : "right", hash: sibling });
    }
    index = Math.floor(index / 2);
  }
  return {
    type: "tsl.inclusion_proof.v1",
    tree_kind: input.tree_kind,
    commitment: input.commitments[input.leaf_index],
    leaf_index: input.leaf_index,
    leaf_hash: input.tree.leaves[input.leaf_index],
    root: input.tree.root,
    epoch_start_ms: input.epoch_start_ms,
    epoch_duration_ms: input.epoch_duration_ms,
    shard: input.shard,
    path,
    checkpoint_hash: input.checkpoint_hash
  };
}

async function insertBatch(startIndex: number, events: Array<{ envelope: EventCommitmentV1; commitment_hash: Hex32; log_index: number }>): Promise<void> {
  const columns = [
    "commitment_hash",
    "sender_trust_id",
    "signing_key_id",
    "event_class",
    "content_commitment",
    "receiver_commitment",
    "metadata_commitment",
    "previous_event_commitment",
    "event_timestamp",
    "nonce",
    "disclosure_policy",
    "canonical_body",
    "signature",
    "relay_id",
    "shard",
    "epoch_start_ms",
    "log_index"
  ];
  const values: unknown[] = [];
  const placeholders = events.map((event, rowIndex) => {
    const base = rowIndex * columns.length;
    values.push(
      event.commitment_hash,
      event.envelope.sender,
      event.envelope.signing_key_id,
      event.envelope.event_class,
      event.envelope.content_commitment,
      event.envelope.receiver_commitment ?? null,
      event.envelope.metadata_commitment ?? null,
      event.envelope.previous_event_commitment ?? null,
      event.envelope.timestamp,
      event.envelope.nonce,
      event.envelope.disclosure_policy,
      Buffer.from(canonicalBytes(event.envelope)),
      event.envelope.signature,
      relayId,
      shard,
      epochStartMs,
      event.log_index
    );
    return `(${columns.map((_, columnIndex) => `$${base + columnIndex + 1}`).join(",")})`;
  });

  await repo.pool.query(
    `INSERT INTO event_commitments(${columns.join(",")})
     VALUES ${placeholders.join(",")}
     ON CONFLICT (commitment_hash) DO NOTHING`,
    values
  );

  if ((startIndex + events.length) % Math.max(batchSize * 10, 100000) === 0 || startIndex + events.length === count) {
    process.stderr.write(`inserted ${startIndex + events.length}/${count}\n`);
  }
}

await repo.migrate();
await repo.upsertIdentity(buildIdentityFromSeed({ trust_id: trustId, key_id: keyId, seed_hex: seedHex }));

const startedAt = Date.now();
const commitments: Hex32[] = new Array(count);
const sampleIndexes: number[] = [];
let batch: Array<{ envelope: EventCommitmentV1; commitment_hash: Hex32; log_index: number }> = [];

for (let index = 0; index < count; index += 1) {
  const event = buildLoadEvent(index);
  commitments[index] = event.commitment_hash;
  batch.push({ ...event, log_index: index });
  if (index % sampleEvery === 0) sampleIndexes.push(index);
  if (batch.length >= batchSize) {
    await insertBatch(index - batch.length + 1, batch);
    batch = [];
  }
}
if (batch.length > 0) {
  await insertBatch(count - batch.length, batch);
}

const treeStartedAt = Date.now();
const tree = buildMerkleTree(commitments);
const checkpoint: BatchCheckpointV1 = {
  type: "tsl.batch_checkpoint.v1",
  epoch_start_ms: epochStartMs,
  epoch_duration_ms: epochDurationMs,
  shard,
  event_root: tree.root,
  receipt_root: ZERO_HASH,
  attestation_root: ZERO_HASH,
  revocation_root: ZERO_HASH,
  event_count: count,
  receipt_count: 0,
  previous_checkpoint: ZERO_HASH,
  relay_id: relayId,
  relay_signature: "0x01"
};
await repo.insertCheckpoint(checkpoint);

let verifiedSamples = 0;
for (const index of sampleIndexes) {
  const proof = buildProofFromTree({
    tree,
    commitments,
    leaf_index: index,
    tree_kind: "event",
    epoch_start_ms: epochStartMs,
    epoch_duration_ms: epochDurationMs,
    shard,
    checkpoint_hash: checkpointHash(checkpoint)
  });
  if (verifyInclusion(proof)) verifiedSamples += 1;
}

const dbCount = await repo.pool.query(
  "SELECT count(*)::bigint AS count FROM event_commitments WHERE epoch_start_ms = $1 AND shard = $2",
  [epochStartMs, shard]
);
const sampledDbRows = await repo.pool.query(
  "SELECT count(*)::bigint AS count FROM event_commitments WHERE epoch_start_ms = $1 AND shard = $2 AND log_index = ANY($3)",
  [epochStartMs, shard, sampleIndexes]
);
await repo.close();

process.stdout.write(
  JSON.stringify(
    {
      count,
      db_count: Number(dbCount.rows[0].count),
      samples: sampleIndexes.length,
      sampled_db_rows: Number(sampledDbRows.rows[0].count),
      verified_samples: verifiedSamples,
      strict_signing: strictSigning,
      batch_size: batchSize,
      shard,
      epoch_start_ms: epochStartMs,
      checkpoint,
      insert_seconds: Number(((treeStartedAt - startedAt) / 1000).toFixed(3)),
      merkle_and_verify_seconds: Number(((Date.now() - treeStartedAt) / 1000).toFixed(3))
    },
    null,
    2
  ) + "\n"
);
