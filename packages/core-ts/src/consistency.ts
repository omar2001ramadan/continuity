import { canonicalBytes } from "./canonicalize";
import { DOMAIN_TAGS, hashDomain } from "./crypto";
import type { BatchCheckpointV1, ConsistencyProofV1, Hex32 } from "./types";
import { checkpointHash } from "./relayStore";

export function buildConsistencyProof(checkpoints: BatchCheckpointV1[]): ConsistencyProofV1 {
  if (checkpoints.length < 2) throw new Error("TSL_CONSISTENCY_CHAIN_TOO_SHORT");
  const ordered = [...checkpoints].sort((a, b) => a.epoch_start_ms - b.epoch_start_ms);
  const shard = ordered[0].shard;
  if (!ordered.every((checkpoint) => checkpoint.shard === shard)) throw new Error("TSL_CONSISTENCY_SHARD_MISMATCH");
  return {
    type: "tsl.consistency_proof.v1",
    shard,
    from_checkpoint: checkpointHash(ordered[0]),
    to_checkpoint: checkpointHash(ordered.at(-1)!),
    chain: ordered.map((checkpoint) => ({
      checkpoint_hash: checkpointHash(checkpoint),
      previous_checkpoint: checkpoint.previous_checkpoint,
      epoch_start_ms: checkpoint.epoch_start_ms
    }))
  };
}

export function consistencyProofHash(proof: ConsistencyProofV1): Hex32 {
  const payload = { ...(proof as unknown as Record<string, unknown>) };
  delete payload.signature;
  return hashDomain(DOMAIN_TAGS.CONSISTENCY_PROOF_V1, canonicalBytes(payload));
}

export function verifyConsistencyProof(proof: ConsistencyProofV1): boolean {
  if (proof.type !== "tsl.consistency_proof.v1") return false;
  if (proof.chain.length < 2) return false;
  if (proof.chain[0].checkpoint_hash !== proof.from_checkpoint) return false;
  if (proof.chain.at(-1)?.checkpoint_hash !== proof.to_checkpoint) return false;
  for (let i = 1; i < proof.chain.length; i += 1) {
    if (proof.chain[i].previous_checkpoint !== proof.chain[i - 1].checkpoint_hash) return false;
    if (proof.chain[i].epoch_start_ms <= proof.chain[i - 1].epoch_start_ms) return false;
  }
  return true;
}

