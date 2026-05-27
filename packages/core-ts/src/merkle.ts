import { DOMAIN_TAGS, ZERO_HASH, concatBytes, hashDomain, hexToBytes, uint64be } from "./crypto";
import type { Hex32, InclusionProofStep, InclusionProofV1, TreeKind } from "./types";

export interface MerkleTree {
  leaves: Hex32[];
  levels: Hex32[][];
  root: Hex32;
}

export function hashLeaf(index: number, commitment: Hex32): Hex32 {
  return hashDomain(DOMAIN_TAGS.MERKLE_LEAF_V1, concatBytes(uint64be(index), hexToBytes(commitment)));
}

export function hashNode(left: Hex32, right: Hex32): Hex32 {
  return hashDomain(DOMAIN_TAGS.MERKLE_NODE_V1, concatBytes(hexToBytes(left), hexToBytes(right)));
}

export function buildMerkleTree(commitments: Hex32[]): MerkleTree {
  if (commitments.length === 0) {
    return { leaves: [], levels: [[]], root: ZERO_HASH };
  }

  const leaves = commitments.map((commitment, index) => hashLeaf(index, commitment));
  const levels: Hex32[][] = [leaves];
  let current = leaves;

  while (current.length > 1) {
    const next: Hex32[] = [];
    for (let index = 0; index < current.length; index += 2) {
      const left = current[index];
      const right = current[index + 1];
      next.push(right ? hashNode(left, right) : left);
    }
    levels.push(next);
    current = next;
  }

  return { leaves, levels, root: current[0] };
}

export function buildInclusionProof(input: {
  commitments: Hex32[];
  leaf_index: number;
  tree_kind: TreeKind;
  epoch_start_ms: number;
  epoch_duration_ms: number;
  shard: string;
  checkpoint_hash?: Hex32;
}): InclusionProofV1 {
  const tree = buildMerkleTree(input.commitments);
  const commitment = input.commitments[input.leaf_index];
  if (!commitment) {
    throw new Error("Cannot build inclusion proof for missing leaf");
  }

  const path: InclusionProofStep[] = [];
  let index = input.leaf_index;

  for (const level of tree.levels.slice(0, -1)) {
    const isRight = index % 2 === 1;
    const siblingIndex = isRight ? index - 1 : index + 1;
    const sibling = level[siblingIndex];
    if (sibling) {
      path.push({
        side: isRight ? "left" : "right",
        hash: sibling
      });
    }
    index = Math.floor(index / 2);
  }

  return {
    type: "tsl.inclusion_proof.v1",
    tree_kind: input.tree_kind,
    commitment,
    leaf_index: input.leaf_index,
    leaf_hash: tree.leaves[input.leaf_index],
    root: tree.root,
    epoch_start_ms: input.epoch_start_ms,
    epoch_duration_ms: input.epoch_duration_ms,
    shard: input.shard,
    path,
    checkpoint_hash: input.checkpoint_hash ?? ZERO_HASH
  };
}

export function verifyInclusion(proof: InclusionProofV1): boolean {
  let current = hashLeaf(proof.leaf_index, proof.commitment);
  if (current !== proof.leaf_hash) return false;

  for (const step of proof.path) {
    if (step.side === "left") {
      current = hashNode(step.hash, current);
    } else if (step.side === "right") {
      current = hashNode(current, step.hash);
    } else {
      return false;
    }
  }

  return current === proof.root;
}
