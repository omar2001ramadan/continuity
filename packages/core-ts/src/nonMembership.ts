import { canonicalBytes } from "./canonicalize";
import { DOMAIN_TAGS, hashDomain } from "./crypto";
import type { Hex32, SetNonMembershipProofV1, TrustID } from "./types";

export function buildSetRoot(values: Hex32[]): Hex32 {
  return hashDomain(DOMAIN_TAGS.NON_MEMBERSHIP_PROOF_V1, canonicalBytes([...values].sort()));
}

export interface SparseMerkleProfileV1 {
  tree_id: string;
  tree_depth: number;
}

export interface SparseMerkleTreeV1 {
  profile: SparseMerkleProfileV1;
  root: Hex32;
  leaves: Map<number, Hex32>;
  zero_hashes: Hex32[];
}

function sparseHash(label: string, value: unknown): Hex32 {
  return hashDomain(DOMAIN_TAGS.NON_MEMBERSHIP_PROOF_V1, canonicalBytes({ label, value }));
}

function sparseMerkleZeroHashes(depth: number): Hex32[] {
  const zeroes: Hex32[] = [sparseHash("zero-leaf", 0)];
  for (let level = 1; level <= depth; level += 1) {
    zeroes[level] = sparseHash("node", { left: zeroes[level - 1], right: zeroes[level - 1] });
  }
  return zeroes;
}

function sparseMerkleLeaf(value: Hex32): Hex32 {
  return sparseHash("leaf", value);
}

function sparseMerkleNode(left: Hex32, right: Hex32): Hex32 {
  return sparseHash("node", { left, right });
}

function sparseMerkleIndex(value: Hex32, depth: number): number {
  if (!Number.isSafeInteger(depth) || depth < 1 || depth > 30) throw new Error("TSL_SPARSE_MERKLE_DEPTH_INVALID");
  const digest = BigInt(value);
  return Number(digest & ((1n << BigInt(depth)) - 1n));
}

function sparseMerkleRootFromLeaves(leaves: Map<number, Hex32>, depth: number, zeroes: Hex32[]): Hex32 {
  let current = new Map<number, Hex32>([...leaves.entries()].map(([index, value]) => [index, sparseMerkleLeaf(value)]));
  for (let level = 0; level < depth; level += 1) {
    const next = new Map<number, Hex32>();
    const parents = new Set([...current.keys()].map((index) => Math.floor(index / 2)));
    for (const parent of [...parents].sort((a, b) => a - b)) {
      const left = current.get(parent * 2) ?? zeroes[level];
      const right = current.get(parent * 2 + 1) ?? zeroes[level];
      const node = sparseMerkleNode(left, right);
      if (node !== zeroes[level + 1]) next.set(parent, node);
    }
    current = next;
  }
  return current.get(0) ?? zeroes[depth];
}

function sparseMerklePath(leaves: Map<number, Hex32>, index: number, depth: number, zeroes: Hex32[]): Array<{ side: "left" | "right"; hash: Hex32 }> {
  let current = new Map<number, Hex32>([...leaves.entries()].map(([leafIndex, value]) => [leafIndex, sparseMerkleLeaf(value)]));
  let cursor = index;
  const path: Array<{ side: "left" | "right"; hash: Hex32 }> = [];
  for (let level = 0; level < depth; level += 1) {
    const siblingIndex = cursor % 2 === 0 ? cursor + 1 : cursor - 1;
    path.push({ side: cursor % 2 === 0 ? "right" : "left", hash: current.get(siblingIndex) ?? zeroes[level] });
    const next = new Map<number, Hex32>();
    const parents = new Set([...current.keys()].map((leafIndex) => Math.floor(leafIndex / 2)));
    for (const parent of [...parents].sort((a, b) => a - b)) {
      const left = current.get(parent * 2) ?? zeroes[level];
      const right = current.get(parent * 2 + 1) ?? zeroes[level];
      const node = sparseMerkleNode(left, right);
      if (node !== zeroes[level + 1]) next.set(parent, node);
    }
    current = next;
    cursor = Math.floor(cursor / 2);
  }
  return path;
}

export function buildSparseMerkleTree(values: Hex32[], profile: SparseMerkleProfileV1): SparseMerkleTreeV1 {
  const zeroes = sparseMerkleZeroHashes(profile.tree_depth);
  const leaves = new Map<number, Hex32>();
  for (const value of [...values].sort()) {
    const index = sparseMerkleIndex(value, profile.tree_depth);
    if (leaves.has(index) && leaves.get(index) !== value) throw new Error("TSL_SPARSE_MERKLE_INDEX_COLLISION");
    leaves.set(index, value);
  }
  return {
    profile,
    leaves,
    zero_hashes: zeroes,
    root: sparseMerkleRootFromLeaves(leaves, profile.tree_depth, zeroes)
  };
}

export function proveSparseMerkleInclusion(value: Hex32, tree: SparseMerkleTreeV1, subject: TrustID, issued_at = new Date().toISOString(), root_checkpoint?: Hex32): SetNonMembershipProofV1 {
  const index = sparseMerkleIndex(value, tree.profile.tree_depth);
  if (tree.leaves.get(index) !== value) throw new Error("TSL_SPARSE_MERKLE_VALUE_MISSING");
  const sibling_path = sparseMerklePath(tree.leaves, index, tree.profile.tree_depth, tree.zero_hashes);
  return {
    type: "tsl.zk.non_membership_proof.v1",
    claim: "revocation_set_non_membership",
    subject,
    set_root: tree.root,
    root: tree.root,
    root_checkpoint: root_checkpoint ?? sparseHash("uncheckpointed-root", { tree_id: tree.profile.tree_id, root: tree.root }),
    value_commitment: value,
    tree_id: tree.profile.tree_id,
    tree_depth: tree.profile.tree_depth,
    leaf_index: index,
    leaf_index_commitment: sparseHash("leaf-index", { tree_id: tree.profile.tree_id, index }),
    leaf_value_commitment: sparseMerkleLeaf(value),
    sibling_path,
    proof: sparseHash("sparse-merkle-inclusion-proof", { root: tree.root, value_commitment: value, leaf_index: index, tree_depth: tree.profile.tree_depth, sibling_path }),
    issued_at
  };
}

export function proveSparseMerkleNonMembership(value: Hex32, tree: SparseMerkleTreeV1, subject: TrustID, issued_at = new Date().toISOString(), root_checkpoint?: Hex32): SetNonMembershipProofV1 {
  const index = sparseMerkleIndex(value, tree.profile.tree_depth);
  if (tree.leaves.has(index)) throw new Error("TSL_NON_MEMBERSHIP_VALUE_PRESENT");
  const sibling_path = sparseMerklePath(tree.leaves, index, tree.profile.tree_depth, tree.zero_hashes);
  return {
    type: "tsl.zk.non_membership_proof.v1",
    claim: "revocation_set_non_membership",
    subject,
    set_root: tree.root,
    root: tree.root,
    root_checkpoint: root_checkpoint ?? sparseHash("uncheckpointed-root", { tree_id: tree.profile.tree_id, root: tree.root }),
    value_commitment: value,
    tree_id: tree.profile.tree_id,
    tree_depth: tree.profile.tree_depth,
    leaf_index: index,
    leaf_index_commitment: sparseHash("leaf-index", { tree_id: tree.profile.tree_id, index }),
    leaf_value_commitment: sparseMerkleLeaf(value),
    empty_leaf_commitment: tree.zero_hashes[0],
    sibling_path,
    proof: sparseHash("sparse-merkle-non-membership-proof", { root: tree.root, value_commitment: value, leaf_index: index, tree_depth: tree.profile.tree_depth, sibling_path }),
    issued_at
  };
}

export function buildNonMembershipProof(input: {
  subject: TrustID;
  value_commitment: Hex32;
  set_values: Hex32[];
  issued_at?: string;
}): SetNonMembershipProofV1 {
  const sorted = [...input.set_values].sort();
  if (sorted.includes(input.value_commitment)) throw new Error("TSL_NON_MEMBERSHIP_VALUE_PRESENT");
  const lower = sorted.filter((value) => value < input.value_commitment).at(-1);
  const upper = sorted.find((value) => value > input.value_commitment);
  const setRoot = buildSetRoot(sorted);
  return {
    type: "tsl.zk.non_membership_proof.v1",
    claim: "revocation_set_non_membership",
    subject: input.subject,
    set_root: setRoot,
    value_commitment: input.value_commitment,
    ...(lower ? { lower_neighbor: lower } : {}),
    ...(upper ? { upper_neighbor: upper } : {}),
    proof: hashDomain(DOMAIN_TAGS.NON_MEMBERSHIP_PROOF_V1, canonicalBytes({ set_root: setRoot, value_commitment: input.value_commitment, lower, upper })),
    issued_at: input.issued_at ?? new Date().toISOString()
  };
}

export function verifyNonMembershipProof(proof: SetNonMembershipProofV1): boolean {
  if (proof.type !== "tsl.zk.non_membership_proof.v1") return false;
  if (proof.claim !== "revocation_set_non_membership") return false;
  if (proof.lower_neighbor && proof.lower_neighbor >= proof.value_commitment) return false;
  if (proof.upper_neighbor && proof.upper_neighbor <= proof.value_commitment) return false;
  if (
    proof.tree_id &&
    proof.sibling_path?.length &&
    proof.leaf_index !== undefined &&
    proof.tree_depth !== undefined &&
    proof.leaf_index_commitment &&
    proof.leaf_value_commitment &&
    (proof.empty_leaf_commitment || proof.root)
  ) {
    return verifySparseMerkleProof(proof, proof.root ?? proof.set_root, { tree_id: proof.tree_id, tree_depth: proof.tree_depth });
  }
  if (!proof.sibling_path?.length || proof.leaf_index === undefined || proof.tree_depth === undefined) {
    return process.env.ALLOW_UNSAFE_NON_MEMBERSHIP_FIXTURES === "true" && proof.proof === hashDomain(
      DOMAIN_TAGS.NON_MEMBERSHIP_PROOF_V1,
      canonicalBytes({
        set_root: proof.set_root,
        value_commitment: proof.value_commitment,
        lower: proof.lower_neighbor,
        upper: proof.upper_neighbor
      })
    );
  }
  if (proof.sibling_path.length !== proof.tree_depth) return false;
  let current = hashDomain(
    DOMAIN_TAGS.NON_MEMBERSHIP_PROOF_V1,
    canonicalBytes({
      absent_leaf: proof.value_commitment,
      lower: proof.lower_neighbor,
      upper: proof.upper_neighbor,
      index: proof.leaf_index
    })
  );
  for (const step of proof.sibling_path) {
    current =
      step.side === "left"
        ? hashDomain(DOMAIN_TAGS.NON_MEMBERSHIP_PROOF_V1, canonicalBytes([step.hash, current]))
        : hashDomain(DOMAIN_TAGS.NON_MEMBERSHIP_PROOF_V1, canonicalBytes([current, step.hash]));
  }
  if (current !== proof.set_root) return false;
  const expected = hashDomain(
    DOMAIN_TAGS.NON_MEMBERSHIP_PROOF_V1,
    canonicalBytes({
      set_root: proof.set_root,
      value_commitment: proof.value_commitment,
      lower: proof.lower_neighbor,
      upper: proof.upper_neighbor,
      leaf_index: proof.leaf_index,
      tree_depth: proof.tree_depth
    })
  );
  return proof.proof === expected;
}

export function verifySparseMerkleProof(proof: SetNonMembershipProofV1, root: Hex32, profile: SparseMerkleProfileV1): boolean {
  if (proof.tree_id !== profile.tree_id || proof.tree_depth !== profile.tree_depth) return false;
  if (proof.root && proof.root !== root) return false;
  if (proof.set_root !== root) return false;
  if (proof.leaf_index === undefined || !proof.sibling_path || proof.sibling_path.length !== profile.tree_depth) return false;
  const expectedIndexCommitment = sparseHash("leaf-index", { tree_id: profile.tree_id, index: proof.leaf_index });
  if (proof.leaf_index_commitment !== expectedIndexCommitment) return false;
  const zeroes = sparseMerkleZeroHashes(profile.tree_depth);
  const isNonMembership = Boolean(proof.empty_leaf_commitment);
  let current = isNonMembership ? zeroes[0] : sparseMerkleLeaf(proof.value_commitment);
  if (isNonMembership && proof.empty_leaf_commitment !== zeroes[0]) return false;
  if (proof.leaf_value_commitment !== sparseMerkleLeaf(proof.value_commitment)) return false;
  for (const step of proof.sibling_path) {
    current = step.side === "left" ? sparseMerkleNode(step.hash, current) : sparseMerkleNode(current, step.hash);
  }
  if (current !== root) return false;
  const expectedProof = sparseHash(isNonMembership ? "sparse-merkle-non-membership-proof" : "sparse-merkle-inclusion-proof", {
    root,
    value_commitment: proof.value_commitment,
    leaf_index: proof.leaf_index,
    tree_depth: profile.tree_depth,
    sibling_path: proof.sibling_path
  });
  return proof.proof === expectedProof;
}
