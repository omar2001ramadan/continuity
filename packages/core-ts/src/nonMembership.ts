import { canonicalBytes } from "./canonicalize";
import { DOMAIN_TAGS, hashDomain } from "./crypto";
import type { Hex32, SetNonMembershipProofV1, TrustID } from "./types";

export function buildSetRoot(values: Hex32[]): Hex32 {
  return hashDomain(DOMAIN_TAGS.NON_MEMBERSHIP_PROOF_V1, canonicalBytes([...values].sort()));
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
  const expected = hashDomain(
    DOMAIN_TAGS.NON_MEMBERSHIP_PROOF_V1,
    canonicalBytes({
      set_root: proof.set_root,
      value_commitment: proof.value_commitment,
      lower: proof.lower_neighbor,
      upper: proof.upper_neighbor
    })
  );
  return proof.proof === expected;
}
