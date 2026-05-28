import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex as nobleBytesToHex, hexToBytes as nobleHexToBytes, randomBytes } from "@noble/hashes/utils";
import { canonicalBytes, withoutSignature } from "./canonicalize";
import type {
  AttestationUnsignedV1,
  AttestationV1,
  EventCommitmentUnsignedV1,
  EventCommitmentV1,
  Hex,
  Hex32,
  HexSig,
  ReceiptCommitmentUnsignedV1,
  ReceiptCommitmentV1,
  RevocationUnsignedV1,
  RevocationV1,
  AgentDelegationUnsignedV1,
  AgentDelegationV1,
  AuditFindingUnsignedV1,
  AuditFindingV1,
  GovernancePolicyUnsignedV1,
  GovernancePolicyV1,
  TrustAssessmentUnsignedV1,
  TrustAssessmentV1
} from "./types";

export const DOMAIN_TAGS = {
  IDENTITY_V1: "tsl.identity.v1",
  EVENT_V1: "tsl.event_commitment.v1",
  RECEIPT_V1: "tsl.receipt_commitment.v1",
  ATTESTATION_V1: "tsl.attestation.v1",
  REVOCATION_V1: "tsl.revocation.v1",
  CHECKPOINT_V1: "tsl.batch_checkpoint.v1",
  MERKLE_LEAF_V1: "tsl.merkle.leaf.v1",
  MERKLE_NODE_V1: "tsl.merkle.node.v1",
  ASSESSMENT_V1: "tsl.trust_assessment.v1",
  ASSESSMENT_V2: "tsl.trust_assessment.v2",
  PROOF_BUNDLE_V1: "tsl.proof_bundle.v1",
  COMMITMENT_V1: "tsl.commitment.v1",
  COMMITMENT_LEGACY_V1: "tsl.commitment.legacy.v1",
  DELEGATION_V2: "tsl.delegation_policy.v2",
  AGENT_ACTION_V2: "tsl.agent_action.v2",
  AGENT_DELEGATION_V1: "tsl.agent_delegation.v1",
  AUDIT_FINDING_V1: "tsl.audit.finding.v1",
  CONSISTENCY_PROOF_V1: "tsl.consistency_proof.v1",
  GOVERNANCE_POLICY_V1: "tsl.governance_policy.v1",
  NON_MEMBERSHIP_PROOF_V1: "tsl.zk.non_membership_proof.v1",
  ZK_THRESHOLD_V1: "tsl.zk.threshold_proof.v1",
  CONTENT_V1: "tsl.content.v1",
  METADATA_V1: "tsl.metadata.v1",
  RECEIVER_V1: "tsl.receiver.v1"
} as const;

export const ZERO_HASH: Hex32 = "0x0000000000000000000000000000000000000000000000000000000000000000";

function normalizeHex(hex: string): string {
  const stripped = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (stripped.length % 2 !== 0) {
    throw new Error("Hex string must have an even number of characters");
  }
  if (!/^[0-9a-fA-F]*$/.test(stripped)) {
    throw new Error("Invalid hex string");
  }
  return stripped.toLowerCase();
}

export function hexToBytes(hex: string): Uint8Array {
  return nobleHexToBytes(normalizeHex(hex));
}

export function bytesToHex(bytes: Uint8Array): Hex {
  return `0x${nobleBytesToHex(bytes)}`;
}

export function randomHex32(): Hex32 {
  return bytesToHex(randomBytes(32)) as Hex32;
}

export function sha256Bytes(data: Uint8Array | string): Uint8Array {
  return sha256(typeof data === "string" ? new TextEncoder().encode(data) : data);
}

export function sha256Hex(data: Uint8Array | string): Hex32 {
  return bytesToHex(sha256Bytes(data)) as Hex32;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

export function uint64be(value: number | bigint): Uint8Array {
  const n = BigInt(value);
  if (n < 0n || n > 0xffffffffffffffffn) {
    throw new Error("uint64be value out of range");
  }
  const output = Buffer.alloc(8);
  output.writeBigUInt64BE(n, 0);
  return Uint8Array.from(output);
}

export function hashDomain(tag: string, data: Uint8Array | string): Hex32 {
  const payload = typeof data === "string" ? new TextEncoder().encode(data) : data;
  return sha256Hex(concatBytes(new TextEncoder().encode(tag), Uint8Array.of(0), payload));
}

export function deriveEd25519PublicKey(seedHex: string): string {
  return nobleBytesToHex(ed25519.getPublicKey(hexToBytes(seedHex)));
}

export function signEd25519(message: Uint8Array | Hex32, seedHex: string): HexSig {
  const bytes = typeof message === "string" ? hexToBytes(message) : message;
  return bytesToHex(ed25519.sign(bytes, hexToBytes(seedHex))) as HexSig;
}

export function verifyEd25519(publicKeyHex: string, message: Uint8Array | Hex32, signatureHex: HexSig): boolean {
  const bytes = typeof message === "string" ? hexToBytes(message) : message;
  try {
    return ed25519.verify(hexToBytes(signatureHex), bytes, hexToBytes(publicKeyHex));
  } catch {
    return false;
  }
}

export function eventHash(unsignedEvent: EventCommitmentUnsignedV1 | EventCommitmentV1): Hex32 {
  const payload = "signature" in unsignedEvent ? withoutSignature(unsignedEvent as unknown as Record<string, unknown>) : unsignedEvent;
  return hashDomain(DOMAIN_TAGS.EVENT_V1, canonicalBytes(payload));
}

export function signEvent(unsignedEvent: EventCommitmentUnsignedV1, seedHex: string): EventCommitmentV1 {
  return {
    ...unsignedEvent,
    signature: signEd25519(eventHash(unsignedEvent), seedHex)
  };
}

export function receiptHash(receipt: ReceiptCommitmentUnsignedV1 | ReceiptCommitmentV1): Hex32 {
  const payload = "signature" in receipt ? withoutSignature(receipt as unknown as Record<string, unknown>) : receipt;
  return hashDomain(DOMAIN_TAGS.RECEIPT_V1, canonicalBytes(payload));
}

export function signReceipt(unsignedReceipt: ReceiptCommitmentUnsignedV1, seedHex: string): ReceiptCommitmentV1 {
  return { ...unsignedReceipt, signature: signEd25519(receiptHash(unsignedReceipt), seedHex) };
}

export function receiptCommitmentHash(receipt: ReceiptCommitmentV1): Hex32 {
  return commitmentHashFromParts(receiptHash(receipt), receipt.signature);
}

export function attestationHash(attestation: AttestationUnsignedV1 | AttestationV1): Hex32 {
  const payload = "signature" in attestation ? withoutSignature(attestation as unknown as Record<string, unknown>) : attestation;
  return hashDomain(DOMAIN_TAGS.ATTESTATION_V1, canonicalBytes(payload));
}

export function signAttestation(unsignedAttestation: AttestationUnsignedV1, seedHex: string): AttestationV1 {
  return { ...unsignedAttestation, signature: signEd25519(attestationHash(unsignedAttestation), seedHex) };
}

export function attestationCommitmentHash(attestation: AttestationV1): Hex32 {
  return commitmentHashFromParts(attestationHash(attestation), attestation.signature);
}

export function revocationHash(revocation: RevocationUnsignedV1 | RevocationV1): Hex32 {
  const payload = "signature" in revocation ? withoutSignature(revocation as unknown as Record<string, unknown>) : revocation;
  return hashDomain(DOMAIN_TAGS.REVOCATION_V1, canonicalBytes(payload));
}

export function signRevocation(unsignedRevocation: RevocationUnsignedV1, seedHex: string): RevocationV1 {
  return { ...unsignedRevocation, signature: signEd25519(revocationHash(unsignedRevocation), seedHex) };
}

export function revocationCommitmentHash(revocation: RevocationV1): Hex32 {
  return commitmentHashFromParts(revocationHash(revocation), revocation.signature);
}

export function assessmentHash(assessment: TrustAssessmentUnsignedV1 | TrustAssessmentV1): Hex32 {
  const payload = "signature" in assessment ? withoutSignature(assessment as unknown as Record<string, unknown>) : assessment;
  return hashDomain(DOMAIN_TAGS.ASSESSMENT_V1, canonicalBytes(payload));
}

export function signTrustAssessment(unsignedAssessment: TrustAssessmentUnsignedV1, seedHex: string): TrustAssessmentV1 {
  return { ...unsignedAssessment, signature: signEd25519(assessmentHash(unsignedAssessment), seedHex) };
}

export function assessmentCommitmentHash(assessment: TrustAssessmentV1): Hex32 {
  return commitmentHashFromParts(assessmentHash(assessment), assessment.signature);
}

export function verifyReceipt(receipt: ReceiptCommitmentV1, publicKeyHex: string): boolean {
  return verifyEd25519(publicKeyHex, receiptHash(receipt), receipt.signature);
}

export function verifyAttestation(attestation: AttestationV1, publicKeyHex: string): boolean {
  return verifyEd25519(publicKeyHex, attestationHash(attestation), attestation.signature);
}

export function verifyRevocation(revocation: RevocationV1, publicKeyHex: string): boolean {
  return verifyEd25519(publicKeyHex, revocationHash(revocation), revocation.signature);
}

export function verifyTrustAssessment(assessment: TrustAssessmentV1, publicKeyHex: string): boolean {
  return verifyEd25519(publicKeyHex, assessmentHash(assessment), assessment.signature);
}

export function agentDelegationHash(delegation: AgentDelegationUnsignedV1 | AgentDelegationV1): Hex32 {
  const payload = { ...(delegation as unknown as Record<string, unknown>) };
  delete payload.controller_signature;
  delete payload.agent_signature;
  return hashDomain(DOMAIN_TAGS.AGENT_DELEGATION_V1, canonicalBytes(payload));
}

export function signAgentDelegation(
  unsignedDelegation: AgentDelegationUnsignedV1,
  controllerSeedHex: string,
  agentSeedHex: string
): AgentDelegationV1 {
  const hash = agentDelegationHash(unsignedDelegation);
  return {
    ...unsignedDelegation,
    controller_signature: signEd25519(hash, controllerSeedHex),
    agent_signature: signEd25519(hash, agentSeedHex)
  };
}

export function auditFindingHash(finding: AuditFindingUnsignedV1 | AuditFindingV1): Hex32 {
  const payload = "signature" in finding ? withoutSignature(finding as unknown as Record<string, unknown>) : finding;
  return hashDomain(DOMAIN_TAGS.AUDIT_FINDING_V1, canonicalBytes(payload));
}

export function signAuditFinding(unsignedFinding: AuditFindingUnsignedV1, auditorSeedHex: string): AuditFindingV1 {
  return { ...unsignedFinding, signature: signEd25519(auditFindingHash(unsignedFinding), auditorSeedHex) };
}

export function governancePolicyHash(policy: GovernancePolicyUnsignedV1 | GovernancePolicyV1): Hex32 {
  const payload = "signature" in policy ? withoutSignature(policy as unknown as Record<string, unknown>) : policy;
  return hashDomain(DOMAIN_TAGS.GOVERNANCE_POLICY_V1, canonicalBytes(payload));
}

export function signGovernancePolicy(unsignedPolicy: GovernancePolicyUnsignedV1, authoritySeedHex: string): GovernancePolicyV1 {
  return { ...unsignedPolicy, signature: signEd25519(governancePolicyHash(unsignedPolicy), authoritySeedHex) };
}

export function verifyGovernancePolicy(policy: GovernancePolicyV1, publicKeyHex: string): boolean {
  return verifyEd25519(publicKeyHex, governancePolicyHash(policy), policy.signature);
}

export function commitmentHashFromParts(eventHashHex: Hex32, signatureHex: HexSig): Hex32 {
  return hashDomain(DOMAIN_TAGS.COMMITMENT_V1, concatBytes(hexToBytes(eventHashHex), hexToBytes(signatureHex)));
}

export function legacyCommitmentHashFromParts(eventHashHex: Hex32, signatureHex: HexSig): Hex32 {
  return sha256Hex(concatBytes(hexToBytes(eventHashHex), hexToBytes(signatureHex)));
}

export function legacyCommitmentHash(event: EventCommitmentV1): Hex32 {
  return legacyCommitmentHashFromParts(eventHash(event), event.signature);
}

export function commitmentHash(event: EventCommitmentV1): Hex32 {
  return commitmentHashFromParts(eventHash(event), event.signature);
}

export function contentCommitment(rawMessage: string, saltHex: string): Hex32 {
  return hashDomain(DOMAIN_TAGS.CONTENT_V1, concatBytes(new TextEncoder().encode(rawMessage), hexToBytes(saltHex)));
}

export function metadataCommitment(canonicalMetadata: unknown, saltHex: string): Hex32 {
  return hashDomain(DOMAIN_TAGS.METADATA_V1, concatBytes(canonicalBytes(canonicalMetadata), hexToBytes(saltHex)));
}

export function receiverCommitment(receiverTrustId: string, saltHex: string): Hex32 {
  return hashDomain(DOMAIN_TAGS.RECEIVER_V1, concatBytes(new TextEncoder().encode(receiverTrustId), hexToBytes(saltHex)));
}
