import { canonicalize } from "./canonicalize";
import {
  commitmentHash,
  contentCommitment,
  deriveEd25519PublicKey,
  eventHash,
  randomHex32,
  signEvent,
  signReceipt,
  signAttestation,
  signRevocation,
  signTrustAssessment,
  metadataCommitment,
  receiptCommitmentHash,
  attestationCommitmentHash,
  revocationCommitmentHash,
  assessmentCommitmentHash
} from "./crypto";
import type {
  AttestationUnsignedV1,
  AttestationV1,
  EventClass,
  EventCommitmentUnsignedV1,
  EventCommitmentV1,
  Hex32,
  IdentityDocumentV1,
  ReceiptClass,
  ReceiptCommitmentUnsignedV1,
  ReceiptCommitmentV1,
  RevocationUnsignedV1,
  RevocationV1,
  RFC3339,
  TrustAssessmentUnsignedV1,
  TrustAssessmentV1,
  TrustID
} from "./types";

export interface BuildMessageEventInput {
  sender: TrustID;
  signing_key_id: string;
  message: string;
  event_class?: EventClass;
  timestamp?: RFC3339;
  nonce?: Hex32;
  content_salt?: string;
  disclosure_policy?: EventCommitmentUnsignedV1["disclosure_policy"];
  receiver_commitment?: Hex32;
  metadata_commitment?: Hex32;
  previous_event_commitment?: Hex32;
}

export interface BuiltMessageEvent {
  unsignedEvent: EventCommitmentUnsignedV1;
  content_salt: string;
}

export function buildMessageEvent(input: BuildMessageEventInput): BuiltMessageEvent {
  const contentSalt = input.content_salt ?? randomHex32();
  return {
    content_salt: contentSalt,
    unsignedEvent: {
      type: "tsl.event_commitment.v1",
      event_class: input.event_class ?? "message",
      sender: input.sender,
      signing_key_id: input.signing_key_id,
      ...(input.receiver_commitment ? { receiver_commitment: input.receiver_commitment } : {}),
      content_commitment: contentCommitment(input.message, contentSalt),
      ...(input.metadata_commitment ? { metadata_commitment: input.metadata_commitment } : {}),
      ...(input.previous_event_commitment ? { previous_event_commitment: input.previous_event_commitment } : {}),
      timestamp: input.timestamp ?? new Date().toISOString(),
      nonce: input.nonce ?? randomHex32(),
      disclosure_policy: input.disclosure_policy ?? "commitment_only"
    }
  };
}

export function buildIdentityFromSeed(input: {
  trust_id: TrustID;
  key_id: string;
  seed_hex: string;
  created_at?: RFC3339;
  controller?: string;
}): IdentityDocumentV1 {
  const publicKey = deriveEd25519PublicKey(input.seed_hex);
  const createdAt = input.created_at ?? new Date().toISOString();
  return {
    type: "tsl.identity.v1",
    id: input.trust_id,
    controller: input.controller ?? input.trust_id,
    created_at: createdAt,
    verification_methods: [
      {
        id: input.key_id,
        type: "ed25519",
        public_key: publicKey,
        status: "active",
        created_at: createdAt
      }
    ]
  };
}

export function signMessageEvent(input: BuildMessageEventInput & { seed_hex: string }): {
  identityPublicKey: string;
  content_salt: string;
  envelope: EventCommitmentV1;
  event_hash: Hex32;
  commitment_hash: Hex32;
  canonical_unsigned_event: string;
} {
  const built = buildMessageEvent(input);
  const envelope = signEvent(built.unsignedEvent, input.seed_hex);
  return {
    identityPublicKey: deriveEd25519PublicKey(input.seed_hex),
    content_salt: built.content_salt,
    envelope,
    event_hash: eventHash(built.unsignedEvent),
    commitment_hash: commitmentHash(envelope),
    canonical_unsigned_event: canonicalize(built.unsignedEvent)
  };
}

export function buildReceiptCommitment(input: {
  event_commitment: Hex32;
  receiver: TrustID;
  signing_key_id: string;
  receipt_class: ReceiptClass;
  timestamp?: RFC3339;
  metadata?: unknown;
  metadata_salt?: string;
  metadata_commitment?: Hex32;
}): { unsignedReceipt: ReceiptCommitmentUnsignedV1; metadata_salt?: string } {
  const metadataSalt = input.metadata !== undefined ? input.metadata_salt ?? randomHex32() : undefined;
  return {
    metadata_salt: metadataSalt,
    unsignedReceipt: {
      type: "tsl.receipt_commitment.v1",
      event_commitment: input.event_commitment,
      receiver: input.receiver,
      signing_key_id: input.signing_key_id,
      receipt_class: input.receipt_class,
      timestamp: input.timestamp ?? new Date().toISOString(),
      ...(input.metadata_commitment
        ? { metadata_commitment: input.metadata_commitment }
        : input.metadata !== undefined && metadataSalt
          ? { metadata_commitment: metadataCommitment(input.metadata, metadataSalt) }
          : {})
    }
  };
}

export function signReceiptCommitment(input: Parameters<typeof buildReceiptCommitment>[0] & { seed_hex: string }): {
  receipt: ReceiptCommitmentV1;
  receipt_hash: Hex32;
  metadata_salt?: string;
} {
  const built = buildReceiptCommitment(input);
  const receipt = signReceipt(built.unsignedReceipt, input.seed_hex);
  return { receipt, receipt_hash: receiptCommitmentHash(receipt), metadata_salt: built.metadata_salt };
}

export function buildAttestation(input: Omit<AttestationUnsignedV1, "type" | "issued_at" | "claim_commitment"> & {
  claim?: unknown;
  claim_salt?: string;
  claim_commitment?: Hex32;
  issued_at?: RFC3339;
}): { unsignedAttestation: AttestationUnsignedV1; claim_salt?: string } {
  const claimSalt = input.claim !== undefined ? input.claim_salt ?? randomHex32() : undefined;
  const claimCommitment =
    input.claim_commitment ?? (input.claim !== undefined && claimSalt ? metadataCommitment(input.claim, claimSalt) : undefined);
  if (!claimCommitment) throw new Error("Attestation requires claim or claim_commitment");
  return {
    claim_salt: claimSalt,
    unsignedAttestation: {
      type: "tsl.attestation.v1",
      issuer: input.issuer,
      subject: input.subject,
      attestation_class: input.attestation_class,
      claim_commitment: claimCommitment,
      visibility: input.visibility,
      issued_at: input.issued_at ?? new Date().toISOString(),
      ...(input.expires_at ? { expires_at: input.expires_at } : {})
    }
  };
}

export function signAttestationObject(input: Parameters<typeof buildAttestation>[0] & { seed_hex: string }): {
  attestation: AttestationV1;
  attestation_hash: Hex32;
  claim_salt?: string;
} {
  const built = buildAttestation(input);
  const attestation = signAttestation(built.unsignedAttestation, input.seed_hex);
  return { attestation, attestation_hash: attestationCommitmentHash(attestation), claim_salt: built.claim_salt };
}

export function buildRevocation(input: Omit<RevocationUnsignedV1, "type" | "effective_at"> & { effective_at?: RFC3339 }): RevocationUnsignedV1 {
  return {
    type: "tsl.revocation.v1",
    trust_id: input.trust_id,
    revoked_key: input.revoked_key,
    ...(input.replacement_key ? { replacement_key: input.replacement_key } : {}),
    reason_class: input.reason_class,
    effective_at: input.effective_at ?? new Date().toISOString()
  };
}

export function signRevocationObject(input: Parameters<typeof buildRevocation>[0] & { seed_hex: string }): {
  revocation: RevocationV1;
  revocation_hash: Hex32;
} {
  const revocation = signRevocation(buildRevocation(input), input.seed_hex);
  return { revocation, revocation_hash: revocationCommitmentHash(revocation) };
}

export function buildTrustAssessment(input: TrustAssessmentUnsignedV1): TrustAssessmentUnsignedV1 {
  return input;
}

export function signTrustAssessmentObject(input: TrustAssessmentUnsignedV1 & { seed_hex: string }): {
  assessment: TrustAssessmentV1;
  assessment_hash: Hex32;
} {
  const { seed_hex, ...assessmentInput } = input;
  const assessment = signTrustAssessment(buildTrustAssessment(assessmentInput), seed_hex);
  return { assessment, assessment_hash: assessmentCommitmentHash(assessment) };
}
