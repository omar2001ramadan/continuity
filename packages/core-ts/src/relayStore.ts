import { canonicalize, withoutField } from "./canonicalize";
import { buildIdentityFromSeed } from "./commitments";
import { DOMAIN_TAGS, ZERO_HASH, attestationHash, commitmentHash, hashDomain, receiptHash, revocationHash, sha256Hex, signEd25519 } from "./crypto";
import { MemoryTrustResolver } from "./identity";
import { buildInclusionProof, buildMerkleTree } from "./merkle";
import type { SettlementBackend } from "./settlement";
import type { AttestationV1, BatchCheckpointV1, EventCommitmentV1, Hex32, HexSig, IdentityDocumentV1, InclusionProofV1, ReceiptCommitmentV1, RevocationV1, TrustID } from "./types";
import { validateSchema } from "./validation";
import { verifyTSL } from "./verifier";

export interface AcceptedEvent {
  event: EventCommitmentV1;
  commitment_hash: Hex32;
  relay_id: TrustID;
  shard: string;
  epoch_start_ms: number;
  epoch_duration_ms: number;
  log_index: number;
  accepted_at: string;
}

export interface AcceptedLogObject {
  commitment_hash: Hex32;
  shard: string;
  epoch_start_ms: number;
  epoch_duration_ms: number;
  log_index: number;
  accepted_at: string;
}

export interface RelayStoreOptions {
  relay_id?: TrustID;
  relay_signing_key_id?: string;
  relay_signing_seed_hex?: string;
  epoch_duration_ms?: number;
  timestamp_window_ms?: number;
  settlement_backend?: SettlementBackend | null;
}

export class RelayValidationError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly details?: unknown
  ) {
    super(message);
  }
}

export class InMemoryRelayStore {
  readonly resolver = new MemoryTrustResolver();
  readonly relay_id: TrustID;
  readonly relay_identity: IdentityDocumentV1 | null;
  readonly epoch_duration_ms: number;
  readonly timestamp_window_ms: number;
  readonly settlement_backend: SettlementBackend | null;
  private readonly relay_signing_seed_hex?: string;
  private readonly events = new Map<Hex32, AcceptedEvent>();
  private readonly receipts = new Map<Hex32, AcceptedLogObject>();
  private readonly attestations = new Map<Hex32, AcceptedLogObject>();
  private readonly revocations = new Map<Hex32, AcceptedLogObject>();
  private readonly nonces = new Set<string>();
  private readonly settledCheckpoints = new Map<string, BatchCheckpointV1>();
  private readonly closedSegments = new Map<string, Hex32[]>();

  constructor(options: RelayStoreOptions = {}) {
    this.relay_id = options.relay_id ?? "did:tsl:relay:dev";
    this.relay_signing_seed_hex = options.relay_signing_seed_hex;
    this.relay_identity = options.relay_signing_seed_hex
      ? buildIdentityFromSeed({
          trust_id: this.relay_id,
          key_id: options.relay_signing_key_id ?? "#relay-checkpoint",
          seed_hex: options.relay_signing_seed_hex,
          created_at: "2026-01-01T00:00:00Z"
        })
      : null;
    this.epoch_duration_ms = options.epoch_duration_ms ?? 300000;
    this.timestamp_window_ms = options.timestamp_window_ms ?? 600000;
    this.settlement_backend = options.settlement_backend ?? null;
    if (this.relay_identity) this.resolver.upsertIdentity(this.relay_identity);
  }

  upsertIdentity(identity: IdentityDocumentV1): void {
    const validation = validateSchema("identity", identity);
    if (!validation.valid) {
      throw new RelayValidationError("TSL_SCHEMA_INVALID", "Identity failed schema validation", validation.errors);
    }
    this.resolver.upsertIdentity(identity);
  }

  async acceptEvent(event: EventCommitmentV1): Promise<AcceptedEvent> {
    const validation = validateSchema("event", event);
    if (!validation.valid) {
      throw new RelayValidationError("TSL_SCHEMA_INVALID", "Event failed schema validation", validation.errors);
    }

    const eventTime = Date.parse(event.timestamp);
    if (!Number.isFinite(eventTime)) {
      throw new RelayValidationError("TSL_TIMESTAMP_INVALID", "Event timestamp is not parseable");
    }
    if (Math.abs(Date.now() - eventTime) > this.timestamp_window_ms) {
      throw new RelayValidationError("TSL_TIMESTAMP_OUT_OF_WINDOW", "Event timestamp is outside relay policy");
    }

    const nonceKey = `${event.sender}:${event.signing_key_id}:${event.nonce}`;
    if (this.nonces.has(nonceKey)) {
      throw new RelayValidationError("TSL_NONCE_REPLAY", "Duplicate sender/key/nonce");
    }

    const verification = await verifyTSL({ envelope: event }, this.resolver);
    if (!verification.verified || !verification.commitment_hash) {
      throw new RelayValidationError("TSL_SIGNATURE_INVALID", "Event did not pass relay verification", verification);
    }

    const epochStart = Math.floor(eventTime / this.epoch_duration_ms) * this.epoch_duration_ms;
    const shard = shardForTrustID(event.sender);
    const segmentKey = checkpointStoreKey(epochStart, shard);
    if (this.closedSegments.has(segmentKey)) {
      throw new RelayValidationError("TSL_LOG_SEGMENT_CLOSED", "Cannot append to a checkpointed epoch/shard segment");
    }
    const logIndex = this.eventsFor(epochStart, shard).length;

    const accepted: AcceptedEvent = {
      event,
      commitment_hash: verification.commitment_hash,
      relay_id: this.relay_id,
      shard,
      epoch_start_ms: epochStart,
      epoch_duration_ms: this.epoch_duration_ms,
      log_index: logIndex,
      accepted_at: new Date().toISOString()
    };

    this.nonces.add(nonceKey);
    this.events.set(verification.commitment_hash, accepted);
    return accepted;
  }

  acceptReceipt(receipt: ReceiptCommitmentV1): AcceptedLogObject {
    const commitment = receiptHash(receipt);
    const epochStart = Math.floor(Date.parse(receipt.timestamp) / this.epoch_duration_ms) * this.epoch_duration_ms;
    const shard = shardForTrustID(receipt.receiver);
    const accepted = this.acceptLogObject(this.receipts, commitment, epochStart, shard);
    this.receipts.set(commitment, accepted);
    return accepted;
  }

  acceptAttestation(attestation: AttestationV1): AcceptedLogObject {
    const commitment = attestationHash(attestation);
    const epochStart = Math.floor(Date.parse(attestation.issued_at) / this.epoch_duration_ms) * this.epoch_duration_ms;
    const shard = shardForTrustID(attestation.issuer);
    const accepted = this.acceptLogObject(this.attestations, commitment, epochStart, shard);
    this.attestations.set(commitment, accepted);
    return accepted;
  }

  acceptRevocation(revocation: RevocationV1): AcceptedLogObject {
    const commitment = revocationHash(revocation);
    const epochStart = Math.floor(Date.parse(revocation.effective_at) / this.epoch_duration_ms) * this.epoch_duration_ms;
    const shard = shardForTrustID(revocation.trust_id);
    const accepted = this.acceptLogObject(this.revocations, commitment, epochStart, shard);
    this.revocations.set(commitment, accepted);
    return accepted;
  }

  private acceptLogObject(store: Map<Hex32, AcceptedLogObject>, commitment: Hex32, epochStart: number, shard: string): AcceptedLogObject {
    const segmentKey = checkpointStoreKey(epochStart, shard);
    if (this.closedSegments.has(segmentKey)) {
      throw new RelayValidationError("TSL_LOG_SEGMENT_CLOSED", "Cannot append to a checkpointed epoch/shard segment");
    }
    return {
      commitment_hash: commitment,
      shard,
      epoch_start_ms: epochStart,
      epoch_duration_ms: this.epoch_duration_ms,
      log_index: this.objectsFor(store, epochStart, shard).length,
      accepted_at: new Date().toISOString()
    };
  }

  getAcceptedEvent(commitment: Hex32): AcceptedEvent | null {
    return this.events.get(commitment) ?? null;
  }

  proofFor(commitment: Hex32): { proof: InclusionProofV1; checkpoint: BatchCheckpointV1 } | null {
    const accepted = this.events.get(commitment);
    if (!accepted) return null;

    const segmentKey = checkpointStoreKey(accepted.epoch_start_ms, accepted.shard);
    const commitments = this.closedSegments.get(segmentKey) ?? this.eventsFor(accepted.epoch_start_ms, accepted.shard).map((item) => item.commitment_hash);
    const checkpoint = this.checkpointFor(accepted.epoch_start_ms, accepted.shard);
    const proof = buildInclusionProof({
      commitments,
      leaf_index: accepted.log_index,
      tree_kind: "event",
      epoch_start_ms: accepted.epoch_start_ms,
      epoch_duration_ms: accepted.epoch_duration_ms,
      shard: accepted.shard,
      checkpoint_hash: checkpointHash(checkpoint)
    });

    return { proof, checkpoint };
  }

  checkpointFor(epoch_start_ms: number, shard: string): BatchCheckpointV1 {
    const settled = this.settledCheckpoints.get(checkpointStoreKey(epoch_start_ms, shard));
    if (settled) return structuredClone(settled);

    const commitments = this.eventsFor(epoch_start_ms, shard).map((item) => item.commitment_hash);
    const receiptCommitments = this.objectsFor(this.receipts, epoch_start_ms, shard).map((item) => item.commitment_hash);
    const attestationCommitments = this.objectsFor(this.attestations, epoch_start_ms, shard).map((item) => item.commitment_hash);
    const revocationCommitments = this.objectsFor(this.revocations, epoch_start_ms, shard).map((item) => item.commitment_hash);
    const eventTree = buildMerkleTree(commitments);
    const receiptTree = buildMerkleTree(receiptCommitments);
    const attestationTree = buildMerkleTree(attestationCommitments);
    const revocationTree = buildMerkleTree(revocationCommitments);
    const checkpoint: BatchCheckpointV1 = {
      type: "tsl.batch_checkpoint.v1",
      epoch_start_ms,
      epoch_duration_ms: this.epoch_duration_ms,
      shard,
      event_root: eventTree.root,
      receipt_root: receiptTree.root,
      attestation_root: attestationTree.root,
      revocation_root: revocationTree.root,
	      event_count: commitments.length,
	      receipt_count: receiptCommitments.length,
	      previous_checkpoint: this.previousCheckpointHash(epoch_start_ms, shard),
	      ...(this.settlement_backend?.settlementBackendId ? { settlement_backend: this.settlement_backend.settlementBackendId } : {}),
	      relay_id: this.relay_id,
	      relay_signature: "0x00"
	    };
    return this.relay_signing_seed_hex ? signCheckpointWithSeed(checkpoint, this.relay_signing_seed_hex) : {
      ...checkpoint,
      relay_signature: pseudoRelaySignature({
        epoch_start_ms,
        shard,
        event_root: eventTree.root
      })
    };
  }

  async submitCheckpoint(epoch_start_ms: number, shard: string): Promise<BatchCheckpointV1> {
    if (!this.settlement_backend) {
      throw new RelayValidationError("TSL_SETTLEMENT_BACKEND_MISSING", "No settlement backend is configured");
    }
    const checkpoint = this.checkpointFor(epoch_start_ms, shard);
    const settled = await this.settlement_backend.submitCheckpoint(checkpoint);
    const segmentKey = checkpointStoreKey(epoch_start_ms, shard);
    const existing = this.settledCheckpoints.get(segmentKey);
    if (existing && checkpointHash(existing) !== checkpointHash(settled)) {
      throw new RelayValidationError("TSL_CHECKPOINT_CONFLICT", "Conflicting checkpoint for closed epoch/shard segment");
    }
    this.closedSegments.set(segmentKey, this.eventsFor(epoch_start_ms, shard).map((item) => item.commitment_hash));
    this.settledCheckpoints.set(segmentKey, settled);
    return structuredClone(settled);
  }

  eventsFor(epoch_start_ms: number, shard: string): AcceptedEvent[] {
    return [...this.events.values()]
      .filter((event) => event.epoch_start_ms === epoch_start_ms && event.shard === shard)
      .sort((left, right) => left.log_index - right.log_index);
  }

  private objectsFor(store: Map<Hex32, AcceptedLogObject>, epoch_start_ms: number, shard: string): AcceptedLogObject[] {
    return [...store.values()]
      .filter((item) => item.epoch_start_ms === epoch_start_ms && item.shard === shard)
      .sort((left, right) => left.log_index - right.log_index);
  }

  identities(): IdentityDocumentV1[] {
    return this.relay_identity ? [structuredClone(this.relay_identity)] : [];
  }

  private previousCheckpointHash(epoch_start_ms: number, shard: string): Hex32 {
    const previous = [...this.settledCheckpoints.values()]
      .filter((checkpoint) => checkpoint.shard === shard && checkpoint.epoch_start_ms < epoch_start_ms)
      .sort((left, right) => right.epoch_start_ms - left.epoch_start_ms)[0];
    return previous ? checkpointHash(previous) : ZERO_HASH;
  }
}

function checkpointStoreKey(epoch_start_ms: number, shard: string): string {
  return `${epoch_start_ms}:${shard}`;
}

export function shardForTrustID(trustId: TrustID): string {
  return sha256Hex(new TextEncoder().encode(trustId)).slice(2, 6);
}

export function checkpointHash(checkpoint: BatchCheckpointV1): Hex32 {
  const payload = withoutField(withoutField(checkpoint as unknown as Record<string, unknown>, "relay_signature"), "settlement_tx");
  return hashDomain(DOMAIN_TAGS.CHECKPOINT_V1, new TextEncoder().encode(canonicalize(payload)));
}

export function legacyCheckpointHashV0(checkpoint: BatchCheckpointV1): Hex32 {
  let payload = withoutField(checkpoint as unknown as Record<string, unknown>, "relay_signature");
  payload = withoutField(payload, "settlement_backend");
  payload = withoutField(payload, "settlement_tx");
  return hashDomain(DOMAIN_TAGS.CHECKPOINT_V1, new TextEncoder().encode(canonicalize(payload)));
}

export function signCheckpointWithSeed(checkpoint: BatchCheckpointV1, seedHex: string): BatchCheckpointV1 {
  const unsigned: BatchCheckpointV1 = { ...checkpoint, relay_signature: "0x00" };
  return { ...checkpoint, relay_signature: signEd25519(checkpointHash(unsigned), seedHex) as HexSig };
}

function pseudoRelaySignature(input: Record<string, unknown>): `0x${string}` {
  return commitmentHash({
    type: "tsl.event_commitment.v1",
    event_class: "attestation",
    sender: "did:tsl:relay:dev",
    signing_key_id: "#relay-pseudo",
    content_commitment: hashDomain("tsl.relay.signature.payload.v1", canonicalize(input)),
    timestamp: "2026-05-25T00:00:00Z",
    nonce: ZERO_HASH,
    disclosure_policy: "public",
    signature: "0x00"
  });
}
