import { verifyEd25519 } from "./crypto";
import { keyActiveAt, notRevokedAt } from "./identity";
import { checkpointHash } from "./relayStore";
import { contractCheckpointFieldsHashForCheckpoint } from "./settlement";
import type { BatchCheckpointV1, Hex32, SettlementEvidenceV1, TrustID, TrustResolver } from "./types";
import { validateSchema } from "./validation";

export interface CheckpointImportValidationInput {
  checkpoint: BatchCheckpointV1;
  resolver: TrustResolver;
  previous_checkpoint?: BatchCheckpointV1 | null;
  existing_checkpoint?: BatchCheckpointV1 | null;
  authorized_relays?: TrustID[];
  require_authorized_relay?: boolean;
  require_settlement_evidence_for_settled?: boolean;
  settlement_evidence?: SettlementEvidenceV1[];
  at_time?: string;
}

export interface CheckpointImportValidationResult {
  ok: boolean;
  checkpoint_hash?: Hex32;
  error_code?: string;
  errors: string[];
}

export async function validateCheckpointImport(input: CheckpointImportValidationInput): Promise<CheckpointImportValidationResult> {
  const errors: string[] = [];
  const checkpointValidation = validateSchema("checkpoint", input.checkpoint);
  if (!checkpointValidation.valid) errors.push("TSL_CHECKPOINT_SCHEMA_INVALID");
  const checkpoint_hash = checkpointHash(input.checkpoint);
  if (input.checkpoint.checkpoint_identity_hash && input.checkpoint.checkpoint_identity_hash !== checkpoint_hash) {
    errors.push("TSL_CHECKPOINT_IDENTITY_MISMATCH");
  }

  if (input.existing_checkpoint && checkpointHash(input.existing_checkpoint) !== checkpoint_hash) {
    errors.push("TSL_CHECKPOINT_CONFLICT");
  }
  if (input.previous_checkpoint && input.checkpoint.previous_checkpoint !== checkpointHash(input.previous_checkpoint)) {
    errors.push("TSL_CHECKPOINT_CHAIN_BROKEN");
  }

  const atTime = input.at_time ?? new Date(input.checkpoint.epoch_start_ms).toISOString();
  const relayIdentity = await input.resolver.resolveTrustID(input.checkpoint.relay_id, atTime);
  const relayKey = relayIdentity?.verification_methods.find(
    (method) => method.type === "ed25519" && keyActiveAt(method, atTime) && notRevokedAt(method, atTime)
  );
  if (!relayKey || !verifyEd25519(relayKey.public_key, checkpoint_hash, input.checkpoint.relay_signature)) {
    errors.push("TSL_CHECKPOINT_SIGNATURE_INVALID");
  }
  if (input.require_authorized_relay && !input.authorized_relays?.includes(input.checkpoint.relay_id)) {
    errors.push("TSL_RELAY_NOT_AUTHORIZED");
  }

  const markedSettled = Boolean(input.checkpoint.settlement_tx);
  if (markedSettled && input.require_settlement_evidence_for_settled) {
    const evidence = input.settlement_evidence?.find(
      (candidate) =>
        candidate.checkpoint_identity_hash === checkpoint_hash ||
        candidate.checkpoint_hash === checkpoint_hash ||
        candidate.settlement_tx === input.checkpoint.settlement_tx
    );
    const evidenceError = settlementEvidenceError(input.checkpoint, checkpoint_hash, evidence);
    if (evidenceError) errors.push(evidenceError);
  }

  return {
    ok: errors.length === 0,
    checkpoint_hash,
    error_code: errors[0],
    errors
  };
}

export function settlementEvidenceError(
  checkpoint: BatchCheckpointV1,
  checkpointHashValue: Hex32 = checkpointHash(checkpoint),
  evidence?: SettlementEvidenceV1
): string | undefined {
  if (!evidence) return "TSL_SETTLEMENT_EVIDENCE_INVALID";
  const validation = validateSchema("settlementEvidenceV1", evidence);
  if (!validation.valid) return "TSL_SETTLEMENT_EVIDENCE_INVALID";
  if (evidence.status !== "settled" || evidence.receipt_status !== "success") return "TSL_SETTLEMENT_EVIDENCE_INVALID";
  if (evidence.checkpoint_hash !== checkpointHashValue || evidence.checkpoint_identity_hash !== checkpointHashValue) return "TSL_SETTLEMENT_EVIDENCE_INVALID";
  if (evidence.contract_checkpoint_fields_hash !== contractCheckpointFieldsHashForCheckpoint(checkpoint)) return "TSL_SETTLEMENT_EVIDENCE_INVALID";
  if (checkpoint.settlement_backend && evidence.settlement_backend !== checkpoint.settlement_backend) return "TSL_SETTLEMENT_EVIDENCE_INVALID";
  if (checkpoint.settlement_tx && evidence.settlement_tx !== checkpoint.settlement_tx) return "TSL_SETTLEMENT_EVIDENCE_INVALID";
  if (!evidence.transaction_receipt_hash || !evidence.block_hash || !evidence.receipt_root || !evidence.receipt_proof_source_commitment || !evidence.finality_source_commitment) {
    return "TSL_SETTLEMENT_EVIDENCE_INVALID";
  }
  return undefined;
}
