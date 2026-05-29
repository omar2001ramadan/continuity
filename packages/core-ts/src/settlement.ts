import { ethers } from "ethers";
import { checkpointHash } from "./relayStore";
import { canonicalBytes } from "./canonicalize";
import { sha256Hex } from "./crypto";
import type { BatchCheckpointV1, Hex32, IdentityDocumentV1, SettlementEvidenceV1, TrustID } from "./types";

export interface SettlementVerificationResult {
  settled: boolean;
  settlement_backend?: string;
  settlement_tx?: string;
  settlement_evidence?: SettlementEvidenceV1;
  error?: string;
}

export interface CheckpointSettlementBackend {
  settlementBackendId?: string;
  submitCheckpoint(checkpoint: BatchCheckpointV1): Promise<BatchCheckpointV1>;
  verifyCheckpointSettlement(checkpoint: BatchCheckpointV1): Promise<SettlementVerificationResult>;
  getCheckpoint(epochStartMs: number, shard: string): Promise<BatchCheckpointV1 | null>;
}

export interface IdentityRegistryBackend {
  registerIdentity(identity: IdentityDocumentV1): Promise<string>;
  rotateIdentityKey(trustId: TrustID, oldKeyId: string, newKeyId: string): Promise<string>;
  revokeIdentityKey(trustId: TrustID, keyId: string, reason: number): Promise<string>;
  getActiveIdentityKey(trustId: TrustID): Promise<string | null>;
  isIdentityKeyRevoked(trustId: TrustID, keyId: string): Promise<boolean>;
}

export interface RevocationRegistryBackend {
  recordRevocation(input: {
    trustId: TrustID;
    keyId: string;
    reason: number;
    effectiveAtMs: number;
    replacementKeyId?: string;
    controllerSignature?: string;
  }): Promise<string>;
  isKeyRevokedAt(trustId: TrustID, keyId: string, atTimeMs: number): Promise<boolean>;
}

function settlementEventHashForEvidence(evidence: Pick<
  SettlementEvidenceV1,
  | "chain_id"
  | "contract_address"
  | "checkpoint_identity_hash"
  | "contract_checkpoint_fields_hash"
  | "settlement_tx"
  | "transaction_receipt_hash"
  | "block_hash"
  | "block_number"
  | "receipt_root"
  | "transaction_index"
  | "receipt_status"
  | "settlement_event_index"
  | "event_topic_hash"
  | "log_index"
  | "submitter"
>): Hex32 {
  return sha256Hex(
    canonicalBytes({
      chain_id: evidence.chain_id,
      contract_address: evidence.contract_address.toLowerCase(),
      checkpoint_identity_hash: evidence.checkpoint_identity_hash,
      contract_checkpoint_fields_hash: evidence.contract_checkpoint_fields_hash,
      settlement_tx: evidence.settlement_tx.toLowerCase(),
      transaction_receipt_hash: evidence.transaction_receipt_hash,
      block_hash: evidence.block_hash,
      block_number: evidence.block_number,
      receipt_root: evidence.receipt_root,
      transaction_index: evidence.transaction_index,
      receipt_status: evidence.receipt_status,
      settlement_event_index: evidence.settlement_event_index,
      event_topic_hash: evidence.event_topic_hash,
      log_index: evidence.log_index,
      submitter: evidence.submitter.toLowerCase()
    })
  );
}

export interface ProviderRegistryBackend {
  isProviderActive(providerId: TrustID): Promise<boolean>;
  isModelRegistered(providerId: TrustID, modelVersion: string): Promise<boolean>;
}

export interface SettlementBackend extends CheckpointSettlementBackend, Partial<IdentityRegistryBackend>, Partial<RevocationRegistryBackend>, Partial<ProviderRegistryBackend> {}

export interface LocalEvmSettlementBackendOptions {
  rpcUrl: string;
  checkpointRegistryAddress: string;
  trustIDRegistryAddress?: string;
  revocationRegistryAddress?: string;
  providerRegistryAddress?: string;
  privateKey?: string;
  chainId?: number;
}

const CHECKPOINT_REGISTRY_ABI = [
  "function submitCheckpoint((uint64 epochStartMs,uint32 epochDurationMs,bytes32 shard,bytes32 eventRoot,bytes32 receiptRoot,bytes32 attestationRoot,bytes32 revocationRoot,uint64 eventCount,uint64 receiptCount,bytes32 previousCheckpoint,bytes32 checkpointIdentityHash,bytes32 relayId,bytes32 settlementBackend) input, bytes relaySignature) external returns (bytes32)",
  "function getCheckpointByEpochShard(uint64 epochStartMs, bytes32 shard) external view returns ((uint64 epochStartMs,uint32 epochDurationMs,bytes32 shard,bytes32 eventRoot,bytes32 receiptRoot,bytes32 attestationRoot,bytes32 revocationRoot,uint64 eventCount,uint64 receiptCount,bytes32 previousCheckpoint,bytes32 checkpointIdentityHash,bytes32 contractCheckpointFieldsHash,bytes32 relayId,bytes32 settlementBackend,address submitter,uint64 submittedAt))",
  "function hasCheckpoint(uint64 epochStartMs, bytes32 shard) external view returns (bool)",
  "function hashCheckpoint((uint64 epochStartMs,uint32 epochDurationMs,bytes32 shard,bytes32 eventRoot,bytes32 receiptRoot,bytes32 attestationRoot,bytes32 revocationRoot,uint64 eventCount,uint64 receiptCount,bytes32 previousCheckpoint,bytes32 checkpointIdentityHash,bytes32 relayId,bytes32 settlementBackend) input) external pure returns (bytes32)",
  "function contractCheckpointFieldsHash((uint64 epochStartMs,uint32 epochDurationMs,bytes32 shard,bytes32 eventRoot,bytes32 receiptRoot,bytes32 attestationRoot,bytes32 revocationRoot,uint64 eventCount,uint64 receiptCount,bytes32 previousCheckpoint,bytes32 checkpointIdentityHash,bytes32 relayId,bytes32 settlementBackend) input) external pure returns (bytes32)"
] as const;

const TRUST_ID_REGISTRY_ABI = [
  "function register(bytes32 trustId, bytes32 activeKey, bytes32 policyCommitment) external",
  "function rotateKey(bytes32 trustId, bytes32 oldKey, bytes32 newKey) external",
  "function revokeKey(bytes32 trustId, bytes32 key, uint8 reason) external",
  "function getActiveKey(bytes32 trustId) external view returns (bytes32)",
  "function isRevoked(bytes32 trustId, bytes32 key) external view returns (bool)"
] as const;

const REVOCATION_REGISTRY_ABI = [
  "function recordRevocation(bytes32 trustId, bytes32 key, uint8 reason, uint64 effectiveAt, bytes32 replacementKey) external returns (bytes32)",
  "function recordRevocationWithAuthorization(bytes32 trustId, bytes32 key, uint8 reason, uint64 effectiveAt, bytes32 replacementKey, bytes controllerSignature) external returns (bytes32)",
  "function isRevoked(bytes32 trustId, bytes32 key, uint64 atTime) external view returns (bool)"
] as const;

const PROVIDER_REGISTRY_ABI = [
  "function providers(bytes32 providerId) external view returns (bytes32 publicKey, bytes32 policyCommitment, bool active)",
  "function modelCards(bytes32 providerId, bytes32 modelId) external view returns (bytes32)"
] as const;

type ContractCheckpoint = {
  epochStartMs: bigint;
  epochDurationMs: bigint;
  shard: string;
  eventRoot: string;
  receiptRoot: string;
  attestationRoot: string;
  revocationRoot: string;
  eventCount: bigint;
  receiptCount: bigint;
  previousCheckpoint: string;
  checkpointIdentityHash: string;
  contractCheckpointFieldsHash: string;
  relayId: string;
  settlementBackend?: string;
  submitter?: string;
  submittedAt: bigint;
};

export class LocalEvmSettlementBackend implements SettlementBackend {
  readonly provider: ethers.JsonRpcProvider;
  readonly chainId: number;
  readonly settlementBackendId: string;
  private readonly registryAddress: string;
  private readonly trustIDRegistryAddress?: string;
  private readonly revocationRegistryAddress?: string;
  private readonly providerRegistryAddress?: string;
  private readonly privateKey?: string;

  constructor(options: LocalEvmSettlementBackendOptions) {
    this.provider = new ethers.JsonRpcProvider(options.rpcUrl);
    this.registryAddress = options.checkpointRegistryAddress;
    this.trustIDRegistryAddress = options.trustIDRegistryAddress;
    this.revocationRegistryAddress = options.revocationRegistryAddress;
    this.providerRegistryAddress = options.providerRegistryAddress;
    this.privateKey = options.privateKey;
    this.chainId = options.chainId ?? 31337;
    this.settlementBackendId = `eip155:${this.chainId}`;
  }

  async submitCheckpoint(checkpoint: BatchCheckpointV1): Promise<BatchCheckpointV1> {
    const contract = await this.writableContract();
    if (!checkpoint.settlement_backend) {
      throw new Error("TSL_CHECKPOINT_SETTLEMENT_BACKEND_REQUIRED");
    }
    if (checkpoint.settlement_backend !== this.settlementBackendId) {
      throw new Error("TSL_CHECKPOINT_SETTLEMENT_BACKEND_MISMATCH");
    }
    const portableCheckpoint: BatchCheckpointV1 = {
      ...checkpoint
    };
    portableCheckpoint.checkpoint_identity_hash = checkpointHash(portableCheckpoint);
    const input = toContractCheckpointInput(portableCheckpoint);
    const contractRelaySignature = await this.signRelayCheckpoint(contract, input);
    const tx = await contract.submitCheckpoint(input, contractRelaySignature);
    const receipt = await tx.wait();
    if (!receipt?.hash) {
      throw new Error("Checkpoint transaction did not produce a receipt hash");
    }

    return {
      ...portableCheckpoint,
      checkpoint_identity_hash: checkpointHash(portableCheckpoint),
      settlement_tx: receipt.hash
    };
  }

  async verifyCheckpointSettlement(checkpoint: BatchCheckpointV1): Promise<SettlementVerificationResult> {
    try {
      const stored = await this.readStoredCheckpoint(checkpoint.epoch_start_ms, checkpoint.shard);
      if (!stored || stored.submittedAt === 0n) {
        return { settled: false, error: "TSL_SETTLEMENT_MISSING" };
      }

      const comparableCheckpoint = { ...checkpoint, settlement_backend: checkpoint.settlement_backend ?? this.settlementBackendId };
      const mismatches = checkpointMismatches(comparableCheckpoint, stored);
      const identityHash = checkpointHash(comparableCheckpoint);
      const fieldsHash = (await this.readableContract().contractCheckpointFieldsHash(toContractCheckpointInput(comparableCheckpoint))) as Hex32;
      if (stored.checkpointIdentityHash !== identityHash || stored.contractCheckpointFieldsHash !== fieldsHash) {
        mismatches.push("checkpoint_identity_hash");
      }
      if (mismatches.length > 0) {
        return {
          settled: false,
          settlement_backend: this.settlementBackendId,
          settlement_tx: checkpoint.settlement_tx,
          error: `TSL_SETTLEMENT_MISMATCH:${mismatches.join(",")}`
        };
      }

      const receipt = checkpoint.settlement_tx ? await this.provider.getTransactionReceipt(checkpoint.settlement_tx) : null;
      const receiptStatus = receipt?.status === 1 ? "success" : receipt?.status === 0 ? "reverted" : "unknown";
      const checkpointLog = receipt?.logs.find((log) => log.address.toLowerCase() === this.registryAddress.toLowerCase() && log.topics[0] === ethers.id("CheckpointSubmitted(bytes32,bytes32,uint64,bytes32,bytes32,address)"));
      const settlementEvidenceBase = checkpoint.settlement_tx && receipt
        ? {
            type: "tsl.settlement_evidence.v1" as const,
            checkpoint_hash: identityHash,
            checkpoint_identity_hash: identityHash,
            settlement_backend: this.settlementBackendId,
            chain_id: this.chainId,
            contract_address: this.registryAddress,
            contract_checkpoint_hash: fieldsHash,
            contract_checkpoint_fields_hash: fieldsHash,
            settlement_tx: receipt.hash,
            evidence_kind: "rpc_attested_receipt" as const,
            transaction_receipt_hash: receipt.hash as Hex32,
            block_hash: receipt.blockHash as Hex32,
            block_number: receipt.blockNumber,
            receipt_root: sha256Hex(canonicalBytes({ block_hash: receipt.blockHash, logs_bloom: receipt.logsBloom, transaction_receipt_hash: receipt.hash })),
            transaction_index: receipt.index,
            receipt_status: receiptStatus as "success" | "reverted" | "unknown",
            settlement_event_index: checkpointLog?.transactionIndex ?? 0,
            event_topic_hash: (checkpointLog?.topics[0] ?? ethers.id("CheckpointSubmitted(bytes32,bytes32,uint64,bytes32,bytes32,address)")) as Hex32,
            log_index: checkpointLog?.index ?? 0,
            submitter: stored.submitter ?? receipt.from ?? ethers.ZeroAddress,
            submitted_at: new Date(Number(stored.submittedAt) * 1000).toISOString(),
            status: receiptStatus === "success" ? ("settled" as const) : ("failed" as const)
          }
        : undefined;
      const settlementEventHash = settlementEvidenceBase ? settlementEventHashForEvidence(settlementEvidenceBase) : undefined;
      const receiptProofSourceCommitment = settlementEvidenceBase
        ? sha256Hex(
            canonicalBytes({
              block_hash: settlementEvidenceBase.block_hash,
              block_number: settlementEvidenceBase.block_number,
              receipt_root: settlementEvidenceBase.receipt_root,
              transaction_receipt_hash: settlementEvidenceBase.transaction_receipt_hash,
              transaction_index: settlementEvidenceBase.transaction_index,
              log_index: settlementEvidenceBase.log_index
            })
          )
        : undefined;
      const finalitySourceCommitment = settlementEvidenceBase
        ? sha256Hex(canonicalBytes({ chain_id: this.chainId, block_hash: settlementEvidenceBase.block_hash, block_number: settlementEvidenceBase.block_number, source: "evm_receipt_v1" }))
        : undefined;

      return {
        settled: receiptStatus === "success",
        settlement_backend: this.settlementBackendId,
        settlement_tx: checkpoint.settlement_tx,
        settlement_evidence: settlementEvidenceBase && settlementEventHash && receiptProofSourceCommitment && finalitySourceCommitment
          ? {
              ...settlementEvidenceBase,
              settlement_event_hash: settlementEventHash,
              receipt_proof_source_commitment: receiptProofSourceCommitment,
              finality_source_commitment: finalitySourceCommitment,
              chain_proof_commitment: sha256Hex(
                canonicalBytes({
                  settlement_event_hash: settlementEventHash,
                  receipt_proof_source_commitment: receiptProofSourceCommitment,
                  finality_source_commitment: finalitySourceCommitment
                })
              )
            }
          : undefined
      };
    } catch (error) {
      return {
        settled: false,
        settlement_backend: this.settlementBackendId,
        settlement_tx: checkpoint.settlement_tx,
        error: error instanceof Error ? error.message : "TSL_SETTLEMENT_UNAVAILABLE"
      };
    }
  }

  async getCheckpoint(epochStartMs: number, shard: string): Promise<BatchCheckpointV1 | null> {
    const stored = await this.readStoredCheckpoint(epochStartMs, shard);
    if (!stored || stored.submittedAt === 0n) return null;
    return {
      type: "tsl.batch_checkpoint.v1",
      epoch_start_ms: Number(stored.epochStartMs),
      epoch_duration_ms: Number(stored.epochDurationMs),
      shard,
      event_root: stored.eventRoot as Hex32,
      receipt_root: stored.receiptRoot as Hex32,
      attestation_root: stored.attestationRoot as Hex32,
      revocation_root: stored.revocationRoot as Hex32,
      event_count: Number(stored.eventCount),
      receipt_count: Number(stored.receiptCount),
      previous_checkpoint: stored.previousCheckpoint as Hex32,
      settlement_backend: this.settlementBackendId,
      relay_id: stored.relayId,
      relay_signature: "0x"
    };
  }

  async registerIdentity(identity: IdentityDocumentV1): Promise<string> {
    const key = identity.verification_methods.find((method) => method.status === "active") ?? identity.verification_methods[0];
    if (!key) throw new Error("Identity has no verification key");
    const contract = await this.optionalWritableContract(this.trustIDRegistryAddress, TRUST_ID_REGISTRY_ABI, "TSL_TRUST_ID_REGISTRY_MISSING");
    const tx = await contract.register(
      trustIdToBytes32(identity.id),
      keyIdToBytes32(key.id),
      identity.privacy_policy_commitment ?? ethers.ZeroHash
    );
    const receipt = await tx.wait();
    return receipt.hash;
  }

  async rotateIdentityKey(trustId: TrustID, oldKeyId: string, newKeyId: string): Promise<string> {
    const contract = await this.optionalWritableContract(this.trustIDRegistryAddress, TRUST_ID_REGISTRY_ABI, "TSL_TRUST_ID_REGISTRY_MISSING");
    const tx = await contract.rotateKey(trustIdToBytes32(trustId), keyIdToBytes32(oldKeyId), keyIdToBytes32(newKeyId));
    const receipt = await tx.wait();
    return receipt.hash;
  }

  async revokeIdentityKey(trustId: TrustID, keyId: string, reason: number): Promise<string> {
    const contract = await this.optionalWritableContract(this.trustIDRegistryAddress, TRUST_ID_REGISTRY_ABI, "TSL_TRUST_ID_REGISTRY_MISSING");
    const tx = await contract.revokeKey(trustIdToBytes32(trustId), keyIdToBytes32(keyId), reason);
    const receipt = await tx.wait();
    return receipt.hash;
  }

  async getActiveIdentityKey(trustId: TrustID): Promise<string | null> {
    if (!this.trustIDRegistryAddress) return null;
    const contract = this.optionalReadableContract(this.trustIDRegistryAddress, TRUST_ID_REGISTRY_ABI);
    const key = (await contract.getActiveKey(trustIdToBytes32(trustId))) as string;
    return key === ethers.ZeroHash ? null : key;
  }

  async isIdentityKeyRevoked(trustId: TrustID, keyId: string): Promise<boolean> {
    if (!this.trustIDRegistryAddress) return false;
    const contract = this.optionalReadableContract(this.trustIDRegistryAddress, TRUST_ID_REGISTRY_ABI);
    return Boolean(await contract.isRevoked(trustIdToBytes32(trustId), keyIdToBytes32(keyId)));
  }

  async recordRevocation(input: {
    trustId: TrustID;
    keyId: string;
    reason: number;
    effectiveAtMs: number;
    replacementKeyId?: string;
    controllerSignature?: string;
  }): Promise<string> {
    const contract = await this.optionalWritableContract(this.revocationRegistryAddress, REVOCATION_REGISTRY_ABI, "TSL_REVOCATION_REGISTRY_MISSING");
    const args = [
      trustIdToBytes32(input.trustId),
      keyIdToBytes32(input.keyId),
      input.reason,
      Math.floor(input.effectiveAtMs / 1000),
      input.replacementKeyId ? keyIdToBytes32(input.replacementKeyId) : ethers.ZeroHash
    ] as const;
    const tx = input.controllerSignature
      ? await contract.recordRevocationWithAuthorization(...args, input.controllerSignature)
      : await contract.recordRevocation(...args);
    const receipt = await tx.wait();
    return receipt.hash;
  }

  async isKeyRevokedAt(trustId: TrustID, keyId: string, atTimeMs: number): Promise<boolean> {
    if (!this.revocationRegistryAddress) return false;
    const contract = this.optionalReadableContract(this.revocationRegistryAddress, REVOCATION_REGISTRY_ABI);
    return Boolean(await contract.isRevoked(trustIdToBytes32(trustId), keyIdToBytes32(keyId), Math.floor(atTimeMs / 1000)));
  }

  async isProviderActive(providerId: TrustID): Promise<boolean> {
    if (!this.providerRegistryAddress) return false;
    const contract = this.optionalReadableContract(this.providerRegistryAddress, PROVIDER_REGISTRY_ABI);
    const provider = await contract.providers(providerIdToBytes32(providerId));
    return Boolean(provider.active ?? provider[2]);
  }

  async isModelRegistered(providerId: TrustID, modelVersion: string): Promise<boolean> {
    if (!this.providerRegistryAddress) return false;
    const contract = this.optionalReadableContract(this.providerRegistryAddress, PROVIDER_REGISTRY_ABI);
    const commitment = (await contract.modelCards(providerIdToBytes32(providerId), modelVersionToBytes32(modelVersion))) as string;
    return commitment !== ethers.ZeroHash;
  }

  private readableContract(): ethers.Contract {
    return new ethers.Contract(this.registryAddress, CHECKPOINT_REGISTRY_ABI, this.provider);
  }

  private async writableContract(): Promise<ethers.Contract> {
    return new ethers.Contract(this.registryAddress, CHECKPOINT_REGISTRY_ABI, await this.writeSigner());
  }

  private optionalReadableContract(address: string, abi: readonly string[]): ethers.Contract {
    return new ethers.Contract(address, abi, this.provider);
  }

  private async optionalWritableContract(address: string | undefined, abi: readonly string[], missingCode: string): Promise<ethers.Contract> {
    if (!address) throw new Error(missingCode);
    return new ethers.Contract(address, abi, await this.writeSigner());
  }

  private async writeSigner(): Promise<ethers.Signer> {
    return this.privateKey ? new ethers.Wallet(this.privateKey, this.provider) : this.provider.getSigner(0);
  }

  private async signRelayCheckpoint(contract: ethers.Contract, input: ReturnType<typeof toContractCheckpointInput>): Promise<string> {
    const checkpointHash = input.checkpointIdentityHash;
    const signer = await this.writeSigner();
    return signer.signMessage(ethers.getBytes(checkpointHash));
  }

  private async readStoredCheckpoint(epochStartMs: number, shard: string): Promise<ContractCheckpoint | null> {
    const contract = this.readableContract();
    const stored = (await contract.getCheckpointByEpochShard(epochStartMs, shardToBytes32(shard))) as ContractCheckpoint;
    return stored;
  }
}

export function createSettlementBackendFromEnv(env: NodeJS.ProcessEnv = process.env): LocalEvmSettlementBackend | null {
  const checkpointRegistryAddress = env.TSL_CHECKPOINT_REGISTRY_ADDRESS;
  if (!checkpointRegistryAddress) return null;
  return new LocalEvmSettlementBackend({
    rpcUrl: env.TSL_SETTLEMENT_RPC_URL ?? "http://127.0.0.1:8545",
    checkpointRegistryAddress,
    trustIDRegistryAddress: env.TSL_TRUST_ID_REGISTRY_ADDRESS,
    revocationRegistryAddress: env.TSL_REVOCATION_REGISTRY_ADDRESS,
    providerRegistryAddress: env.TSL_PROVIDER_REGISTRY_ADDRESS,
    privateKey: env.TSL_SETTLEMENT_PRIVATE_KEY,
    chainId: Number(env.TSL_SETTLEMENT_CHAIN_ID ?? 31337)
  });
}

export function shardToBytes32(shard: string): string {
  const normalized = shard.startsWith("0x") ? shard : `0x${shard}`;
  if (!/^0x[0-9a-fA-F]{1,64}$/.test(normalized)) {
    throw new Error(`Invalid shard hex: ${shard}`);
  }
  return ethers.zeroPadValue(normalized, 32);
}

export function relayIdToBytes32(relayId: string): string {
  if (/^0x[0-9a-fA-F]{64}$/.test(relayId)) return relayId;
  return ethers.id(relayId);
}

export function trustIdToBytes32(trustId: string): string {
  if (/^0x[0-9a-fA-F]{64}$/.test(trustId)) return trustId;
  return ethers.id(trustId);
}

export function keyIdToBytes32(keyId: string): string {
  if (/^0x[0-9a-fA-F]{64}$/.test(keyId)) return keyId;
  return ethers.id(keyId);
}

export function providerIdToBytes32(providerId: string): string {
  return trustIdToBytes32(providerId);
}

export function modelVersionToBytes32(modelVersion: string): string {
  if (/^0x[0-9a-fA-F]{64}$/.test(modelVersion)) return modelVersion;
  return ethers.id(modelVersion);
}

function toContractCheckpointInput(checkpoint: BatchCheckpointV1) {
  return {
    epochStartMs: BigInt(checkpoint.epoch_start_ms),
    epochDurationMs: checkpoint.epoch_duration_ms,
    shard: shardToBytes32(checkpoint.shard),
    eventRoot: checkpoint.event_root,
    receiptRoot: checkpoint.receipt_root,
    attestationRoot: checkpoint.attestation_root,
    revocationRoot: checkpoint.revocation_root,
    eventCount: BigInt(checkpoint.event_count),
    receiptCount: BigInt(checkpoint.receipt_count),
    previousCheckpoint: checkpoint.previous_checkpoint,
    checkpointIdentityHash: checkpointHash(checkpoint),
    relayId: relayIdToBytes32(checkpoint.relay_id),
    settlementBackend: checkpoint.settlement_backend ? ethers.id(checkpoint.settlement_backend) : ethers.ZeroHash
  };
}

export function contractCheckpointFieldsHashForCheckpoint(checkpoint: BatchCheckpointV1): Hex32 {
  const input = toContractCheckpointInput(checkpoint);
  const abi = ethers.AbiCoder.defaultAbiCoder();
  const rootsHash = ethers.keccak256(
    abi.encode(
      ["uint64", "uint32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
      [input.epochStartMs, input.epochDurationMs, input.shard, input.eventRoot, input.receiptRoot, input.attestationRoot, input.revocationRoot]
    )
  ) as Hex32;
  const countsHash = ethers.keccak256(abi.encode(["uint64", "uint64"], [input.eventCount, input.receiptCount])) as Hex32;
  return ethers.keccak256(
    abi.encode(
      ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
      [rootsHash, countsHash, input.previousCheckpoint, input.checkpointIdentityHash, input.relayId, input.settlementBackend]
    )
  ) as Hex32;
}

function checkpointMismatches(checkpoint: BatchCheckpointV1, stored: ContractCheckpoint): string[] {
  const expected = toContractCheckpointInput(checkpoint);
  const mismatches: string[] = [];
  if (stored.epochStartMs !== expected.epochStartMs) mismatches.push("epoch_start_ms");
  if (Number(stored.epochDurationMs) !== expected.epochDurationMs) mismatches.push("epoch_duration_ms");
  if (stored.shard.toLowerCase() !== expected.shard.toLowerCase()) mismatches.push("shard");
  if (stored.eventRoot.toLowerCase() !== expected.eventRoot.toLowerCase()) mismatches.push("event_root");
  if (stored.receiptRoot.toLowerCase() !== expected.receiptRoot.toLowerCase()) mismatches.push("receipt_root");
  if (stored.attestationRoot.toLowerCase() !== expected.attestationRoot.toLowerCase()) mismatches.push("attestation_root");
  if (stored.revocationRoot.toLowerCase() !== expected.revocationRoot.toLowerCase()) mismatches.push("revocation_root");
  if (stored.eventCount !== expected.eventCount) mismatches.push("event_count");
  if (stored.receiptCount !== expected.receiptCount) mismatches.push("receipt_count");
  if (stored.previousCheckpoint.toLowerCase() !== expected.previousCheckpoint.toLowerCase()) mismatches.push("previous_checkpoint");
  if (stored.settlementBackend && stored.settlementBackend.toLowerCase() !== expected.settlementBackend.toLowerCase()) mismatches.push("settlement_backend");
  if (stored.relayId.toLowerCase() !== expected.relayId.toLowerCase()) mismatches.push("relay_id");
  return mismatches;
}
