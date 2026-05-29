import { canonicalBytes } from "./canonicalize";
import { DOMAIN_TAGS, hashDomain, sha256Hex } from "./crypto";
import type { Hex32, TrustID, ZkCircuitReleaseManifestV1, ZkThresholdProofV1, ZkVerificationKeyRegistryV1 } from "./types";

export interface BuildThresholdProofInput {
  claim: ZkThresholdProofV1["claim"];
  subject: TrustID;
  value: number;
  threshold: number;
  witness_salt: Hex32;
  issued_at?: string;
}

export interface BuildGroth16ThresholdProofInput extends BuildThresholdProofInput {
  wasm_path: string;
  zkey_path: string;
  circuit_id?: string;
  verification_key_id?: string;
  release_manifest_hash?: Hex32;
}

type SnarkJsModule = {
  groth16: {
    fullProve(input: Record<string, unknown>, wasmPath: string, zkeyPath: string): Promise<{
      proof: unknown;
      publicSignals: string[];
    }>;
    verify(verificationKey: unknown, publicSignals: string[], proof: unknown): Promise<boolean>;
  };
  zKey: {
    exportVerificationKey(zkeyPath: string): Promise<unknown>;
  };
};

async function loadSnarkJs(): Promise<SnarkJsModule> {
  return (await import("snarkjs")) as unknown as SnarkJsModule;
}

export function subjectHashField(subject: TrustID): string {
  const digest = BigInt(sha256Hex(subject));
  // BN254 scalar field.
  const field = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  return (digest % field).toString();
}

export function buildThresholdProof(input: BuildThresholdProofInput): ZkThresholdProofV1 {
  if (!Number.isSafeInteger(input.value) || input.value < 0) throw new Error("TSL_ZK_VALUE_INVALID");
  if (!Number.isSafeInteger(input.threshold) || input.threshold < 0) throw new Error("TSL_ZK_THRESHOLD_INVALID");
  if (input.value < input.threshold) throw new Error("TSL_ZK_THRESHOLD_NOT_MET");
  const witnessCommitment = hashDomain(
    DOMAIN_TAGS.ZK_THRESHOLD_V1,
    canonicalBytes({
      claim: input.claim,
      subject: input.subject,
      value: input.value,
      salt: input.witness_salt
    })
  );
  const publicInputHash = hashDomain(
    DOMAIN_TAGS.ZK_THRESHOLD_V1,
    canonicalBytes({
      claim: input.claim,
      subject: input.subject,
      threshold: input.threshold,
      witness_commitment: witnessCommitment
    })
  );
  return {
    type: "tsl.zk.threshold_proof.v1",
    claim: input.claim,
    subject: input.subject,
    threshold: input.threshold,
    witness_commitment: witnessCommitment,
    public_input_hash: publicInputHash,
    proof: hashDomain(
      DOMAIN_TAGS.ZK_THRESHOLD_V1,
      canonicalBytes({
        public_input_hash: publicInputHash,
        value: input.value,
        salt: input.witness_salt
      })
    ),
    issued_at: input.issued_at ?? new Date().toISOString()
  };
}

export async function buildGroth16ThresholdProof(input: BuildGroth16ThresholdProofInput): Promise<ZkThresholdProofV1> {
  const base = buildThresholdProof(input);
  const snarkjs = await loadSnarkJs();
  const subjectHash = subjectHashField(input.subject);
  const zeroPath = ["0", "0", "0", "0"];
  const zeroBits = [0, 0, 0, 0];
  const receiptLeaves = Array.from({ length: 8 }, (_, index) => (BigInt(subjectHash) + BigInt(index + 1) + BigInt(index + 101)).toString());
  const receiptSalts = Array.from({ length: 8 }, (_, index) => String(index + 1));
  const counterpartyCommitments = Array.from({ length: 8 }, (_, index) => String(index + 101));
  const circuitInput =
    input.claim === "identity_age_days"
      ? {
          creation_epoch_day: 0,
          current_epoch_day: input.value,
          threshold: input.threshold,
          subject_hash: subjectHash,
          registry_leaf: subjectHash,
          registry_path: zeroPath,
          registry_path_bits: zeroBits
        }
      : {
          reciprocal_receipt_count: input.value,
          threshold: input.threshold,
          subject_hash: subjectHash,
          receipt_leaves: receiptLeaves,
          receipt_salts: receiptSalts,
          counterparty_commitments: counterpartyCommitments,
          receipt_valid: Array.from({ length: 8 }, () => 1)
        };
  const { proof, publicSignals: rawPublicSignals } = await snarkjs.groth16.fullProve(
    circuitInput,
    input.wasm_path,
    input.zkey_path
  );
  const verificationKey = await snarkjs.zKey.exportVerificationKey(input.zkey_path);
  const publicSignals = publicSignalsToStrings(rawPublicSignals);
  return {
    ...base,
    ...(input.circuit_id ? { circuit_id: input.circuit_id } : {}),
    ...(input.verification_key_id ? { verification_key_id: input.verification_key_id } : {}),
    public_signal_commitment: publicSignalCommitment(publicSignals),
    ...(input.release_manifest_hash ? { release_manifest_hash: input.release_manifest_hash } : {}),
    groth16: {
      protocol: "groth16",
      curve: "bn128",
      proof,
      public_signals: publicSignals,
      verification_key: verificationKey
    }
  };
}

function publicSignalsToStrings(publicSignals: Array<string | number | bigint>): string[] {
  return publicSignals.map(String);
}

export function publicSignalCommitment(publicSignals: string[]): Hex32 {
  return hashDomain(DOMAIN_TAGS.ZK_THRESHOLD_V1, canonicalBytes(publicSignals.map(String)));
}

export function zkCircuitReleaseManifestHash(manifest: ZkCircuitReleaseManifestV1): Hex32 {
  return hashDomain("tsl.zk.circuit_release_manifest.v1", canonicalBytes(manifest));
}

export function zkVerificationKeyRegistryHash(registry: ZkVerificationKeyRegistryV1): Hex32 {
  return hashDomain("tsl.zk.verification_key_registry.v1", canonicalBytes(registry));
}

export function zkVerificationKeyObjectHash(verificationKey: unknown): Hex32 {
  return sha256Hex(canonicalBytes(verificationKey));
}

function manifestForProof(input: {
  proof: ZkThresholdProofV1;
  manifests?: ZkCircuitReleaseManifestV1[];
}): ZkCircuitReleaseManifestV1 | undefined {
  return input.manifests?.find((manifest) => {
    const manifestHash = zkCircuitReleaseManifestHash(manifest);
    return (
      manifest.claim === input.proof.claim &&
      manifest.circuit_id === input.proof.circuit_id &&
      manifest.verification_key_id === input.proof.verification_key_id &&
      manifestHash === input.proof.release_manifest_hash
    );
  });
}

export function zkProofUsesRegisteredCircuit(input: {
  proof: ZkThresholdProofV1;
  manifests?: ZkCircuitReleaseManifestV1[];
  registry?: ZkVerificationKeyRegistryV1;
}): boolean {
  const manifest = manifestForProof(input);
  if (!manifest || manifest.status !== "active") return false;
  const manifestHash = zkCircuitReleaseManifestHash(manifest);
  if (!input.registry) return false;
  return input.registry.active_manifest_hashes.includes(manifestHash) && !input.registry.revoked_manifest_hashes.includes(manifestHash);
}

export function verifyThresholdProof(proof: ZkThresholdProofV1): boolean {
  if (proof.type !== "tsl.zk.threshold_proof.v1") return false;
  if (!Number.isSafeInteger(proof.threshold) || proof.threshold < 0) return false;
  const expectedPublicInputHash = hashDomain(
    DOMAIN_TAGS.ZK_THRESHOLD_V1,
    canonicalBytes({
      claim: proof.claim,
      subject: proof.subject,
      threshold: proof.threshold,
      witness_commitment: proof.witness_commitment
    })
  );
  return expectedPublicInputHash === proof.public_input_hash && /^0x[0-9a-f]{64}$/.test(proof.proof);
}

export async function verifyThresholdProofAsync(
  proof: ZkThresholdProofV1,
  options: {
    require_registered_circuit?: boolean;
    require_manifest_verification_key_hash?: boolean;
    reject_dev_circuits?: boolean;
    manifests?: ZkCircuitReleaseManifestV1[];
    registry?: ZkVerificationKeyRegistryV1;
  } = {}
): Promise<boolean> {
  if (!verifyThresholdProof(proof)) return false;
  if (!proof.groth16) return process.env.ALLOW_UNSAFE_ZK_HASH_FIXTURES === "true";
  if (!proof.groth16.verification_key) return false;
  const signals = proof.groth16.public_signals.map(String);
  if (proof.public_signal_commitment && proof.public_signal_commitment !== publicSignalCommitment(signals)) return false;
  const manifest = manifestForProof({ proof, manifests: options.manifests });
  if (options.require_registered_circuit && !zkProofUsesRegisteredCircuit({ proof, manifests: options.manifests, registry: options.registry })) return false;
  if (options.reject_dev_circuits && manifest?.status !== "active") return false;
  const requireManifestKeyHash = Boolean(options.require_manifest_verification_key_hash || options.require_registered_circuit || options.reject_dev_circuits);
  if (requireManifestKeyHash && !manifest?.verification_key) return false;
  const verificationKey = manifest?.verification_key ?? proof.groth16.verification_key;
  if (requireManifestKeyHash) {
    if (!manifest) return false;
    if (zkVerificationKeyObjectHash(verificationKey) !== manifest.verification_key_hash) return false;
  }
  const thresholdClaim = proof.claim === "identity_age_days" || proof.claim === "reciprocal_receipt_count";
  if (!thresholdClaim && !options.require_registered_circuit) return false;
  const expectedSubjectHash = subjectHashField(proof.subject);
  if (!signals.includes(expectedSubjectHash)) return false;
  if (thresholdClaim && !signals.includes(String(proof.threshold))) return false;
  const snarkjs = await loadSnarkJs();
  return snarkjs.groth16.verify(verificationKey, signals, proof.groth16.proof);
}
