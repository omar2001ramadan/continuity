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
  production_circuit_input?: Record<string, unknown>;
  receipt_leaves?: string[];
  receipt_salts?: string[];
  counterparty_commitments?: string[];
  receipt_valid?: number[];
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
  let circuitInput: Record<string, unknown>;
  if (input.production_circuit_input) {
    circuitInput = {
      subject_hash: subjectHash,
      threshold: input.threshold,
      threshold_days: input.threshold,
      threshold_count: input.threshold,
      max_dispute_rate_bps: input.threshold,
      threshold_distance_bps: input.threshold,
      current_epoch_day: input.value,
      ...input.production_circuit_input
    };
    const missing = requiredProductionCircuitInputs(input.claim).filter((field) => !(field in circuitInput));
    if (missing.length > 0) throw new Error(`TSL_ZK_WITNESS_INTERFACE_INCOMPLETE:${missing.join(",")}`);
  } else if (input.claim === "identity_age_days") {
    circuitInput = {
      creation_epoch_day: 0,
      current_epoch_day: input.value,
      threshold: input.threshold,
      subject_hash: subjectHash,
      registry_leaf: subjectHash,
      registry_path: zeroPath,
      registry_path_bits: zeroBits
    };
  } else if (input.claim === "reciprocal_receipt_count") {
    const unsafeSynthetic = process.env.ALLOW_UNSAFE_ZK_SYNTHETIC_RECEIPTS === "true";
    const receiptLeaves =
      input.receipt_leaves ?? (unsafeSynthetic ? Array.from({ length: 8 }, (_, index) => (BigInt(subjectHash) + BigInt(index + 1) + BigInt(index + 101)).toString()) : undefined);
    const receiptSalts =
      input.receipt_salts ?? (unsafeSynthetic ? Array.from({ length: 8 }, (_, index) => String(index + 1)) : undefined);
    const counterpartyCommitments =
      input.counterparty_commitments ?? (unsafeSynthetic ? Array.from({ length: 8 }, (_, index) => String(index + 101)) : undefined);
    const receiptValid = input.receipt_valid ?? (unsafeSynthetic ? Array.from({ length: 8 }, () => 1) : undefined);
    if (!receiptLeaves?.length || !receiptSalts?.length || !counterpartyCommitments?.length || !receiptValid?.length) {
      throw new Error("TSL_ZK_RECEIPT_WITNESS_REQUIRED");
    }
    circuitInput = {
      reciprocal_receipt_count: input.value,
      threshold: input.threshold,
      threshold_count: input.threshold,
      subject_hash: subjectHash,
      receipt_leaves: receiptLeaves,
      receipt_salts: receiptSalts,
      counterparty_commitments: counterpartyCommitments,
      receipt_valid: receiptValid
    };
  } else if (process.env.ALLOW_UNSAFE_ZK_UNSUPPORTED_CIRCUITS === "true") {
    circuitInput = {
      value: input.value,
      threshold: input.threshold,
      subject_hash: subjectHash
    };
  } else {
    throw new Error("TSL_ZK_CIRCUIT_UNSUPPORTED_PRODUCTION_CLAIM");
  }
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

function requiredProductionCircuitInputs(claim: ZkThresholdProofV1["claim"]): string[] {
  switch (claim) {
    case "identity_age_days":
      return ["subject_hash", "creation_epoch_day", "current_epoch_day", "threshold_days", "public_registry_root", "registry_leaf", "registry_salt", "registry_siblings", "registry_path_bits"];
    case "reciprocal_receipt_count":
      return ["subject_hash", "threshold_count", "public_receipt_root", "receipt_leaves", "receipt_salts", "counterparty_commitments", "receipt_siblings", "receipt_path_bits", "receipt_valid"];
    case "dispute_rate_bound":
      return ["subject_hash", "max_dispute_rate_bps", "public_receipt_root", "completed_leaves", "disputed_leaves", "completed_siblings", "completed_path_bits", "disputed_siblings", "disputed_path_bits", "completed_valid", "disputed_valid"];
    case "set_membership":
      return ["subject_hash", "set_id", "public_set_root", "membership_leaf", "membership_salt", "membership_siblings", "membership_path_bits"];
    case "revocation_set_non_membership":
      return ["subject_hash", "key_hash", "revocation_pointer_hash", "value_commitment", "public_revocation_root", "sparse_leaf_index", "empty_leaf_commitment", "sibling_path", "path_bits"];
    case "organization_membership":
      return ["subject_hash", "org_hash", "issuer_hash", "current_epoch_day", "public_attestation_root", "issuer_registry_root", "attestation_leaf", "attestation_siblings", "attestation_path_bits", "issuer_leaf", "issuer_siblings", "issuer_path_bits", "not_expired_epoch_day"];
    case "agent_scope_compliance":
      return ["subject_hash", "agent_hash", "principal_hash", "action_hash", "parameter_values_hash", "policy_constraints_hash", "scope_commitment", "delegation_chain_root", "delegation_siblings", "delegation_path_bits", "human_approval_required", "human_approval_present"];
    case "private_graph_distance":
      return ["subject_hash", "threshold_distance_bps", "committed_local_neighborhood_root", "trusted_seed_commitment", "adversarial_seed_commitment", "aggregate_proof_commitment", "local_edge_weights_bps", "trusted_seed_scores_bps", "adversarial_seed_scores_bps", "local_edge_valid"];
  }
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

function isDevCircuitId(circuitId?: string): boolean {
  return (
    !circuitId ||
    circuitId.startsWith("dev_") ||
    circuitId.includes(":dev") ||
    circuitId.includes("fixture") ||
    circuitId.includes("prototype") ||
    circuitId === "identity-age-threshold-v1" ||
    circuitId === "reciprocal-receipt-count-threshold-v1" ||
    circuitId === "revocation-set-non-membership-v1" ||
    circuitId === "agent-scope-compliance-v1"
  );
}

const REQUIRED_WITNESS_FIELDS: Record<string, string[]> = {
  identity_age_days: ["creation_proof", "salt", "registry_path"],
  reciprocal_receipt_count: ["receipt_leaves", "counterparty_salts", "counterparties", "merkle_paths"],
  dispute_rate_bound: ["completed_receipt_leaves", "disputed_receipt_leaves", "merkle_paths"],
  set_membership: ["membership_leaf", "salt", "merkle_path"],
  revocation_set_non_membership: ["sparse_merkle_non_membership_path", "leaf_index", "value_commitment"],
  organization_membership: ["attestation_witness", "issuer_path"],
  agent_scope_compliance: ["parameter_values", "policy_witness", "delegation_path"],
  private_graph_distance: ["committed_local_neighborhood", "aggregate_proof", "seed_commitments"]
};

function manifestDeclaresWitnessInterface(manifest: ZkCircuitReleaseManifestV1): boolean {
  const required = REQUIRED_WITNESS_FIELDS[manifest.claim] ?? [];
  const schema = manifest.private_witness_schema ?? {};
  const properties = (schema.properties ?? {}) as Record<string, unknown>;
  const requiredList = Array.isArray(schema.required) ? schema.required.map(String) : [];
  return required.every((field) => field in properties || requiredList.includes(field));
}

export function zkProofUsesRegisteredCircuit(input: {
  proof: ZkThresholdProofV1;
  manifests?: ZkCircuitReleaseManifestV1[];
  registry?: ZkVerificationKeyRegistryV1;
}): boolean {
  const manifest = manifestForProof(input);
  if (!manifest || manifest.status !== "active") return false;
  if (isDevCircuitId(manifest.circuit_id) || isDevCircuitId(input.proof.circuit_id)) return false;
  if (!manifest.signature || !input.registry?.signature) return false;
  if (!manifest.hash_suite || !manifest.witness_interface) return false;
  if (!manifest.public_signal_schema || !manifest.private_witness_schema || !manifest.soundness_bits || !manifest.privacy_notes?.length) return false;
  if (manifest.soundness_bits < 100 || !manifestDeclaresWitnessInterface(manifest)) return false;
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
  if (options.reject_dev_circuits && process.env.TSL_NETWORK === "mainnet") {
    for (const flag of ["ALLOW_UNSAFE_ZK_HASH_FIXTURES", "ALLOW_UNSAFE_ZK_SYNTHETIC_RECEIPTS", "ALLOW_UNSAFE_ZK_UNSUPPORTED_CIRCUITS"]) {
      if (process.env[flag] === "true") return false;
    }
  }
	  if (!proof.groth16) return process.env.ALLOW_UNSAFE_ZK_HASH_FIXTURES === "true" && !(options.reject_dev_circuits && process.env.TSL_NETWORK === "mainnet");
	  if (!proof.groth16.verification_key) return false;
	  if (options.reject_dev_circuits && isDevCircuitId(proof.circuit_id)) return false;
	  const signals = proof.groth16.public_signals.map(String);
  if (proof.public_signal_commitment && proof.public_signal_commitment !== publicSignalCommitment(signals)) return false;
	  const manifest = manifestForProof({ proof, manifests: options.manifests });
	  const productionCircuitRequired = Boolean(options.require_registered_circuit || options.reject_dev_circuits);
	  if (productionCircuitRequired && !zkProofUsesRegisteredCircuit({ proof, manifests: options.manifests, registry: options.registry })) return false;
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
