import { canonicalBytes } from "./canonicalize";
import { DOMAIN_TAGS, hashDomain, sha256Hex } from "./crypto";
import type { Hex32, TrustID, ZkThresholdProofV1 } from "./types";

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
}

type SnarkJsModule = {
  groth16: {
    fullProve(input: Record<string, string | number | bigint>, wasmPath: string, zkeyPath: string): Promise<{
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
  const witnessSignal = input.claim === "identity_age_days" ? "identity_age_days" : "reciprocal_receipt_count";
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    {
      [witnessSignal]: input.value,
      threshold: input.threshold,
      subject_hash: subjectHash
    },
    input.wasm_path,
    input.zkey_path
  );
  const verificationKey = await snarkjs.zKey.exportVerificationKey(input.zkey_path);
  return {
    ...base,
    groth16: {
      protocol: "groth16",
      curve: "bn128",
      proof,
      public_signals: publicSignals.map(String),
      verification_key: verificationKey
    }
  };
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

export async function verifyThresholdProofAsync(proof: ZkThresholdProofV1): Promise<boolean> {
  if (!verifyThresholdProof(proof)) return false;
  if (!proof.groth16) return true;
  if (!proof.groth16.verification_key) return false;
  if (!["identity_age_days", "reciprocal_receipt_count"].includes(proof.claim)) return false;
  const expectedSubjectHash = subjectHashField(proof.subject);
  const signals = proof.groth16.public_signals.map(String);
  if (!signals.includes(String(proof.threshold))) return false;
  if (!signals.includes(expectedSubjectHash)) return false;
  const snarkjs = await loadSnarkJs();
  return snarkjs.groth16.verify(proof.groth16.verification_key, signals, proof.groth16.proof);
}
