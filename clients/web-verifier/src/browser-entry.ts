import {
  LocalEvmSettlementBackend,
  MemoryTrustResolver,
  verifyTSL,
  type IdentityDocumentV1,
  type ProofBundleV1,
  type VerificationResult,
  type VerifierPolicy
} from "../../../packages/verifier-ts/src/index";
import type { VerifyTSLInput } from "../../../packages/core-ts/src/types";

export interface BrowserVerifierOptions {
  rpcUrl?: string;
  checkpointRegistryAddress?: string;
  trustIDRegistryAddress?: string;
  revocationRegistryAddress?: string;
  providerRegistryAddress?: string;
  chainId?: number;
  policy?: VerifierPolicy;
}

function identityDocuments(bundle: ProofBundleV1): IdentityDocumentV1[] {
  return [bundle.identity];
}

function verificationInput(bundle: ProofBundleV1): VerifyTSLInput {
  return {
    envelope: bundle.envelope,
    proof: bundle.proof,
    checkpoint: bundle.checkpoint,
    receipts: bundle.receipts,
    attestations: bundle.attestations,
    revocations: bundle.revocations,
    assessment: bundle.assessment ?? undefined,
    assessment_v2: bundle.assessment_v2 ?? undefined,
    scoring_profile: bundle.scoring_profile,
    domain_policy: bundle.domain_policy,
    evidence_coverage: bundle.evidence_coverage,
    metadata_fingerprints: bundle.metadata_fingerprints,
    graph_profile: bundle.graph_profile,
    graph_feature_vector: bundle.graph_feature_vector,
    sybil_assessment: bundle.sybil_assessment,
    drift_report: bundle.drift_report,
    zk_proofs: bundle.zk_proofs,
    delegations: bundle.delegations,
    delegation_policies: bundle.delegation_policies,
    agent_actions: bundle.agent_actions,
    audit_findings: bundle.audit_findings,
    consistency_proofs: bundle.consistency_proofs,
    non_membership_proofs: bundle.non_membership_proofs,
    governance_policy: bundle.governance_policy,
    message_disclosure: bundle.message_disclosure
  };
}

export async function verifyBundle(bundle: ProofBundleV1, options: BrowserVerifierOptions = {}): Promise<VerificationResult> {
  const resolver = new MemoryTrustResolver(identityDocuments(bundle));
  const policy = options.policy ?? {
    require_inclusion: Boolean(bundle.proof),
    require_checkpoint: Boolean(bundle.checkpoint),
    require_settlement: Boolean(options.rpcUrl && options.checkpointRegistryAddress && bundle.checkpoint?.settlement_tx)
  };
  const settlementBackend =
    options.rpcUrl && options.checkpointRegistryAddress
      ? new LocalEvmSettlementBackend({
          rpcUrl: options.rpcUrl,
          checkpointRegistryAddress: options.checkpointRegistryAddress,
          trustIDRegistryAddress: options.trustIDRegistryAddress,
          revocationRegistryAddress: options.revocationRegistryAddress,
          providerRegistryAddress: options.providerRegistryAddress,
          chainId: options.chainId
        })
      : undefined;

  return verifyTSL(verificationInput(bundle), resolver, policy, settlementBackend);
}

function decodeBase64Url(payload: string): string {
  const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
  const padding = "=".repeat((4 - (normalized.length % 4)) % 4);
  return atob(normalized + padding);
}

export function decodeProofPayload(raw: string): ProofBundleV1 {
  const trimmed = raw.trim();
  if (trimmed.startsWith("{")) return JSON.parse(trimmed) as ProofBundleV1;
  if (trimmed.startsWith("tsl://proof/")) return JSON.parse(decodeBase64Url(trimmed.slice("tsl://proof/".length))) as ProofBundleV1;
  const payload = trimmed.includes("/p/") ? trimmed.slice(trimmed.lastIndexOf("/p/") + 3) : trimmed;
  return JSON.parse(decodeBase64Url(payload)) as ProofBundleV1;
}

declare global {
  interface Window {
    TSLWebVerifier: {
      decodeProofPayload: typeof decodeProofPayload;
      verifyBundle: typeof verifyBundle;
    };
  }
}

window.TSLWebVerifier = {
  decodeProofPayload,
  verifyBundle
};
