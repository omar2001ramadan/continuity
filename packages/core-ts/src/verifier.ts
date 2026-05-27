import {
  assessmentHash,
  attestationHash,
  contentCommitment,
  eventHash,
  commitmentHashFromParts,
  receiptHash,
  revocationHash,
  auditFindingHash,
  governancePolicyHash,
  verifyEd25519
} from "./crypto";
import { verifyAgentDelegation } from "./agent";
import { verifyConsistencyProof } from "./consistency";
import { findVerificationMethod, keyActiveAt, notRevokedAt } from "./identity";
import { verifyInclusion } from "./merkle";
import { verifyNonMembershipProof } from "./nonMembership";
import { checkpointHash } from "./relayStore";
import type { SettlementBackend } from "./settlement";
import type { BatchCheckpointV1, TrustResolver, VerificationChecks, VerificationResult, VerifierPolicy, VerifyTSLInput } from "./types";
import { validateSchema } from "./validation";
import { verifyThresholdProofAsync } from "./zk";
import {
  agentActionV2Hash,
  delegationPolicyV2Hash,
  driftReportV1Hash,
  graphFeatureVectorV1Hash,
  metadataFingerprintCommitmentV1Hash,
  scoringProfileV2Hash,
  sybilAssessmentV1Hash,
  trustAssessmentV2Hash,
  verifyDelegatedAgentActionV0
} from "./v2";

const defaultChecks = (): VerificationChecks => ({
  schema_valid: false,
  signature_valid: false,
  key_found: false,
  key_active: false,
  not_revoked: false,
  included_in_log: false,
  checkpoint_valid: false,
  checkpoint_matches_proof: false,
  checkpoint_settled: false
});

function checkpointRootForKind(checkpoint: BatchCheckpointV1, kind: string): string | undefined {
  if (kind === "event") return checkpoint.event_root;
  if (kind === "receipt") return checkpoint.receipt_root;
  if (kind === "attestation") return checkpoint.attestation_root;
  if (kind === "revocation") return checkpoint.revocation_root;
  return undefined;
}

export async function verifyTSL(
  input: VerifyTSLInput,
  resolver: TrustResolver,
  policy: VerifierPolicy = {},
  settlementBackend?: SettlementBackend
): Promise<VerificationResult> {
  const checks = defaultChecks();
  const errors: string[] = [];
  const explanation: string[] = [];
  let settlementStatus: VerificationResult["settlement_status"] = policy.require_settlement ? "pending" : "not_required";
  let riskLabel: VerificationResult["risk_label"] = "not_assessed";

  const eventValidation = validateSchema("event", input.envelope);
  checks.schema_valid = eventValidation.valid;
  if (!eventValidation.valid) {
    errors.push("TSL_SCHEMA_INVALID", ...eventValidation.errors);
    return { verified: false, checks, risk_label: "not_assessed", explanation, errors };
  }

  const unsignedEventHash = eventHash(input.envelope);
  const identity = await resolver.resolveTrustID(input.envelope.sender, input.envelope.timestamp);
  if (!identity) {
    errors.push("TSL_KEY_NOT_FOUND");
    return {
      verified: false,
      event_hash: unsignedEventHash,
      checks,
      risk_label: "not_assessed",
      explanation,
      errors
    };
  }

  const key = findVerificationMethod(identity, input.envelope.signing_key_id);
  checks.key_found = key !== null;
  checks.key_active = keyActiveAt(key, input.envelope.timestamp);
  checks.not_revoked = notRevokedAt(key);

  if (key?.type === "ed25519") {
    checks.signature_valid = verifyEd25519(key.public_key, unsignedEventHash, input.envelope.signature);
  }

  const commitmentHash = commitmentHashFromParts(unsignedEventHash, input.envelope.signature);

  if (policy.require_chain_revocation) {
    if (settlementBackend?.isKeyRevokedAt) {
      checks.chain_revocation_checked = true;
      const revokedOnChain = await settlementBackend.isKeyRevokedAt(
        input.envelope.sender,
        input.envelope.signing_key_id,
        Date.parse(input.envelope.timestamp)
      );
      if (revokedOnChain) {
        checks.not_revoked = false;
        errors.push("TSL_KEY_REVOKED");
      }
    } else {
      checks.chain_revocation_checked = false;
      errors.push("TSL_CHAIN_REVOCATION_UNAVAILABLE");
    }
  }

  if (checks.signature_valid) explanation.push("Signature valid");
  if (checks.key_active) explanation.push("Key active at event timestamp");
  if (checks.not_revoked) explanation.push("No active key revocation in resolved identity state");

  if (input.revocations?.length) {
    checks.revocation_state_valid = true;
    for (const revocation of input.revocations) {
      const validation = validateSchema("revocation", revocation);
      if (!validation.valid) {
        checks.revocation_state_valid = false;
        errors.push("TSL_REVOCATION_INVALID", ...validation.errors);
        continue;
      }
      const revocationIdentity = await resolver.resolveTrustID(revocation.trust_id, revocation.effective_at);
      const revocationKey =
        revocationIdentity?.verification_methods.find((method) => method.status === "active") ??
        (revocationIdentity ? findVerificationMethod(revocationIdentity, revocation.revoked_key) : null);
      const revocationSignatureValid =
        revocationKey?.type === "ed25519" ? verifyEd25519(revocationKey.public_key, revocationHash(revocation), revocation.signature) : false;
      if (!revocationSignatureValid) {
        checks.revocation_state_valid = false;
        errors.push("TSL_REVOCATION_SIGNATURE_INVALID");
      }
      if (
        revocation.trust_id === input.envelope.sender &&
        revocation.revoked_key === input.envelope.signing_key_id &&
        Date.parse(revocation.effective_at) <= Date.parse(input.envelope.timestamp)
      ) {
        checks.not_revoked = false;
        checks.revocation_state_valid = false;
        errors.push("TSL_KEY_REVOKED");
      }
    }
    if (checks.revocation_state_valid) explanation.push("Signed revocation state is valid");
  }

  if (input.message_disclosure?.raw_message !== undefined && input.message_disclosure.content_salt) {
    checks.content_commitment_matches =
      contentCommitment(input.message_disclosure.raw_message, input.message_disclosure.content_salt) ===
      input.envelope.content_commitment;
    if (checks.content_commitment_matches) {
      explanation.push("Disclosed message matches content commitment");
    }
  }

  if (input.proof) {
    const proofValidation = validateSchema("inclusionProof", input.proof);
    if (!proofValidation.valid) {
      errors.push("TSL_INCLUSION_INVALID", ...proofValidation.errors);
    } else {
      checks.included_in_log = input.proof.tree_kind === "event" && input.proof.commitment === commitmentHash && verifyInclusion(input.proof);
      if (checks.included_in_log) explanation.push("Event included in Merkle log proof");
      if (input.proof.tree_kind === "receipt") checks.receipt_included = verifyInclusion(input.proof);
      if (input.proof.tree_kind === "attestation") checks.attestation_included = verifyInclusion(input.proof);
      if (input.proof.tree_kind === "revocation") checks.revocation_included = verifyInclusion(input.proof);
    }
  }

  if (input.receipts?.length) {
    checks.receipt_valid = true;
    for (const receipt of input.receipts) {
      const validation = validateSchema("receipt", receipt);
      if (!validation.valid) {
        checks.receipt_valid = false;
        errors.push("TSL_RECEIPT_INVALID", ...validation.errors);
        continue;
      }
      const receiptIdentity = await resolver.resolveTrustID(receipt.receiver, receipt.timestamp);
      const receiptKey = receiptIdentity ? findVerificationMethod(receiptIdentity, receipt.signing_key_id) : null;
      const valid =
        receipt.event_commitment === commitmentHash &&
        receiptKey?.type === "ed25519" &&
        keyActiveAt(receiptKey, receipt.timestamp) &&
        verifyEd25519(receiptKey.public_key, receiptHash(receipt), receipt.signature);
      if (!valid) {
        checks.receipt_valid = false;
        errors.push("TSL_RECEIPT_INVALID");
      }
    }
    if (checks.receipt_valid) explanation.push("Receipt signatures valid");
  }

  if (input.attestations?.length) {
    checks.attestation_valid = true;
    for (const attestation of input.attestations) {
      const validation = validateSchema("attestation", attestation);
      if (!validation.valid) {
        checks.attestation_valid = false;
        errors.push("TSL_ATTESTATION_INVALID", ...validation.errors);
        continue;
      }
      const issuerIdentity = await resolver.resolveTrustID(attestation.issuer, attestation.issued_at);
      const issuerKey = issuerIdentity?.verification_methods.find((method) => keyActiveAt(method, attestation.issued_at));
      const valid =
        attestation.subject === input.envelope.sender &&
        issuerKey?.type === "ed25519" &&
        verifyEd25519(issuerKey.public_key, attestationHash(attestation), attestation.signature);
      if (!valid) {
        checks.attestation_valid = false;
        errors.push("TSL_ATTESTATION_INVALID");
      }
    }
    if (checks.attestation_valid) explanation.push("Attestation signatures valid");
  }

  if (input.assessment) {
    const validation = validateSchema("trustAssessment", input.assessment);
    const issuerIdentity = validation.valid ? await resolver.resolveTrustID(input.assessment.issuer, input.assessment.issued_at) : null;
    const issuerKey = issuerIdentity?.verification_methods.find((method) => keyActiveAt(method, input.assessment!.issued_at));
    const providerAllowed =
      !policy.accepted_scoring_providers?.length || policy.accepted_scoring_providers.includes(input.assessment.issuer);
    const maxAgeOk =
      policy.max_assessment_age_ms === undefined ||
      Date.now() - Date.parse(input.assessment.issued_at) <= policy.max_assessment_age_ms;
    const hasEvidence =
      Boolean(input.assessment.evidence_commitment) &&
      Array.isArray(input.assessment.features_disclosed) &&
      input.assessment.features_disclosed.length > 0 &&
      Array.isArray(input.assessment.explanation) &&
      input.assessment.explanation.length > 0;
    if (policy.require_provider_registry) {
      if (settlementBackend?.isProviderActive && settlementBackend?.isModelRegistered) {
        checks.provider_active = await settlementBackend.isProviderActive(input.assessment.issuer);
        checks.model_registered = await settlementBackend.isModelRegistered(input.assessment.issuer, input.assessment.model_version);
      } else {
        checks.provider_active = false;
        checks.model_registered = false;
        errors.push("TSL_PROVIDER_REGISTRY_UNAVAILABLE");
      }
    }
    checks.assessment_valid =
      validation.valid &&
      input.assessment.subject === input.envelope.sender &&
      Date.parse(input.assessment.expires_at) > Date.now() &&
      providerAllowed &&
      maxAgeOk &&
      hasEvidence &&
      (!policy.require_provider_registry || (checks.provider_active === true && checks.model_registered === true)) &&
      issuerKey?.type === "ed25519" &&
      verifyEd25519(issuerKey.public_key, assessmentHash(input.assessment), input.assessment.signature);
    if (checks.assessment_valid) {
      explanation.push("Signed trust assessment is valid");
      riskLabel = input.assessment.label;
    } else {
      errors.push("TSL_ASSESSMENT_INVALID", ...validation.errors);
      if (!providerAllowed) errors.push("TSL_PROVIDER_NOT_ACCEPTED");
      if (!maxAgeOk) errors.push("TSL_ASSESSMENT_TOO_OLD");
      if (!hasEvidence) errors.push("TSL_ASSESSMENT_EVIDENCE_INCOMPLETE");
      if (policy.require_provider_registry && checks.provider_active === false) errors.push("TSL_PROVIDER_INACTIVE");
      if (policy.require_provider_registry && checks.model_registered === false) errors.push("TSL_MODEL_NOT_REGISTERED");
    }
  }

  if (input.scoring_profile || input.assessment_v2 || policy.require_v2_assessment) {
    if (input.scoring_profile) {
      const validation = validateSchema("scoringProfileV2", input.scoring_profile);
      const providerIdentity = validation.valid ? await resolver.resolveTrustID(input.scoring_profile.provider, input.scoring_profile.issued_at) : null;
      const providerKey = providerIdentity?.verification_methods.find((method) => keyActiveAt(method, input.scoring_profile!.issued_at));
      const acceptedProfile =
        !policy.accepted_scoring_profiles?.length || policy.accepted_scoring_profiles.includes(input.scoring_profile.profile_id);
      checks.scoring_profile_valid = Boolean(
        validation.valid &&
          acceptedProfile &&
          Date.parse(input.scoring_profile.valid_after) <= Date.parse(input.envelope.timestamp) &&
          Date.parse(input.scoring_profile.expires_at) > Date.parse(input.envelope.timestamp) &&
          providerKey?.type === "ed25519" &&
          verifyEd25519(providerKey.public_key, scoringProfileV2Hash(input.scoring_profile), input.scoring_profile.signature)
      );
      if (!checks.scoring_profile_valid) {
        errors.push("TSL_SCORING_PROFILE_INVALID", ...validation.errors);
        if (!acceptedProfile) errors.push("TSL_SCORING_PROFILE_NOT_ACCEPTED");
      }
    } else if (policy.require_v2_assessment) {
      checks.scoring_profile_valid = false;
      errors.push("TSL_SCORING_PROFILE_MISSING");
    }

    if (input.domain_policy) {
      const validation = validateSchema("domainPolicyV1", input.domain_policy);
      checks.domain_policy_valid =
        validation.valid && (!policy.required_domain_policy || input.domain_policy.domain === policy.required_domain_policy);
      if (!checks.domain_policy_valid) errors.push("TSL_DOMAIN_POLICY_INVALID", ...validation.errors);
    } else if (policy.required_domain_policy) {
      checks.domain_policy_valid = false;
      errors.push("TSL_DOMAIN_POLICY_MISSING");
    }

    if (input.evidence_coverage) {
      const validation = validateSchema("evidenceCoverageV1", input.evidence_coverage);
      checks.evidence_coverage_valid = validation.valid;
      if (!checks.evidence_coverage_valid) errors.push("TSL_EVIDENCE_COVERAGE_INVALID", ...validation.errors);
    }

    if (input.assessment_v2) {
      const validation = validateSchema("trustAssessmentV2", input.assessment_v2);
      const issuerIdentity = validation.valid ? await resolver.resolveTrustID(input.assessment_v2.issuer, input.assessment_v2.issued_at) : null;
      const issuerKey = issuerIdentity?.verification_methods.find((method) => keyActiveAt(method, input.assessment_v2!.issued_at));
      const profileMatches =
        !input.scoring_profile || input.assessment_v2.scoring_profile_id === input.scoring_profile.profile_id;
      const domainMatches = !input.domain_policy || input.assessment_v2.domain === input.domain_policy.domain;
      checks.trust_assessment_v2_valid = Boolean(
        validation.valid &&
          input.assessment_v2.subject === input.envelope.sender &&
          Date.parse(input.assessment_v2.expires_at) > Date.now() &&
          profileMatches &&
          domainMatches &&
          issuerKey?.type === "ed25519" &&
          verifyEd25519(issuerKey.public_key, trustAssessmentV2Hash(input.assessment_v2), input.assessment_v2.signature)
      );
      if (checks.trust_assessment_v2_valid) {
        explanation.push("Signed v2 trust assessment is valid");
        riskLabel =
          input.assessment_v2.label === "cryptographic_failure" ||
          input.assessment_v2.label === "settlement_missing" ||
          input.assessment_v2.label === "revoked_or_compromised"
            ? "high_risk"
            : input.assessment_v2.label;
      } else {
        errors.push("TSL_TRUST_ASSESSMENT_V2_INVALID", ...validation.errors);
      }
    } else if (policy.require_v2_assessment) {
      checks.trust_assessment_v2_valid = false;
      errors.push("TSL_TRUST_ASSESSMENT_V2_MISSING");
    }
  }

  if (input.metadata_fingerprints?.length || policy.require_metadata_fingerprint_policy) {
    checks.metadata_fingerprint_valid = true;
    for (const fingerprint of input.metadata_fingerprints ?? []) {
      const validation = validateSchema("metadataFingerprintCommitmentV1", fingerprint);
      const subjectIdentity = validation.valid ? await resolver.resolveTrustID(fingerprint.subject, fingerprint.expires_at) : null;
      const subjectKey = subjectIdentity?.verification_methods.find((method) => keyActiveAt(method, input.envelope.timestamp));
      const valid =
        validation.valid &&
        fingerprint.subject === input.envelope.sender &&
        subjectKey?.type === "ed25519" &&
        verifyEd25519(subjectKey.public_key, metadataFingerprintCommitmentV1Hash(fingerprint), fingerprint.signature);
      if (!valid) {
        checks.metadata_fingerprint_valid = false;
        errors.push("TSL_METADATA_FINGERPRINT_INVALID", ...validation.errors);
      }
    }
    if (policy.require_metadata_fingerprint_policy && !input.metadata_fingerprints?.length) {
      checks.metadata_fingerprint_valid = false;
      errors.push("TSL_METADATA_FINGERPRINT_MISSING");
    }
  }

  if (input.graph_profile || input.graph_feature_vector || input.sybil_assessment || input.drift_report || policy.require_graph_artifacts) {
    const graphProfileValidation = input.graph_profile ? validateSchema("graphProfileV2", input.graph_profile) : undefined;
    const graphVectorValidation = input.graph_feature_vector ? validateSchema("graphFeatureVectorV1", input.graph_feature_vector) : undefined;
    const sybilValidation = input.sybil_assessment ? validateSchema("sybilAssessmentV1", input.sybil_assessment) : undefined;
    const driftValidation = input.drift_report ? validateSchema("driftReportV1", input.drift_report) : undefined;
    checks.graph_artifacts_valid = Boolean(
      (!input.graph_profile || graphProfileValidation?.valid) &&
        (!input.graph_feature_vector || graphVectorValidation?.valid) &&
        (!input.sybil_assessment || sybilValidation?.valid) &&
        (!input.drift_report || driftValidation?.valid)
    );
    if (input.graph_feature_vector) {
      const subjectIdentity = await resolver.resolveTrustID(input.graph_feature_vector.subject, input.graph_feature_vector.computed_at);
      const subjectKey = subjectIdentity?.verification_methods.find((method) => keyActiveAt(method, input.graph_feature_vector!.computed_at));
      checks.graph_artifacts_valid =
        checks.graph_artifacts_valid &&
        input.graph_feature_vector.subject === input.envelope.sender &&
        subjectKey?.type === "ed25519" &&
        verifyEd25519(subjectKey.public_key, graphFeatureVectorV1Hash(input.graph_feature_vector), input.graph_feature_vector.signature);
    }
    if (input.sybil_assessment) {
      const subjectIdentity = await resolver.resolveTrustID(input.sybil_assessment.subject, input.sybil_assessment.computed_at);
      const subjectKey = subjectIdentity?.verification_methods.find((method) => keyActiveAt(method, input.sybil_assessment!.computed_at));
      checks.sybil_assessment_valid = Boolean(
        input.sybil_assessment.subject === input.envelope.sender &&
          subjectKey?.type === "ed25519" &&
          verifyEd25519(subjectKey.public_key, sybilAssessmentV1Hash(input.sybil_assessment), input.sybil_assessment.signature)
      );
      checks.graph_artifacts_valid = checks.graph_artifacts_valid && checks.sybil_assessment_valid;
    }
    if (input.drift_report) {
      const subjectIdentity = await resolver.resolveTrustID(input.drift_report.subject, input.drift_report.computed_at);
      const subjectKey = subjectIdentity?.verification_methods.find((method) => keyActiveAt(method, input.drift_report!.computed_at));
      checks.drift_report_valid = Boolean(
        input.drift_report.subject === input.envelope.sender &&
          subjectKey?.type === "ed25519" &&
          verifyEd25519(subjectKey.public_key, driftReportV1Hash(input.drift_report), input.drift_report.signature)
      );
      checks.graph_artifacts_valid = checks.graph_artifacts_valid && checks.drift_report_valid;
    }
    if (policy.require_graph_artifacts && !checks.graph_artifacts_valid) {
      errors.push("TSL_GRAPH_ARTIFACTS_INVALID");
      if (graphProfileValidation) errors.push(...graphProfileValidation.errors);
      if (graphVectorValidation) errors.push(...graphVectorValidation.errors);
      if (sybilValidation) errors.push(...sybilValidation.errors);
      if (driftValidation) errors.push(...driftValidation.errors);
    }
  }

  if (input.zk_proofs?.length || policy.require_zk_claims?.length) {
    checks.zk_valid = true;
    const validClaims = new Set<string>();
    for (const proof of input.zk_proofs ?? []) {
      const validation = validateSchema("zkThresholdProof", proof);
      const valid = validation.valid && proof.subject === input.envelope.sender && (await verifyThresholdProofAsync(proof));
      if (valid) {
        validClaims.add(proof.claim);
      } else {
        checks.zk_valid = false;
        errors.push("TSL_ZK_PROOF_INVALID", ...validation.errors);
      }
    }
    for (const requiredClaim of policy.require_zk_claims ?? []) {
      if (!validClaims.has(requiredClaim)) {
        checks.zk_valid = false;
        errors.push("TSL_ZK_CLAIM_MISSING");
      }
    }
    if (checks.zk_valid) explanation.push("Required selective-disclosure threshold proofs are valid");
  }

  if (input.delegations?.length || policy.require_agent_scope) {
    checks.agent_scope_valid = true;
    let matchedRequiredScope = false;
    for (const delegation of input.delegations ?? []) {
      const validation = validateSchema("agentDelegation", delegation);
      const scopeToCheck = delegation.agent === input.envelope.sender ? policy.require_agent_scope : undefined;
      const valid =
        validation.valid &&
        delegation.agent === input.envelope.sender &&
        (await verifyAgentDelegation(delegation, resolver, scopeToCheck, input.envelope.timestamp));
      if (valid && (!policy.require_agent_scope || delegation.scope.includes(policy.require_agent_scope))) {
        matchedRequiredScope = true;
      }
      if (!valid) {
        checks.agent_scope_valid = false;
        errors.push("TSL_AGENT_SCOPE_INVALID", ...validation.errors);
      }
    }
    if (policy.require_agent_scope && !matchedRequiredScope) {
      checks.agent_scope_valid = false;
      errors.push("TSL_AGENT_SCOPE_INVALID");
    }
    if (checks.agent_scope_valid) explanation.push("Agent delegation scope is valid");
  }

  if (input.agent_actions?.length || input.delegation_policies?.length) {
    checks.delegated_action_valid = true;
    const publicKeys: Record<string, string> = {};
    for (const policyObject of input.delegation_policies ?? []) {
      const validation = validateSchema("delegationPolicyV2", policyObject);
      const principalIdentity = validation.valid ? await resolver.resolveTrustID(policyObject.principal, policyObject.valid_from) : null;
      const principalKey = principalIdentity?.verification_methods.find((method) => keyActiveAt(method, policyObject.valid_from));
      if (!validation.valid || principalKey?.type !== "ed25519" || !verifyEd25519(principalKey.public_key, delegationPolicyV2Hash(policyObject), policyObject.signature)) {
        checks.delegated_action_valid = false;
        errors.push("TSL_DELEGATION_POLICY_INVALID", ...validation.errors);
      } else {
        publicKeys[policyObject.principal] = principalKey.public_key;
      }
    }
    for (const action of input.agent_actions ?? []) {
      const validation = validateSchema("agentActionV2", action);
      const agentIdentity = validation.valid ? await resolver.resolveTrustID(action.agent, action.issued_at) : null;
      const agentKey = agentIdentity?.verification_methods.find((method) => keyActiveAt(method, action.issued_at));
      if (agentKey?.type === "ed25519") publicKeys[action.agent] = agentKey.public_key;
      const result =
        validation.valid && input.delegation_policies
          ? verifyDelegatedAgentActionV0({
              action,
              delegation_chain: input.delegation_policies,
              public_keys: publicKeys,
              at_time: input.envelope.timestamp
            })
          : { ok: false, error_code: "TSL_DELEGATION_POLICY_MISSING" };
      if (!result.ok) {
        checks.delegated_action_valid = false;
        errors.push(result.error_code ?? "TSL_DELEGATED_ACTION_INVALID", ...validation.errors);
      }
    }
  }

  if (input.consistency_proofs?.length || policy.require_consistency_proof) {
    checks.consistency_proof_valid = true;
    let matchingConsistencyProof = false;
    for (const proof of input.consistency_proofs ?? []) {
      const validation = validateSchema("consistencyProof", proof);
      const currentCheckpointHash = input.checkpoint ? checkpointHash(input.checkpoint) : undefined;
      const valid = validation.valid && verifyConsistencyProof(proof) && (!currentCheckpointHash || proof.to_checkpoint === currentCheckpointHash);
      if (valid) matchingConsistencyProof = true;
      if (!valid) {
        checks.consistency_proof_valid = false;
        errors.push("TSL_CONSISTENCY_PROOF_INVALID", ...validation.errors);
      }
    }
    if (policy.require_consistency_proof && !matchingConsistencyProof) {
      checks.consistency_proof_valid = false;
      errors.push("TSL_CONSISTENCY_PROOF_MISSING");
    }
    if (checks.consistency_proof_valid) explanation.push("Checkpoint consistency proof is valid");
  }

  if (input.non_membership_proofs?.length || policy.require_non_membership_proof) {
    checks.non_membership_proof_valid = true;
    let matchedNonMembership = false;
    for (const proof of input.non_membership_proofs ?? []) {
      const validation = validateSchema("nonMembershipProof", proof);
      const valid = validation.valid && proof.subject === input.envelope.sender && verifyNonMembershipProof(proof);
      if (valid) matchedNonMembership = true;
      if (!valid) {
        checks.non_membership_proof_valid = false;
        errors.push("TSL_NON_MEMBERSHIP_PROOF_INVALID", ...validation.errors);
      }
    }
    if (policy.require_non_membership_proof && !matchedNonMembership) {
      checks.non_membership_proof_valid = false;
      errors.push("TSL_NON_MEMBERSHIP_PROOF_MISSING");
    }
    if (checks.non_membership_proof_valid) explanation.push("Required non-membership proof is valid");
  }

  if (input.governance_policy || policy.require_governance_policy) {
    checks.governance_policy_valid = false;
    const governancePolicy = input.governance_policy;
    if (governancePolicy) {
      const validation = validateSchema("governancePolicy", governancePolicy);
      const authority = await resolver.resolveTrustID(governancePolicy.authority, governancePolicy.issued_at);
      const authorityKey = authority ? findVerificationMethod(authority, governancePolicy.authority_key_id) : null;
      const accepted =
        !policy.accepted_governance_policy || policy.accepted_governance_policy === governancePolicy.policy_id;
      const notExpired = !governancePolicy.expires_at || Date.parse(governancePolicy.expires_at) > Date.now();
      checks.governance_policy_valid = Boolean(
        accepted &&
          validation.valid &&
          notExpired &&
          !governancePolicy.emergency_pause &&
          authorityKey?.type === "ed25519" &&
          verifyEd25519(authorityKey.public_key, governancePolicyHash(governancePolicy), governancePolicy.signature)
      );
      if (!checks.governance_policy_valid) {
        errors.push("TSL_GOVERNANCE_POLICY_INVALID");
        errors.push(...validation.errors);
        if (!accepted) errors.push("TSL_GOVERNANCE_POLICY_NOT_ACCEPTED");
        if (!notExpired) errors.push("TSL_GOVERNANCE_POLICY_EXPIRED");
        if (governancePolicy.emergency_pause) errors.push("TSL_GOVERNANCE_EMERGENCY_PAUSED");
      } else {
        explanation.push("Accepted governance policy is valid");
      }
    } else {
      errors.push("TSL_GOVERNANCE_POLICY_MISSING");
    }
  }

  if (input.audit_findings?.length || policy.require_audit_consistency) {
    checks.audit_consistency_valid = true;
    let validAuditFindingCount = 0;
    for (const finding of input.audit_findings ?? []) {
      const validation = validateSchema("auditFinding", finding);
      const auditorAllowed = !policy.accepted_auditors?.length || policy.accepted_auditors.includes(finding.auditor);
      const auditorIdentity = validation.valid ? await resolver.resolveTrustID(finding.auditor, finding.issued_at) : null;
      const auditorKey = auditorIdentity?.verification_methods.find((method) => keyActiveAt(method, finding.issued_at));
      const signatureValid =
        auditorKey?.type === "ed25519" && verifyEd25519(auditorKey.public_key, auditFindingHash(finding), finding.signature);
      const expectedCheckpointHash = input.checkpoint ? checkpointHash(input.checkpoint) : undefined;
      const checkpointMatches =
        !input.checkpoint ||
        (finding.checkpoint_hash !== undefined && finding.checkpoint_hash === expectedCheckpointHash);
      const valid = validation.valid && auditorAllowed && signatureValid && checkpointMatches && finding.severity !== "critical";
      if (valid) {
        validAuditFindingCount += 1;
      } else {
        checks.audit_consistency_valid = false;
        errors.push("TSL_AUDIT_FINDING_INVALID", ...validation.errors);
        if (!auditorAllowed) errors.push("TSL_AUDITOR_NOT_ACCEPTED");
        if (!signatureValid) errors.push("TSL_AUDIT_SIGNATURE_INVALID");
        if (!checkpointMatches) errors.push("TSL_AUDIT_CHECKPOINT_MISMATCH");
        if (finding.severity === "critical") errors.push("TSL_AUDIT_CRITICAL_FINDING");
      }
    }
    if (policy.require_audit_consistency && validAuditFindingCount === 0) {
      checks.audit_consistency_valid = false;
      errors.push("TSL_AUDIT_CONSISTENCY_INVALID");
    }
    if (checks.audit_consistency_valid) explanation.push("Accepted audit findings are valid and non-critical");
  }

  if (input.checkpoint) {
    const checkpointValidation = validateSchema("checkpoint", input.checkpoint);
    checks.checkpoint_valid = checkpointValidation.valid;
    if (!checkpointValidation.valid) {
      errors.push("TSL_CHECKPOINT_INVALID", ...checkpointValidation.errors);
    }
  }

  if (input.proof && input.checkpoint && checks.checkpoint_valid) {
    checks.checkpoint_matches_proof =
      input.proof.epoch_start_ms === input.checkpoint.epoch_start_ms &&
      input.proof.epoch_duration_ms === input.checkpoint.epoch_duration_ms &&
      input.proof.shard === input.checkpoint.shard &&
      checkpointRootForKind(input.checkpoint, input.proof.tree_kind) === input.proof.root;
    if (checks.checkpoint_matches_proof) explanation.push("Checkpoint root matches inclusion proof");
  }

  if (input.checkpoint && settlementBackend) {
    const settlement = await settlementBackend.verifyCheckpointSettlement(input.checkpoint);
    checks.checkpoint_settled = settlement.settled;
    if (settlement.settled) {
      explanation.push("Checkpoint is settled in configured settlement backend");
      settlementStatus = "settled";
    } else if (settlement.error) {
      errors.push(settlement.error);
      settlementStatus = settlement.error.includes("MISMATCH") ? "mismatch" : settlement.error.includes("UNAVAILABLE") ? "unavailable" : "pending";
    }
  }

  if (!checks.key_found) errors.push("TSL_KEY_NOT_FOUND");
  if (checks.key_found && !checks.key_active) errors.push("TSL_KEY_INACTIVE");
  if (!checks.not_revoked) errors.push("TSL_KEY_REVOKED");
  if (!checks.signature_valid) errors.push("TSL_SIGNATURE_INVALID");
  if (checks.content_commitment_matches === false) errors.push("TSL_CONTENT_COMMITMENT_MISMATCH");
  if (policy.require_inclusion && !checks.included_in_log) errors.push("TSL_INCLUSION_INVALID");
  if (policy.require_checkpoint && !checks.checkpoint_matches_proof) errors.push("TSL_CHECKPOINT_INVALID");
  if (policy.require_settlement && !checks.checkpoint_settled) errors.push("TSL_SETTLEMENT_MISSING");

  const verified =
    checks.schema_valid &&
    checks.signature_valid &&
    checks.key_found &&
    checks.key_active &&
    checks.not_revoked &&
    checks.content_commitment_matches !== false &&
    checks.receipt_valid !== false &&
    checks.attestation_valid !== false &&
    checks.revocation_state_valid !== false &&
    checks.assessment_valid !== false &&
    checks.trust_assessment_v2_valid !== false &&
    checks.scoring_profile_valid !== false &&
    checks.domain_policy_valid !== false &&
    checks.evidence_coverage_valid !== false &&
    checks.metadata_fingerprint_valid !== false &&
    checks.graph_artifacts_valid !== false &&
    checks.sybil_assessment_valid !== false &&
    checks.drift_report_valid !== false &&
    checks.delegated_action_valid !== false &&
    checks.zk_valid !== false &&
    checks.agent_scope_valid !== false &&
    checks.consistency_proof_valid !== false &&
    checks.non_membership_proof_valid !== false &&
    checks.governance_policy_valid !== false &&
    checks.audit_consistency_valid !== false &&
    (!policy.require_chain_revocation || checks.chain_revocation_checked === true) &&
    (!policy.require_zk_claims?.length || checks.zk_valid === true) &&
    (!policy.require_agent_scope || checks.agent_scope_valid === true) &&
    (!policy.require_consistency_proof || checks.consistency_proof_valid === true) &&
    (!policy.require_non_membership_proof || checks.non_membership_proof_valid === true) &&
    (!policy.require_governance_policy || checks.governance_policy_valid === true) &&
    (!policy.require_audit_consistency || checks.audit_consistency_valid === true) &&
    (!policy.require_v2_assessment || checks.trust_assessment_v2_valid === true) &&
    (!policy.require_metadata_fingerprint_policy || checks.metadata_fingerprint_valid === true) &&
    (!policy.require_graph_artifacts || checks.graph_artifacts_valid === true) &&
    (!policy.require_inclusion || checks.included_in_log) &&
    (!policy.require_checkpoint || checks.checkpoint_matches_proof) &&
    (!policy.require_settlement || checks.checkpoint_settled);

  return {
    verified,
    commitment_hash: commitmentHash,
    event_hash: unsignedEventHash,
    checks,
    settlement_status: settlementStatus,
    risk_label: riskLabel,
    explanation,
    errors: [...new Set(errors)]
  };
}
