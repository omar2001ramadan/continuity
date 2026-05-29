import {
  assessmentHash,
  attestationHash,
  contentCommitment,
  eventHash,
  commitmentHashFromParts,
  legacyCommitmentHashFromParts,
  receiptHash,
  revocationHash,
  auditFindingHash,
  governancePolicyHash,
  sha256Hex,
  verifyEd25519
} from "./crypto";
import { canonicalBytes } from "./canonicalize";
import { verifyAgentDelegation } from "./agent";
import { verifyConsistencyProof } from "./consistency";
import { findVerificationMethod, keyActiveAt, notRevokedAt } from "./identity";
import { verifyInclusion } from "./merkle";
import { verifyNonMembershipProof } from "./nonMembership";
import { checkpointHash, legacyCheckpointHashV0 } from "./relayStore";
import type { SettlementBackend } from "./settlement";
import type { BatchCheckpointV1, Hex32, SeedGovernanceProfileV1, TrustResolver, VerificationChecks, VerificationResult, VerifierPolicy, VerifyTSLInput } from "./types";
import { validateSchema } from "./validation";
import { verifyThresholdProofAsync } from "./zk";
import {
  agentActionV2Hash,
  computeDriftReportV0,
  computeGraphFeatureVectorV0,
  computeSybilAssessmentV0,
  constructGraphFromEvidenceV0,
  delegationPolicyV2Hash,
  disclosureConsentV1Hash,
  driftReportV1Hash,
  graphFeatureVectorV1Hash,
  metadataFingerprintCommitmentV1Hash,
  scoringProfileV2Hash,
  sybilAssessmentV1Hash,
  trustAssessmentV2Hash,
  verifyDelegatedAgentActionV0
} from "./v2";
import type { GraphV0 } from "./v2";

function checkpointHashForPolicy(checkpoint: BatchCheckpointV1): Hex32 {
  return process.env.ALLOW_LEGACY_CHECKPOINT_HASH_V0 === "true" ? legacyCheckpointHashV0(checkpoint) : checkpointHash(checkpoint);
}

function normalizeGraphAlgorithm(algorithm: string | undefined): string | undefined {
  if (algorithm === "louvain") return "louvain_modularity_v1";
  if (algorithm === "leiden") return "leiden_refinement_v1";
  return algorithm;
}

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

async function disclosureConsentAllows(input: VerifyTSLInput, fieldClasses: string[], resolver: TrustResolver, policy: VerifierPolicy): Promise<boolean> {
  const consents = input.disclosure_consents ?? [];
  const at = Date.parse(input.envelope.timestamp);
  for (const consent of consents) {
    const validation = validateSchema("disclosureConsentV1", consent);
    if (!validation.valid || consent.subject !== input.envelope.sender) continue;
    if (Date.parse(consent.issued_at) > at || Date.parse(consent.expires_at) <= at) continue;
    if (policy.verifier_or_provider && consent.verifier_or_provider !== policy.verifier_or_provider) continue;
    if (policy.disclosure_purpose && consent.purpose !== policy.disclosure_purpose) continue;
    if (policy.revoked_disclosure_pointers?.includes(consent.revocation_pointer)) continue;
    const allowed = new Set(consent.allowed_field_classes);
    const forbidden = new Set(consent.forbidden_field_classes);
    if (!fieldClasses.every((fieldClass) => allowed.has(fieldClass) && !forbidden.has(fieldClass))) continue;
    const identity = await resolver.resolveTrustID(consent.subject, consent.issued_at);
    const consentKey = identity?.verification_methods.find((method) => keyActiveAt(method, consent.issued_at) && notRevokedAt(method));
    if (consentKey?.type === "ed25519" && verifyEd25519(consentKey.public_key, disclosureConsentV1Hash(consent), consent.signature)) {
      return true;
    }
  }
  return false;
}

function seedGovernanceProfileHash(profile: SeedGovernanceProfileV1) {
  const unsigned = { ...profile } as Record<string, unknown>;
  delete unsigned.signature;
  return sha256Hex(canonicalBytes(unsigned));
}

async function seedGovernanceProfileValid(input: {
  profile: SeedGovernanceProfileV1 | undefined;
  expectedClass: "trusted" | "adversarial";
  seeds: string[];
  expectedSeedCommitment?: string;
  expectedGovernanceCommitment?: string;
  resolver: TrustResolver;
}): Promise<boolean> {
  const profile = input.profile;
  if (!profile || profile.seed_class !== input.expectedClass || profile.review_state !== "approved") return false;
  if (!validateSchema("seedGovernanceProfileV1", profile).valid) return false;
  const sortedSeeds = [...input.seeds].sort();
  const seedCommitment = sha256Hex(canonicalBytes(sortedSeeds));
  if (profile.seed_set_commitment !== seedCommitment || input.expectedSeedCommitment !== seedCommitment) return false;
  if (input.expectedGovernanceCommitment && input.expectedGovernanceCommitment !== seedGovernanceProfileHash(profile)) return false;
  if (!profile.signature) return false;
  const issuerIdentity = await input.resolver.resolveTrustID(profile.issuer, profile.reviewed_at);
  const issuerKey = issuerIdentity?.verification_methods.find((method) => keyActiveAt(method, profile.reviewed_at) && notRevokedAt(method));
  return issuerKey?.type === "ed25519" && verifyEd25519(issuerKey.public_key, seedGovernanceProfileHash(profile), profile.signature);
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
  if (policy.reject_unsafe_fixtures_on_mainnet && process.env.TSL_NETWORK === "mainnet") {
    for (const flag of ["ALLOW_UNSAFE_CHECKPOINT_SIGNATURE_FIXTURES", "ALLOW_UNSAFE_ZK_HASH_FIXTURES", "ALLOW_LEGACY_CHECKPOINT_HASH_V0"]) {
      if (process.env[flag] === "true") errors.push("TSL_UNSAFE_FIXTURE_POLICY_ENABLED");
    }
  }

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
  const legacyCommitmentHash = legacyCommitmentHashFromParts(unsignedEventHash, input.envelope.signature);

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
    checks.disclosure_consent_valid = await disclosureConsentAllows(input, ["raw_content", "content_salt"], resolver, policy);
    if (!checks.disclosure_consent_valid) {
      errors.push("TSL_DISCLOSURE_CONSENT_MISSING");
    }
    checks.content_commitment_matches =
      checks.disclosure_consent_valid &&
      contentCommitment(input.message_disclosure.raw_message, input.message_disclosure.content_salt) === input.envelope.content_commitment;
    if (checks.content_commitment_matches) {
      explanation.push("Disclosed message matches content commitment");
    }
  }

  if (input.proof) {
    const proofValidation = validateSchema("inclusionProof", input.proof);
    if (!proofValidation.valid) {
      errors.push("TSL_INCLUSION_INVALID", ...proofValidation.errors);
    } else {
      checks.included_in_log =
        input.proof.tree_kind === "event" &&
        (input.proof.commitment === commitmentHash || input.proof.commitment === legacyCommitmentHash) &&
        verifyInclusion(input.proof);
      if (checks.included_in_log) explanation.push("Event included in Merkle log proof");
      if (input.proof.tree_kind === "receipt") checks.receipt_included = verifyInclusion(input.proof);
      if (input.proof.tree_kind === "attestation") checks.attestation_included = verifyInclusion(input.proof);
      if (input.proof.tree_kind === "revocation") checks.revocation_included = verifyInclusion(input.proof);
    }
  }

  if (input.receipts?.length) {
    checks.receipt_valid = true;
    if (policy.require_receipt_inclusion_for_disclosed_receipts) {
      const consent = await disclosureConsentAllows(input, ["exact_counterparties"], resolver, policy);
      checks.disclosure_consent_valid = checks.disclosure_consent_valid !== false && consent;
      if (!consent) {
        checks.receipt_valid = false;
        errors.push("TSL_DISCLOSURE_CONSENT_MISSING");
      }
    }
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
        (receipt.event_commitment === commitmentHash || receipt.event_commitment === legacyCommitmentHash) &&
        receiptKey?.type === "ed25519" &&
        keyActiveAt(receiptKey, receipt.timestamp) &&
        verifyEd25519(receiptKey.public_key, receiptHash(receipt), receipt.signature);
      if (!valid) {
        checks.receipt_valid = false;
        errors.push("TSL_RECEIPT_INVALID");
      }
      if (policy.require_receipt_inclusion_for_disclosed_receipts) {
        const receiptCommitment = receiptHash(receipt);
        const receiptProof = input.receipt_proofs?.find((proof) => proof.commitment === receiptCommitment);
        const receiptProofValid =
          Boolean(
            receiptProof &&
              validateSchema("inclusionProof", receiptProof).valid &&
              receiptProof.tree_kind === "receipt" &&
              verifyInclusion(receiptProof) &&
              (!input.checkpoint ||
                (receiptProof.checkpoint_hash === checkpointHashForPolicy(input.checkpoint) &&
                  receiptProof.root === input.checkpoint.receipt_root &&
                  receiptProof.epoch_start_ms === input.checkpoint.epoch_start_ms &&
                  receiptProof.shard === input.checkpoint.shard))
          );
        checks.receipt_included = checks.receipt_included !== false && receiptProofValid;
        if (!receiptProofValid) {
          checks.receipt_valid = false;
          errors.push("TSL_RECEIPT_INCLUSION_INVALID");
        }
      }
    }
    if (checks.receipt_valid) explanation.push("Receipt signatures valid");
  }

  if (input.attestations?.length) {
    checks.attestation_valid = true;
    if (policy.require_receipt_inclusion_for_disclosed_receipts && input.attestations.some((attestation) => attestation.visibility !== "public")) {
      const consent = await disclosureConsentAllows(input, ["attestations"], resolver, policy);
      checks.disclosure_consent_valid = checks.disclosure_consent_valid !== false && consent;
      if (!consent) {
        checks.attestation_valid = false;
        errors.push("TSL_DISCLOSURE_CONSENT_MISSING");
      }
    }
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

    if (policy.require_provider_governance_active) {
      const governance = input.provider_governance_status;
      const governanceValidation = governance ? validateSchema("providerGovernanceStatusV1", governance) : { valid: false, errors: [] };
      const expectedProvider = input.scoring_profile?.provider ?? input.assessment_v2?.issuer;
      checks.provider_governance_valid = Boolean(
        governance &&
          governanceValidation.valid &&
          governance.provider === expectedProvider &&
          governance.status === "active" &&
          governance.model_registered === true &&
          governance.promotion_gate_result === "pass" &&
          governance.red_team_result === "pass" &&
          governance.privacy_leakage_bps <= 1000
      );
      if (!checks.provider_governance_valid) {
        errors.push(...governanceValidation.errors);
        errors.push("TSL_PROVIDER_INACTIVE");
        if (governance?.model_registered === false) errors.push("TSL_MODEL_NOT_REGISTERED");
      }
    }

    if (input.assessment_v2) {
      const validation = validateSchema("trustAssessmentV2", input.assessment_v2);
      const issuerIdentity = validation.valid ? await resolver.resolveTrustID(input.assessment_v2.issuer, input.assessment_v2.issued_at) : null;
      const issuerKey = issuerIdentity?.verification_methods.find((method) => keyActiveAt(method, input.assessment_v2!.issued_at));
      const profileMatches =
        !input.scoring_profile || input.assessment_v2.scoring_profile_id === input.scoring_profile.profile_id;
      const domainMatches = !input.domain_policy || input.assessment_v2.domain === input.domain_policy.domain;
      const gateMatches =
        input.assessment_v2.gate_result.schema_valid === checks.schema_valid &&
        input.assessment_v2.gate_result.signature_valid === checks.signature_valid &&
        input.assessment_v2.gate_result.key_active === checks.key_active &&
        input.assessment_v2.gate_result.not_revoked === checks.not_revoked &&
        (input.assessment_v2.gate_result.included_in_log === undefined || input.assessment_v2.gate_result.included_in_log === checks.included_in_log);
      checks.trust_assessment_v2_valid = Boolean(
        validation.valid &&
          input.assessment_v2.subject === input.envelope.sender &&
          Date.parse(input.assessment_v2.expires_at) > Date.now() &&
          profileMatches &&
          domainMatches &&
          gateMatches &&
          (!input.scoring_profile || input.assessment_v2.issuer === input.scoring_profile.provider) &&
          issuerKey?.type === "ed25519" &&
          verifyEd25519(issuerKey.public_key, trustAssessmentV2Hash(input.assessment_v2), input.assessment_v2.signature)
      );
      if (checks.trust_assessment_v2_valid) {
        explanation.push("Signed v2 trust assessment is valid");
        riskLabel =
          input.assessment_v2.label === "cryptographic_failure" ||
          input.assessment_v2.label === "settlement_missing" ||
          input.assessment_v2.label === "unsettled_or_unproven" ||
          input.assessment_v2.label === "delegation_missing" ||
          input.assessment_v2.label === "revoked_or_compromised"
            ? "high_risk"
            : input.assessment_v2.label;
      } else {
        errors.push("TSL_TRUST_ASSESSMENT_V2_INVALID", ...validation.errors);
        if (!gateMatches) errors.push("TSL_ASSESSMENT_GATE_MISMATCH");
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
        (!policy.require_research_graph_algorithm ||
          input.graph_feature_vector.community_algorithm_id === normalizeGraphAlgorithm(input.graph_profile?.community_detection.algorithm)) &&
        subjectKey?.type === "ed25519" &&
        verifyEd25519(subjectKey.public_key, graphFeatureVectorV1Hash(input.graph_feature_vector), input.graph_feature_vector.signature);
    }
    if (policy.require_research_graph_algorithm) {
      const algorithm = normalizeGraphAlgorithm(input.graph_profile?.community_detection.algorithm);
      checks.research_graph_algorithm_valid = algorithm === "louvain_modularity_v1" || algorithm === "leiden_refinement_v1";
      if (!checks.research_graph_algorithm_valid) errors.push("TSL_GRAPH_ARTIFACTS_INVALID");
      checks.graph_artifacts_valid = checks.graph_artifacts_valid && checks.research_graph_algorithm_valid;
    }
    if (policy.require_seed_governance_opening) {
      const trustedSeeds = [...(input.trusted_seeds ?? [])].sort();
      const adversarialSeeds = [...(input.adversarial_seeds ?? [])].sort();
      const trustedCommitment = sha256Hex(canonicalBytes(trustedSeeds));
      const adversarialCommitment = sha256Hex(canonicalBytes(adversarialSeeds));
      const trustedGovernanceValid = await seedGovernanceProfileValid({
        profile: input.trusted_seed_governance,
        expectedClass: "trusted",
        seeds: trustedSeeds,
        expectedSeedCommitment: input.graph_profile?.seed_sets.trusted_seed_commitment,
        expectedGovernanceCommitment: input.graph_profile?.seed_sets.trusted_seed_governance_commitment,
        resolver
      });
      const adversarialGovernanceValid = await seedGovernanceProfileValid({
        profile: input.adversarial_seed_governance,
        expectedClass: "adversarial",
        seeds: adversarialSeeds,
        expectedSeedCommitment: input.graph_profile?.seed_sets.adversarial_seed_commitment,
        expectedGovernanceCommitment: input.graph_profile?.seed_sets.adversarial_seed_governance_commitment,
        resolver
      });
      checks.seed_governance_valid = Boolean(
        input.graph_profile &&
          trustedCommitment === input.graph_profile.seed_sets.trusted_seed_commitment &&
          adversarialCommitment === input.graph_profile.seed_sets.adversarial_seed_commitment &&
          trustedGovernanceValid &&
          adversarialGovernanceValid
      );
      if (!checks.seed_governance_valid) errors.push("TSL_SEED_GOVERNANCE_OPENING_INVALID");
      checks.graph_artifacts_valid = checks.graph_artifacts_valid && checks.seed_governance_valid;
    }
    if (input.sybil_assessment) {
      if (policy.require_sybil_provider_issuer && !input.sybil_assessment.issuer) {
        checks.sybil_assessment_valid = false;
        checks.graph_artifacts_valid = false;
        errors.push("TSL_SYBIL_PROVIDER_ISSUER_REQUIRED");
      }
      const issuerOrSubject = input.sybil_assessment.issuer ?? input.sybil_assessment.subject;
      const issuerIdentity = await resolver.resolveTrustID(issuerOrSubject, input.sybil_assessment.computed_at);
      const issuerKey = issuerIdentity?.verification_methods.find((method) => keyActiveAt(method, input.sybil_assessment!.computed_at));
      checks.sybil_assessment_valid = Boolean(
        checks.sybil_assessment_valid !== false &&
          input.sybil_assessment.subject === input.envelope.sender &&
          issuerKey?.type === "ed25519" &&
          verifyEd25519(issuerKey.public_key, sybilAssessmentV1Hash(input.sybil_assessment), input.sybil_assessment.signature)
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
    let evidenceGraph: GraphV0 | undefined;
    if (input.graph_profile && (input.graph_feature_vector || input.sybil_assessment)) {
      evidenceGraph = await constructGraphFromEvidenceV0({
        events: [input.envelope],
        receipts: input.receipts,
        attestations: input.attestations,
        delegation_policies: input.delegation_policies,
        resolver,
        graph_profile: input.graph_profile,
        at_time: input.graph_feature_vector?.computed_at ?? input.sybil_assessment?.computed_at ?? input.envelope.timestamp,
        event_receivers: input.event_receivers
      });
    }
    if (input.graph_profile && input.graph_feature_vector && evidenceGraph) {
      const recomputed = computeGraphFeatureVectorV0({
        subject: input.graph_feature_vector.subject,
        graph: evidenceGraph,
        graph_profile_id: input.graph_profile.profile_id,
        graph_profile: input.graph_profile,
        trusted_seeds: input.trusted_seeds,
        adversarial_seeds: input.adversarial_seeds,
        computed_at: input.graph_feature_vector.computed_at
      });
      const graphMatches =
        recomputed.weighted_degree_bps === input.graph_feature_vector.weighted_degree_bps &&
        recomputed.reciprocity_bps === input.graph_feature_vector.reciprocity_bps &&
        recomputed.counterparty_hhi_bps === input.graph_feature_vector.counterparty_hhi_bps &&
        recomputed.counterparty_entropy_bps === input.graph_feature_vector.counterparty_entropy_bps &&
        recomputed.effective_counterparty_count_milli === input.graph_feature_vector.effective_counterparty_count_milli &&
        recomputed.seed_escape_bps === input.graph_feature_vector.seed_escape_bps &&
        recomputed.adversarial_proximity_bps === input.graph_feature_vector.adversarial_proximity_bps &&
        recomputed.community_algorithm_id === input.graph_feature_vector.community_algorithm_id &&
        recomputed.community_escape_bps === input.graph_feature_vector.community_escape_bps &&
        recomputed.community_diversity_bps === input.graph_feature_vector.community_diversity_bps &&
        recomputed.conductance_bps === input.graph_feature_vector.conductance_bps &&
        recomputed.trusted_neighbor_mass_bps === input.graph_feature_vector.trusted_neighbor_mass_bps &&
        recomputed.trusted_seed_distance_bps === input.graph_feature_vector.trusted_seed_distance_bps &&
        recomputed.adversarial_seed_distance_bps === input.graph_feature_vector.adversarial_seed_distance_bps &&
        recomputed.pagerank_bps === input.graph_feature_vector.pagerank_bps &&
        recomputed.ppr_lite_bps === input.graph_feature_vector.ppr_lite_bps &&
        recomputed.modularity_bps === input.graph_feature_vector.modularity_bps &&
        recomputed.community_pass_count === input.graph_feature_vector.community_pass_count;
      const graphCommitmentsMatch =
        recomputed.recomputation_commitment === input.graph_feature_vector.recomputation_commitment &&
        recomputed.privacy_disclosure_level === input.graph_feature_vector.privacy_disclosure_level;
      const fullGraphMatches = graphMatches && graphCommitmentsMatch;
      checks.graph_artifacts_valid = checks.graph_artifacts_valid && fullGraphMatches;
      if (!fullGraphMatches) errors.push("TSL_GRAPH_ARTIFACTS_INVALID");
    }
    if (input.sybil_assessment && input.graph_profile && evidenceGraph) {
        const sybilProfile = input.sybil_profile;
        const recomputedSybil = computeSybilAssessmentV0({
          subject: input.sybil_assessment.subject,
          issuer: input.sybil_assessment.issuer,
          graph: evidenceGraph,
          graph_profile: input.graph_profile,
          trusted_seeds: input.trusted_seeds,
          adversarial_seeds: input.adversarial_seeds,
          computed_at: input.sybil_assessment.computed_at,
          sybil_profile: sybilProfile
        });
        const sybilMatches =
          recomputedSybil.cluster_concentration_bps === input.sybil_assessment.cluster_concentration_bps &&
          recomputedSybil.trusted_escape_bps === input.sybil_assessment.trusted_escape_bps &&
          recomputedSybil.internal_receipt_ratio_bps === input.sybil_assessment.internal_receipt_ratio_bps &&
          recomputedSybil.seed_set_commitment === input.sybil_assessment.seed_set_commitment &&
          recomputedSybil.evidence_commitment === input.sybil_assessment.evidence_commitment &&
          recomputedSybil.cluster_id_commitment === input.sybil_assessment.cluster_id_commitment &&
          recomputedSybil.adversary_tier_assumed === input.sybil_assessment.adversary_tier_assumed &&
          recomputedSybil.creation_sync_bps === input.sybil_assessment.creation_sync_bps &&
          recomputedSybil.issuer_reuse_bps === input.sybil_assessment.issuer_reuse_bps &&
          recomputedSybil.external_diversity_bps === input.sybil_assessment.external_diversity_bps &&
          recomputedSybil.seed_contamination_bps === input.sybil_assessment.seed_contamination_bps &&
          recomputedSybil.receipt_symmetry_bps === input.sybil_assessment.receipt_symmetry_bps &&
          recomputedSybil.attack_cost_minor_units === input.sybil_assessment.attack_cost_minor_units &&
          JSON.stringify(recomputedSybil.cost_components) === JSON.stringify(input.sybil_assessment.cost_components) &&
          recomputedSybil.expected_benefit_minor_units === input.sybil_assessment.expected_benefit_minor_units &&
          recomputedSybil.attack_scenario === input.sybil_assessment.attack_scenario &&
          recomputedSybil.risk_score_bps === input.sybil_assessment.risk_score_bps &&
          recomputedSybil.risk_label === input.sybil_assessment.risk_label;
        checks.graph_artifacts_valid = checks.graph_artifacts_valid && sybilMatches;
        if (!sybilMatches) errors.push("TSL_SYBIL_ARTIFACT_INVALID");
    }
      if (input.drift_report && input.drift_feature_history) {
        const recomputedDrift = computeDriftReportV0({
          subject: input.drift_report.subject,
          drift_profile_id: input.drift_report.drift_profile_id,
          feature_history: input.drift_feature_history,
          baseline_window_days: input.drift_report.baseline_window_days,
          observation_window_days: input.drift_report.observation_window_days,
          computed_at: input.drift_report.computed_at,
          last_verified_event_at: input.drift_report.last_verified_event_at,
          cohort_baseline_components: input.drift_cohort_baseline_components
        });
        const driftMatches =
          recomputedDrift.drift_score_bps === input.drift_report.drift_score_bps &&
          recomputedDrift.drift_label === input.drift_report.drift_label &&
          recomputedDrift.action === input.drift_report.action &&
          recomputedDrift.feature_history_commitment === input.drift_report.feature_history_commitment &&
          recomputedDrift.baseline_profile_commitment === input.drift_report.baseline_profile_commitment &&
          recomputedDrift.covariance_profile_commitment === input.drift_report.covariance_profile_commitment &&
          recomputedDrift.sparse_mode === input.drift_report.sparse_mode &&
          recomputedDrift.recomputation_status === input.drift_report.recomputation_status &&
          recomputedDrift.last_verified_event_at === input.drift_report.last_verified_event_at &&
          recomputedDrift.days_since_last_verified_event === input.drift_report.days_since_last_verified_event &&
          JSON.stringify(recomputedDrift.component_scores_bps ?? {}) === JSON.stringify(input.drift_report.component_scores_bps ?? {});
        checks.graph_artifacts_valid = checks.graph_artifacts_valid && driftMatches;
        if (!driftMatches) errors.push("TSL_DRIFT_ARTIFACT_INVALID");
      }
      if (policy.require_full_covariance_drift && input.drift_report) {
        checks.full_covariance_drift_valid = Boolean(input.drift_feature_history?.length && input.drift_report.covariance_profile_commitment && input.drift_report.feature_history_commitment);
        if (!checks.full_covariance_drift_valid) errors.push("TSL_FULL_COVARIANCE_DRIFT_REQUIRED");
        checks.graph_artifacts_valid = checks.graph_artifacts_valid && checks.full_covariance_drift_valid;
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
      const valid =
        validation.valid &&
        proof.subject === input.envelope.sender &&
        (await verifyThresholdProofAsync(proof, {
          require_registered_circuit: policy.require_registered_zk_circuit,
          require_manifest_verification_key_hash: policy.require_manifest_verification_key_hash,
          reject_dev_circuits: policy.reject_dev_zk_circuits,
          manifests: input.zk_circuit_manifests,
          registry: input.zk_verification_key_registry
        }));
      if (valid) {
        if (policy.require_registered_zk_circuit) checks.zk_circuit_registered = true;
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
	              at_time: action.issued_at
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
      const currentCheckpointHash = input.checkpoint ? checkpointHashForPolicy(input.checkpoint) : undefined;
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
      const sparseRequired = policy.require_sparse_merkle_revocation_root === true;
      const sparseShape = Boolean(proof.tree_id && proof.root && proof.root_checkpoint && proof.leaf_index_commitment && proof.leaf_value_commitment && proof.sibling_path?.length);
      const checkpointRootBound =
        !sparseRequired ||
        Boolean(
          input.checkpoint &&
            proof.root_checkpoint === checkpointHashForPolicy(input.checkpoint) &&
            proof.root === input.checkpoint.revocation_root &&
            proof.set_root === input.checkpoint.revocation_root
        );
      const valid = validation.valid && proof.subject === input.envelope.sender && (!sparseRequired || sparseShape) && checkpointRootBound && verifyNonMembershipProof(proof);
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
      const expectedCheckpointHash = input.checkpoint ? checkpointHashForPolicy(input.checkpoint) : undefined;
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
    } else {
      const relayIdentity = await resolver.resolveTrustID(input.checkpoint.relay_id, input.envelope.timestamp);
      const relayKey = relayIdentity?.verification_methods.find((method) => keyActiveAt(method, input.envelope.timestamp));
      const unsafeFixtureSignatureAllowed =
        process.env.ALLOW_UNSAFE_CHECKPOINT_SIGNATURE_FIXTURES === "true" &&
        !(policy.reject_unsafe_fixtures_on_mainnet && process.env.TSL_NETWORK === "mainnet");
      checks.checkpoint_signature_valid =
        (unsafeFixtureSignatureAllowed && input.checkpoint.relay_signature === "0x00") ||
        (relayKey?.type === "ed25519" && verifyEd25519(relayKey.public_key, checkpointHashForPolicy(input.checkpoint), input.checkpoint.relay_signature));
      if (!checks.checkpoint_signature_valid) {
        errors.push("TSL_CHECKPOINT_SIGNATURE_INVALID");
      }
      if (policy.require_authorized_relay) {
        checks.authorized_relay_valid = Boolean(
          checks.checkpoint_signature_valid &&
            (!policy.authorized_relays?.length || policy.authorized_relays.includes(input.checkpoint.relay_id))
        );
        if (!checks.authorized_relay_valid) errors.push("TSL_RELAY_NOT_AUTHORIZED");
      }
    }
  }

  if (input.proof && input.checkpoint && checks.checkpoint_valid) {
    checks.checkpoint_matches_proof =
      input.proof.epoch_start_ms === input.checkpoint.epoch_start_ms &&
      input.proof.epoch_duration_ms === input.checkpoint.epoch_duration_ms &&
      input.proof.shard === input.checkpoint.shard &&
      input.proof.checkpoint_hash === checkpointHashForPolicy(input.checkpoint) &&
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

  if (input.assessment_v2) {
    const finalGateMatches =
      (input.assessment_v2.gate_result.checkpoint_valid === undefined ||
        input.assessment_v2.gate_result.checkpoint_valid === checks.checkpoint_matches_proof) &&
      (input.assessment_v2.gate_result.settlement_satisfied === undefined ||
        input.assessment_v2.gate_result.settlement_satisfied === checks.checkpoint_settled) &&
      (input.assessment_v2.gate_result.delegation_valid === undefined ||
        input.assessment_v2.gate_result.delegation_valid === checks.delegated_action_valid);
    const coverageMatches =
      !input.evidence_coverage ||
      (input.assessment_v2.coverage_bps === input.evidence_coverage.coverage_bps &&
        (!input.assessment_v2.evidence_coverage_commitment ||
          input.assessment_v2.evidence_coverage_commitment === sha256Hex(canonicalBytes(input.evidence_coverage))));
    if (!finalGateMatches || !coverageMatches) {
      checks.trust_assessment_v2_valid = false;
      if (!finalGateMatches) errors.push("TSL_ASSESSMENT_GATE_MISMATCH");
      if (!coverageMatches) errors.push("TSL_EVIDENCE_COVERAGE_INVALID");
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
    checks.disclosure_consent_valid !== false &&
    checks.checkpoint_signature_valid !== false &&
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
    checks.zk_circuit_registered !== false &&
    checks.research_graph_algorithm_valid !== false &&
    checks.provider_governance_valid !== false &&
    checks.seed_governance_valid !== false &&
    checks.full_covariance_drift_valid !== false &&
    checks.authorized_relay_valid !== false &&
    checks.governance_policy_valid !== false &&
    checks.audit_consistency_valid !== false &&
    !errors.includes("TSL_UNSAFE_FIXTURE_POLICY_ENABLED") &&
    (!policy.require_chain_revocation || checks.chain_revocation_checked === true) &&
    (!policy.require_zk_claims?.length || checks.zk_valid === true) &&
    (!policy.require_agent_scope || checks.agent_scope_valid === true) &&
    (!policy.require_consistency_proof || checks.consistency_proof_valid === true) &&
    (!policy.require_non_membership_proof || checks.non_membership_proof_valid === true) &&
    (!policy.require_registered_zk_circuit || checks.zk_circuit_registered === true) &&
    (!policy.require_research_graph_algorithm || checks.research_graph_algorithm_valid === true) &&
    (!policy.require_provider_governance_active || checks.provider_governance_valid === true) &&
    (!policy.require_seed_governance_opening || checks.seed_governance_valid === true) &&
    (!policy.require_full_covariance_drift || checks.full_covariance_drift_valid === true) &&
    (!policy.require_authorized_relay || checks.authorized_relay_valid === true) &&
    (!policy.require_receipt_inclusion_for_disclosed_receipts || !input.receipts?.length || checks.receipt_included === true) &&
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
