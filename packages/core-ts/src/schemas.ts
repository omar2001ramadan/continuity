import identitySchema from "../../../specs/json-schema/identity.v1.schema.json";
import eventCommitmentSchema from "../../../specs/json-schema/event_commitment.v1.schema.json";
import receiptCommitmentSchema from "../../../specs/json-schema/receipt_commitment.v1.schema.json";
import attestationSchema from "../../../specs/json-schema/attestation.v1.json";
import revocationSchema from "../../../specs/json-schema/revocation.v1.schema.json";
import checkpointSchema from "../../../specs/json-schema/batch_checkpoint.v1.schema.json";
import inclusionProofSchema from "../../../specs/json-schema/inclusion_proof.v1.schema.json";
import trustAssessmentSchema from "../../../specs/json-schema/trust_assessment.v1.json";
import zkThresholdProofSchema from "../../../specs/json-schema/zk_threshold_proof.v1.json";
import agentDelegationSchema from "../../../specs/json-schema/agent_delegation.v1.json";
import auditFindingSchema from "../../../specs/json-schema/audit_finding.v1.json";
import consistencyProofSchema from "../../../specs/json-schema/consistency_proof.v1.json";
import governancePolicySchema from "../../../specs/json-schema/governance_policy.v1.json";
import nonMembershipProofSchema from "../../../specs/json-schema/non_membership_proof.v1.json";
import proofBundleV1Schema from "../../../specs/json-schema/proof_bundle.v1.schema.json";
import scoringProfileV2Schema from "../../../specs/json-schema/scoring_profile.v2.schema.json";
import featureDefinitionV2Schema from "../../../specs/json-schema/feature_definition.v2.schema.json";
import domainPolicyV1Schema from "../../../specs/json-schema/domain_policy.v1.schema.json";
import evidenceCoverageV1Schema from "../../../specs/json-schema/evidence_coverage.v1.schema.json";
import trustAssessmentV2Schema from "../../../specs/json-schema/trust_assessment.v2.schema.json";
import metadataFingerprintCommitmentV1Schema from "../../../specs/json-schema/metadata_fingerprint_commitment.v1.schema.json";
import graphProfileV2Schema from "../../../specs/json-schema/graph_profile.v2.schema.json";
import graphFeatureVectorV1Schema from "../../../specs/json-schema/graph_feature_vector.v1.schema.json";
import sybilAssessmentV1Schema from "../../../specs/json-schema/sybil_assessment.v1.schema.json";
import driftReportV1Schema from "../../../specs/json-schema/drift_report.v1.schema.json";
import attestationV2Schema from "../../../specs/json-schema/attestation.v2.schema.json";
import modelCardV2Schema from "../../../specs/json-schema/model_card.v2.schema.json";
import evaluationReportV1Schema from "../../../specs/json-schema/evaluation_report.v1.schema.json";
import delegationPolicyV2Schema from "../../../specs/json-schema/delegation_policy.v2.schema.json";
import agentActionV2Schema from "../../../specs/json-schema/agent_action.v2.schema.json";

export const schemas = {
  identity: identitySchema,
  event: eventCommitmentSchema,
  receipt: receiptCommitmentSchema,
  attestation: attestationSchema,
  revocation: revocationSchema,
  checkpoint: checkpointSchema,
  inclusionProof: inclusionProofSchema,
  trustAssessment: trustAssessmentSchema,
  zkThresholdProof: zkThresholdProofSchema,
  agentDelegation: agentDelegationSchema,
  auditFinding: auditFindingSchema,
  consistencyProof: consistencyProofSchema,
  governancePolicy: governancePolicySchema,
  nonMembershipProof: nonMembershipProofSchema,
  proofBundleV1: proofBundleV1Schema,
  scoringProfileV2: scoringProfileV2Schema,
  featureDefinitionV2: featureDefinitionV2Schema,
  domainPolicyV1: domainPolicyV1Schema,
  evidenceCoverageV1: evidenceCoverageV1Schema,
  trustAssessmentV2: trustAssessmentV2Schema,
  metadataFingerprintCommitmentV1: metadataFingerprintCommitmentV1Schema,
  graphProfileV2: graphProfileV2Schema,
  graphFeatureVectorV1: graphFeatureVectorV1Schema,
  sybilAssessmentV1: sybilAssessmentV1Schema,
  driftReportV1: driftReportV1Schema,
  attestationV2: attestationV2Schema,
  modelCardV2: modelCardV2Schema,
  evaluationReportV1: evaluationReportV1Schema,
  delegationPolicyV2: delegationPolicyV2Schema,
  agentActionV2: agentActionV2Schema
} as const;

export type SchemaName = keyof typeof schemas;
