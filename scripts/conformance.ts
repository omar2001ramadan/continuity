import fs from "node:fs";
import path from "node:path";
import { canonicalBytes } from "../packages/core-ts/src/canonicalize";
import { buildIdentityFromSeed, signMessageEvent } from "../packages/core-ts/src/commitments";
import { commitmentHashFromParts, hashDomain, legacyCommitmentHashFromParts, sha256Hex, signReceipt } from "../packages/core-ts/src/crypto";
import { buildThresholdProof, verifyThresholdProofAsync, zkCircuitReleaseManifestHash, zkProofUsesRegisteredCircuit, zkVerificationKeyObjectHash } from "../packages/core-ts/src/zk";
import { buildSparseMerkleTree, proveSparseMerkleNonMembership, verifySparseMerkleProof } from "../packages/core-ts/src/nonMembership";
import {
  computeDriftReportV0,
  computeEvidenceCoverageV0,
  computeGraphFeatureVectorV0,
  computeMetadataFingerprintCommitmentV0,
  computeReferenceScoreV0,
  computeSybilAssessmentV0,
  constructGraphFromEvidenceV0,
  constructGraphFromRawEdgesForTestV0,
  constructGraphV0,
  verifyDelegatedAgentActionV0
} from "../packages/core-ts/src/v2";
import { validateSchema, type SchemaName } from "../packages/core-ts/src/validation";
import errorCodeRegistry from "../specs/error-codes.v1.json";

const root = path.resolve(import.meta.dirname, "..");

interface TraceabilityEntry {
  object_type: string;
  schema_name: SchemaName;
  schema_path: string;
  ts_type: string;
  validator: SchemaName;
  valid_example: string;
  invalid_examples: string[];
  test_vector: string;
  migration_note: string;
  conformance_level: string;
}

interface TraceabilityMatrix {
  type: "tsl.spec_traceability.v1";
  source: "Core_architecture.md";
  source_mutability: "read_only";
  objects: TraceabilityEntry[];
}

interface ProductionReadinessEvidence {
  type: "tsl.production_readiness_evidence.v1";
  status: "missing" | "draft" | "reviewed" | "approved" | "rejected";
  owner: string;
  review_date: string | null;
  approver: string | null;
  release_decision: "blocked" | "approved" | "rejected";
  items: Array<{
    id: string;
    owner: string;
    status: "missing" | "draft" | "reviewed" | "approved" | "rejected";
    review_date: string | null;
    approver: string | null;
    evidence_links: string[];
    blocking_findings: Array<{
      id: string;
      severity: "low" | "medium" | "high" | "critical";
      status: "open" | "mitigated" | "accepted" | "closed";
      description: string;
    }>;
    release_decision: "blocked" | "approved" | "rejected";
  }>;
}

interface FindingTracker {
  type: "tsl.finding_tracker.v1";
  status: "draft" | "active" | "approved" | "rejected";
  owner: string;
  updated_at: string;
  findings: Array<{
    id: string;
    source: string;
    severity: "low" | "medium" | "high" | "critical";
    status: "open" | "mitigated" | "accepted" | "closed";
    owner: string;
    description: string;
    fix_commit: string | null;
    retest_evidence: string | null;
    closure_approver: string | null;
    closed_at: string | null;
  }>;
}

const requestedLevel = (process.argv[2] ?? "rc2").toLowerCase();
const conformanceOrder = ["rc0", "rc1", "rc2", "rc3", "rc4", "mainnet"];
const levels =
  requestedLevel === "spec" || requestedLevel === "all"
    ? conformanceOrder.filter((level) => level !== "mainnet")
    : requestedLevel === "mainnet"
      ? conformanceOrder
      : conformanceOrder.slice(0, conformanceOrder.indexOf(requestedLevel) + 1 || 3);

const traceability = JSON.parse(fs.readFileSync(path.join(root, "specs/spec-traceability.v1.json"), "utf8")) as TraceabilityMatrix;
const requiredByLevel: Record<string, TraceabilityEntry[]> = conformanceOrder.reduce<Record<string, TraceabilityEntry[]>>((accumulator, level) => {
  accumulator[level] = traceability.objects.filter((entry) => entry.conformance_level === level);
  return accumulator;
}, {});

const requiredArtifactPaths = [
  "Core_architecture.md",
  "specs/error-codes.v1.json",
  "specs/openapi/relay-api.v1.yaml",
  "specs/openapi/verifier-api.v1.yaml",
  "specs/openapi/resolver-api.v1.yaml",
  "specs/openapi/scoring-provider-api.v1.yaml",
  "specs/openapi/auditor-api.v1.yaml",
  "packages/core-ts/src/index.ts",
  "packages/core-rust/src/lib.rs",
  "packages/core-python/tsl_core/__init__.py",
  "packages/verifier-ts/src/index.ts",
  "packages/client-sdk-ts/src/index.ts",
  "packages/agent-sdk-python/tsl_agent_sdk/__init__.py",
  "services/relay-node/src/index.ts",
  "services/log-node/src/index.ts",
  "services/checkpoint-submitter/src/index.ts",
  "services/resolver-node/src/index.ts",
  "services/verifier-api/src/index.ts",
  "services/scoring-provider/src/index.ts",
  "services/auditor-node/src/index.ts",
  "clients/web-verifier/src/index.ts",
  "clients/browser-extension/manifest.json",
  "clients/cli/src/index.ts",
  "clients/agent-sidecar/src/index.ts",
  "infra/db/migrations/001_initial.sql",
  "infra/k8s/tsl-production-reference.yaml",
  "infra/terraform/main.tf",
  "docker-compose.yml"
];

const requiredRcArtifactPaths = [
  "algorithms/reference-scorer-v0.md",
  "algorithms/graph-construction-v0.md",
  "algorithms/drift-baseline-v0.md",
  "algorithms/sybil-simulation-v0.md",
  "algorithms/calibration-v0.md",
  "algorithms/leakage-score-v0.md",
  "algorithms/delegation-authorization-v0.md",
  "conformance/tsl-rc0.md",
  "conformance/tsl-rc1.md",
  "conformance/tsl-rc2.md",
  "conformance/tsl-rc3.md",
  "conformance/tsl-rc4.md",
  "conformance/tsl-mainnet.md",
  "security/threat-model.md",
  "security/incident-response.md",
  "security/key-management-policy.md",
  "security/privacy-threat-model.md",
  "security/agent-security-test-plan.md",
  "legal-compliance/privacy-policy-draft.md",
  "legal-compliance/terms-of-service-draft.md",
  "legal-compliance/appeal-and-takedown-policy.md",
  "legal-compliance/automated-decisioning-review.md"
];

const requiredMainnetArtifactPaths = [
  "runbooks/relay-outage.md",
  "runbooks/checkpoint-delay.md",
  "runbooks/checkpoint-conflict.md",
  "runbooks/log-node-corruption.md",
  "runbooks/relay-key-compromise.md",
  "runbooks/provider-key-compromise.md",
  "runbooks/user-key-compromise.md",
  "runbooks/schema-migration-failure.md",
  "runbooks/settlement-backend-outage.md",
  "runbooks/vulnerability-disclosure-and-patch-release.md",
  "runbooks/data-retention-and-deletion-request.md",
  "runbooks/auditor-false-positive-finding.md",
  "runbooks/privacy-incident.md",
  "runbooks/bad-scorer-release.md",
  "runbooks/emergency-rollback.md",
  "runbooks/abuse-campaign.md",
  "security/secure-sdlc.md",
  "security/dependency-policy.md",
  "security/cryptography-review.md",
  "security/vulnerability-disclosure-policy.md",
  "security/audit-plan.md",
  "security/abuse-response-policy.md",
  "security/negative-claims-risk-review.md",
  "legal-compliance/data-processing-addendum-draft.md",
  "legal-compliance/gdpr-ccpa-mapping.md",
  "legal-compliance/law-enforcement-request-policy.md",
  "legal-compliance/production-legal-review-evidence.md",
  "security/production-security-audit-evidence.md",
  "security/finding-tracker.v1.schema.json",
  "security/production-finding-tracker.json",
  "specs/json-schema/production_readiness_evidence.v1.schema.json",
  "conformance/production-readiness-evidence.json",
  "key-ceremonies/key-ceremony-record.v1.schema.json",
  "key-ceremonies/examples/relay-key-rotation.json"
];

const coreArchitectureSchemaRequiredFields: Record<string, string[]> = {
  "attestation.v2": [
    "attestation_id",
    "claim_class",
    "claim_polarity",
    "severity",
    "evidence_commitment",
    "evidence_policy",
    "appeal_uri",
    "valid_after",
    "revocation_pointer"
  ],
  "evidence_coverage.v1": [
    "valid_signed_event_count",
    "valid_receipt_count",
    "unique_counterparty_count",
    "distinct_community_count",
    "attestation_count",
    "recent_revocation_count",
    "coverage_label"
  ],
  "graph_profile.v2": ["negative_edge_policy", "privacy_policy"],
  "model_card.v2": ["metrics"],
  "evaluation_report.v1": ["metrics"]
};

const coreArchitectureApiEndpoints = [
  "/v1/proof-bundles/{bundleId}",
  "/v1/scoring-profiles/{profileId}",
  "/v1/model-cards/{modelId}",
  "/v1/delegations/verify"
];

const coreArchitectureDatabaseTables = [
  "scoring_profiles_v2",
  "feature_definitions_v2",
  "domain_policies_v1",
  "evidence_coverage_v1",
  "trust_assessments_v2",
  "metadata_fingerprint_commitments_v1",
  "graph_feature_vectors_v1",
  "sybil_assessments_v1",
  "drift_reports_v1",
  "model_cards_v2",
  "evaluation_reports_v1",
  "delegation_policies_v2",
  "agent_actions_v2"
];

function readJson(file: string): unknown {
  return JSON.parse(fs.readFileSync(path.join(root, file), "utf8"));
}

function assert(condition: unknown, message: string): void {
  if (!condition) throw new Error(message);
}

function checkArtifactTree(): void {
  assert(traceability.type === "tsl.spec_traceability.v1", "Traceability matrix must declare tsl.spec_traceability.v1");
  assert(traceability.source === "Core_architecture.md", "Traceability matrix must cite Core_architecture.md");
  assert(traceability.source_mutability === "read_only", "Traceability matrix must keep Core_architecture.md read-only");
  assert(traceability.objects.length > 0, "Traceability matrix must not be empty");
  const objectTypes = new Set<string>();
  for (const entry of traceability.objects) {
    assert(!objectTypes.has(entry.object_type), `Duplicate traceability object ${entry.object_type}`);
    objectTypes.add(entry.object_type);
    assert(entry.schema_name === entry.validator, `${entry.object_type} schema_name and validator must match`);
    assert(entry.ts_type.length > 0, `${entry.object_type} must map to a TS type`);
    assert(entry.migration_note.length >= 20, `${entry.object_type} must have a concrete migration note`);
    assert(["rc0", "rc1", "rc2", "rc3", "rc4", "mainnet"].includes(entry.conformance_level), `${entry.object_type} has invalid conformance level`);
    for (const artifactPath of [entry.schema_path, entry.valid_example, `${entry.test_vector}/input.json`, `${entry.test_vector}/manifest.json`, ...entry.invalid_examples]) {
      assert(fs.existsSync(path.join(root, artifactPath)), `${entry.object_type} traceability path missing: ${artifactPath}`);
    }
    const invalidNames = new Set(entry.invalid_examples.map((example) => path.basename(example)));
    for (const requiredName of ["missing-required.json", "malformed-signature-or-hash.json", "unknown-field.json"]) {
      assert(invalidNames.has(requiredName), `${entry.object_type} must trace invalid example ${requiredName}`);
    }
  }
  for (const artifactPath of requiredArtifactPaths) {
    assert(fs.existsSync(path.join(root, artifactPath)), `Missing required architecture artifact ${artifactPath}`);
  }
  for (const artifactPath of requiredRcArtifactPaths) {
    assert(fs.existsSync(path.join(root, artifactPath)), `Missing required RC semantic artifact ${artifactPath}`);
  }
  if (requestedLevel === "mainnet") {
    for (const artifactPath of requiredMainnetArtifactPaths) {
      assert(fs.existsSync(path.join(root, artifactPath)), `Missing required MAINNET artifact ${artifactPath}`);
    }
    const readinessFiles = [...requiredRcArtifactPaths, ...requiredMainnetArtifactPaths].filter((artifactPath) => /\.(md|json|yaml|yml)$/.test(artifactPath));
    const forbidden = /\b(placeholder|not implemented|non-mainnet|TODO)\b/i;
    for (const artifactPath of readinessFiles) {
      if (artifactPath.endsWith(".schema.json")) continue;
      const text = fs.readFileSync(path.join(root, artifactPath), "utf8");
      assert(!forbidden.test(text), `MAINNET artifact still contains placeholder language: ${artifactPath}`);
    }
    checkProductionReadinessEvidence();
  }
}

function checkProductionReadinessEvidence(): void {
  const evidence = readJson("conformance/production-readiness-evidence.json") as ProductionReadinessEvidence;
  checkProductionFindingTracker();
  const statuses = new Set(["missing", "draft", "reviewed", "approved", "rejected"]);
  const decisions = new Set(["blocked", "approved", "rejected"]);
  assert(evidence.type === "tsl.production_readiness_evidence.v1", "MAINNET evidence manifest type is invalid");
  assert(statuses.has(evidence.status), "MAINNET evidence manifest status is invalid");
  assert(decisions.has(evidence.release_decision), "MAINNET evidence manifest release_decision is invalid");
  assert(
    evidence.status === "approved",
    `MAINNET production-readiness evidence must be approved by human/security/legal/ops owners before release (current status: ${evidence.status})`
  );
  assert(
    evidence.release_decision === "approved",
    `MAINNET release decision must be approved after production evidence review (current decision: ${evidence.release_decision})`
  );
  assert(Boolean(evidence.approver), "MAINNET evidence manifest requires an approver");
  assertFreshReviewDate(evidence.review_date, "MAINNET evidence manifest");
  assert(Array.isArray(evidence.items) && evidence.items.length > 0, "MAINNET production-readiness evidence must list controlled items");

  const requiredItems = [
    "security_audit",
    "legal_review",
    "ops_runbooks",
    "key_management",
    "provider_governance",
    "deployment_evidence",
    "postgres_live_integration",
    "cli_sidecar_v2_integration",
    "hosted_service_integration"
  ];
  const ids = new Set(evidence.items.map((item) => item.id));
  for (const id of requiredItems) assert(ids.has(id), `MAINNET evidence manifest missing item ${id}`);

  for (const item of evidence.items) {
    assert(item.id.length > 0, "MAINNET evidence item requires id");
    assert(item.owner.length > 0, `MAINNET evidence item requires owner: ${item.id}`);
    assert(statuses.has(item.status), `MAINNET evidence item status is invalid: ${item.id}`);
    assert(decisions.has(item.release_decision), `MAINNET evidence item release_decision is invalid: ${item.id}`);
    assert(item.status === "approved", `MAINNET evidence item is not approved: ${item.id}`);
    assert(item.release_decision === "approved", `MAINNET evidence item release decision is not approved: ${item.id}`);
    assert(Boolean(item.approver), `MAINNET evidence item requires approver: ${item.id}`);
    assertFreshReviewDate(item.review_date, `MAINNET evidence item ${item.id}`);
    assert(Array.isArray(item.evidence_links) && item.evidence_links.length > 0, `MAINNET evidence item must link evidence: ${item.id}`);
    for (const link of item.evidence_links) {
      assert(fs.existsSync(path.join(root, link)), `MAINNET evidence link missing for ${item.id}: ${link}`);
      const text = fs.readFileSync(path.join(root, link), "utf8");
      assert(!/\b(draft|missing|placeholder|not implemented|non-mainnet|TODO|REPLACE)\b/i.test(text), `MAINNET evidence link is not production-approved: ${link}`);
    }
    for (const finding of item.blocking_findings ?? []) {
      assert(
        finding.severity !== "critical" && finding.severity !== "high" || finding.status === "closed",
        `MAINNET evidence item has unresolved high/critical finding: ${item.id}/${finding.id}`
      );
    }
  }
}

function checkProductionFindingTracker(): void {
  const tracker = readJson("security/production-finding-tracker.json") as FindingTracker;
  const statuses = new Set(["draft", "active", "approved", "rejected"]);
  const findingStatuses = new Set(["open", "mitigated", "accepted", "closed"]);
  const severities = new Set(["low", "medium", "high", "critical"]);
  assert(tracker.type === "tsl.finding_tracker.v1", "Production finding tracker type is invalid");
  assert(statuses.has(tracker.status), "Production finding tracker status is invalid");
  assert(tracker.owner.length > 0, "Production finding tracker requires owner");
  assertFreshReviewDate(tracker.updated_at, "Production finding tracker");
  assert(Array.isArray(tracker.findings), "Production finding tracker requires findings array");
  for (const finding of tracker.findings) {
    assert(finding.id.length > 0, "Production finding requires id");
    assert(finding.source.length > 0, `Production finding requires source: ${finding.id}`);
    assert(severities.has(finding.severity), `Production finding severity is invalid: ${finding.id}`);
    assert(findingStatuses.has(finding.status), `Production finding status is invalid: ${finding.id}`);
    assert(finding.owner.length > 0, `Production finding requires owner: ${finding.id}`);
    assert(finding.description.length > 0, `Production finding requires description: ${finding.id}`);
    if (finding.status === "closed") {
      assert(Boolean(finding.fix_commit), `Closed production finding requires fix_commit: ${finding.id}`);
      assert(Boolean(finding.retest_evidence), `Closed production finding requires retest_evidence: ${finding.id}`);
      assert(Boolean(finding.closure_approver), `Closed production finding requires closure_approver: ${finding.id}`);
      assertFreshReviewDate(finding.closed_at, `Closed production finding ${finding.id}`);
    }
    assert(
      finding.severity !== "critical" && finding.severity !== "high" || finding.status === "closed",
      `Production finding tracker has unresolved high/critical finding: ${finding.id}`
    );
  }
}

function assertFreshReviewDate(value: string | null, label: string): void {
  assert(Boolean(value), `${label} requires review_date`);
  const ms = Date.parse(value!);
  assert(Number.isFinite(ms), `${label} review_date is invalid`);
  const ageDays = (Date.now() - ms) / 86400000;
  assert(ageDays <= 180, `${label} review_date is stale`);
}

function checkCoreArchitectureRequiredShapes(): void {
  for (const [objectType, fields] of Object.entries(coreArchitectureSchemaRequiredFields)) {
    const schema = readJson(`specs/json-schema/${objectType}.schema.json`) as { required?: string[]; properties?: Record<string, unknown> };
    for (const field of fields) {
      assert(schema.required?.includes(field), `${objectType} must require ${field} from Core_architecture.md`);
      assert(schema.properties && field in schema.properties, `${objectType} must define ${field} from Core_architecture.md`);
    }
  }

  const openapiText = coreArchitectureApiEndpoints.map((endpoint) => endpoint).join("\n");
  const openapiFiles = fs.readdirSync(path.join(root, "specs/openapi")).map((file) => fs.readFileSync(path.join(root, "specs/openapi", file), "utf8")).join("\n");
  for (const endpoint of coreArchitectureApiEndpoints) {
    assert(openapiFiles.includes(endpoint), `Missing Core_architecture.md endpoint ${endpoint}`);
  }
  assert(openapiText.length > 0, "Core_architecture.md endpoint registry cannot be empty");
  checkOpenApiHardening();

  const migration = fs.readFileSync(path.join(root, "infra/db/migrations/001_initial.sql"), "utf8");
  for (const table of coreArchitectureDatabaseTables) {
    assert(new RegExp(`CREATE TABLE IF NOT EXISTS ${table}\\b`).test(migration), `Missing Core_architecture.md database table ${table}`);
  }
}

function checkOpenApiHardening(): void {
  const required = [
    { file: "specs/openapi/verifier-api.v1.yaml", path: "/v1/verify", needsRequest: true },
    { file: "specs/openapi/relay-api.v1.yaml", path: "/v1/delegations/verify", needsRequest: true },
    { file: "specs/openapi/scoring-provider-api.v1.yaml", path: "/v1/assessments/v2", needsRequest: true },
    { file: "specs/openapi/scoring-provider-api.v1.yaml", path: "/v1/scoring/profiles", needsRequest: true },
    { file: "specs/openapi/scoring-provider-api.v1.yaml", path: "/v1/scoring/model-cards", needsRequest: true }
  ];
  for (const item of required) {
    const text = fs.readFileSync(path.join(root, item.file), "utf8");
    assert(text.includes(item.path), `${item.file} missing ${item.path}`);
    assert(text.includes("components:"), `${item.file} must define OpenAPI components`);
    assert(text.includes("ErrorResponse:"), `${item.file} must define canonical ErrorResponse`);
    assert(text.includes("securitySchemes:"), `${item.file} must declare security schemes`);
    if (item.needsRequest) assert(text.includes("requestBody:"), `${item.file} ${item.path} must declare requestBody`);
    assert(text.includes("$ref: '#/components/schemas/ErrorResponse'"), `${item.file} must reference canonical ErrorResponse`);
    assert(/application\/json:[\s\S]*schema:/.test(text), `${item.file} must use JSON schemas for API bodies`);
  }
}

function checkErrorRegistry(): void {
  const registry = new Set((errorCodeRegistry.codes as Array<{ code: string }>).map((entry) => entry.code));
  const searchRoots = ["packages", "services", "clients", "scripts"];
  const codePattern = /TSL_[A-Z0-9_]+/g;
  const nonErrorCodePatterns = [
    /^TSL_.*_(ADDRESS|URL|URI|KEY|KEY_URI|SEED_HEX|PRIVATE_KEY|RPC_URL|DEPLOYMENT|OUT|COUNT|SAMPLES|CONCURRENCY|RETRIES|BATCH|BATCH_SIZE|RUN_ID|ID|IDS|TRUST_ID|CHAIN_ID|CONTRACTS|STREAMS|MS)$/,
    /^TSL_(DATABASE_URL|EPOCH_MS|ENV_FILE|LOAD_ENV_IN_TESTS|TIMESTAMP_WINDOW_MS|GOSSIP_PEERS|LOG_CONSUMER_GROUP|RELAY_ID|RELAY_SIGNATURE|VERIFY_CONTRACTS|SCORING_PERSISTENCE|SCORING_ALLOW_MEMORY_STORE)$/
  ];
  for (const searchRoot of searchRoots) {
    const fullRoot = path.join(root, searchRoot);
    if (!fs.existsSync(fullRoot)) continue;
    const stack = [fullRoot];
    while (stack.length) {
      const current = stack.pop()!;
      const stat = fs.statSync(current);
      if (stat.isDirectory()) {
        if (current.includes(`${path.sep}node_modules${path.sep}`) || current.includes(`${path.sep}target${path.sep}`)) continue;
        for (const child of fs.readdirSync(current)) stack.push(path.join(current, child));
        continue;
      }
      if (!/\.(ts|tsx|js|cjs|json|yaml|yml|md)$/.test(current) || current.endsWith("verifier.bundle.js")) continue;
      const text = fs.readFileSync(current, "utf8");
      for (const match of text.matchAll(codePattern)) {
        const code = match[0];
        if (code.startsWith("TSL_RELEASE_") || code.startsWith("TSL_LOAD_") || code.startsWith("TSL_FULL_PATH_")) continue;
        if (code === "TSL_ERROR_CODE_REGISTRY" || code === "TSL_ERROR_CODES") continue;
        if (nonErrorCodePatterns.some((pattern) => pattern.test(code))) continue;
        assert(registry.has(code), `Error code ${code} is used but not registered in specs/error-codes.v1.json`);
      }
    }
  }
}

function checkObject(entry: TraceabilityEntry): void {
  const schemaPath = entry.schema_path;
  assert(fs.existsSync(path.join(root, schemaPath)), `Missing schema ${schemaPath}`);

  const validPath = entry.valid_example;
  const validExample = readJson(validPath);
  const validResult = validateSchema(entry.validator, validExample);
  assert(validResult.valid, `${validPath} failed validation: ${validResult.errors.join("; ")}`);

  for (const relativeInvalidPath of entry.invalid_examples) {
    const invalidPath = path.join(root, relativeInvalidPath);
    assert(fs.existsSync(invalidPath), `Missing invalid example ${relativeInvalidPath}`);
    const invalidResult = validateSchema(entry.validator, JSON.parse(fs.readFileSync(invalidPath, "utf8")));
    assert(!invalidResult.valid, `${invalidPath} unexpectedly passed validation`);
  }

  const vectorRoot = entry.test_vector;
  const input = readJson(`${vectorRoot}/input.json`) as Record<string, unknown>;
  const manifest = readJson(`${vectorRoot}/manifest.json`) as {
    object_type: string;
    expected: { schema_valid: boolean; canonical_hash: string };
  };
  const vectorResult = validateSchema(entry.validator, input);
  assert(vectorResult.valid === manifest.expected.schema_valid, `${vectorRoot} schema result mismatch`);
  assert(input.type === manifest.object_type, `${vectorRoot} object type mismatch`);
  const canonicalHash = hashDomain(String(input.type), canonicalBytes(input));
  assert(canonicalHash === manifest.expected.canonical_hash, `${vectorRoot} canonical hash mismatch`);
}

async function checkSemanticConformance(): Promise<void> {
  assertThrows(() => canonicalBytes({ invalid_float: 0.5 }), "Canonicalization must reject floats");
  assertThrows(() => canonicalBytes({ unsafe_integer: Number.MAX_SAFE_INTEGER + 1 }), "Canonicalization must reject unsafe integers");

  const fakeHash = "0x1111111111111111111111111111111111111111111111111111111111111111" as const;
  const fakeSignature =
    "0x22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222" as const;
  assert(commitmentHashFromParts(fakeHash, fakeSignature) !== legacyCommitmentHashFromParts(fakeHash, fakeSignature), "Canonical commitment hash must be domain-separated from legacy hash");

  const fullCoverage = computeEvidenceCoverageV0({
    subject: "did:tsl:a",
    valid_signed_event_count: 25,
    valid_receipt_count: 10,
    unique_counterparty_count: 5,
    computed_at: "2026-05-27T12:00:00Z"
  });
  assert(fullCoverage.coverage_bps === 10000, `Full evidence coverage formula mismatch: ${fullCoverage.coverage_bps}`);
  const partialCoverage = computeEvidenceCoverageV0({
    subject: "did:tsl:a",
    valid_signed_event_count: 1,
    valid_receipt_count: 1,
    unique_counterparty_count: 1,
    computed_at: "2026-05-27T12:00:00Z"
  });
  const expectedPartialCoverage = Math.floor(10000 * Math.min(1, 1 / 25) ** 0.25 * Math.min(1, 1 / 10) ** 0.35 * Math.min(1, 1 / 5) ** 0.4);
  assert(partialCoverage.coverage_bps === expectedPartialCoverage, `Multiplicative evidence coverage formula mismatch: ${partialCoverage.coverage_bps}`);
  const scoringPolicy = {
    type: "tsl.domain_policy.v1" as const,
    domain: "conformance_scoring",
    policy_version: "1.0.0",
    requires_settlement: false,
    requires_delegation_check: false,
    requires_content_opening: false,
    min_coverage_bps: 0,
    max_assessment_age_seconds: 86400,
    false_positive_cost_class: "high",
    false_negative_cost_class: "critical",
    sparse_identity_default: "unknown_caution",
    thresholds: { trusted_bps: 9000, likely_trusted_bps: 7500, medium_bps: 5500, suspicious_bps: 3500, high_risk_bps: 1500 }
  };
  const scoringBase = {
    subject: "did:tsl:a",
    issuer: "did:tsl:provider:reference",
    scoring_profile_id: "reference-scoring-conformance",
    model_version: "reference-v0",
    gate_result: {
      schema_valid: true,
      canonicalization_valid: true,
      signature_valid: true,
      key_active: true,
      not_revoked: true,
      included_in_log: true,
      checkpoint_valid: true,
      settlement_satisfied: true,
      delegation_valid: true
    },
    evidence_coverage: fullCoverage,
    confidence_profile: { method: "analytic_profile_v1" as const, min_width_bps: 100, max_width_bps: 100, coverage_weight_bps: 0 },
    domain_policy: scoringPolicy,
    issued_at: "2026-05-27T12:00:00Z"
  };
  const trustedScore = computeReferenceScoreV0({ ...scoringBase, normalized_features_bps: { trust: 10000 }, weights_bps: { trust: 9000 } });
  assert(trustedScore.label === "trusted", `Trusted label threshold mismatch: ${trustedScore.label}`);
  const likelyScore = computeReferenceScoreV0({ ...scoringBase, normalized_features_bps: { trust: 10000 }, weights_bps: { trust: 7500 } });
  assert(likelyScore.label === "likely_trusted", `Likely-trusted label threshold mismatch: ${likelyScore.label}`);
  const sparseScore = computeReferenceScoreV0({ ...scoringBase, evidence_coverage: { ...partialCoverage, coverage_bps: 2000 }, normalized_features_bps: { trust: 10000 }, weights_bps: { trust: 4000 } });
  assert(sparseScore.label === "insufficient_evidence", `Sparse identity label mismatch: ${sparseScore.label}`);
  const noAdverseScore = computeReferenceScoreV0({ ...scoringBase, normalized_features_bps: { trust: 10000 }, weights_bps: { trust: 4000 }, has_adverse_evidence: false });
  const adverseScore = computeReferenceScoreV0({ ...scoringBase, normalized_features_bps: { trust: 10000 }, weights_bps: { trust: 4000 }, has_adverse_evidence: true });
  assert(noAdverseScore.label === "unknown_caution", `Suspicious label must require adverse evidence: ${noAdverseScore.label}`);
  assert(adverseScore.label === "suspicious", `Adverse-evidence suspicious label mismatch: ${adverseScore.label}`);
  assertThrows(
    () =>
      computeReferenceScoreV0({
        ...scoringBase,
        normalized_features_bps: { trust: 10000 },
        weights_bps: { trust: 8000 },
        calibration_profile: {
          profile_id: "bad-calibration",
          points: [
            { raw_bps: 0, calibrated_bps: 1000 },
            { raw_bps: 5000, calibrated_bps: 900 },
            { raw_bps: 10000, calibrated_bps: 10000 }
          ]
        }
      }),
    "Calibration profile must reject non-monotone mappings"
  );

  const aSeed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
  const bSeed = "0101010101010101010101010101010101010101010101010101010101010101";
  const cSeed = "0202020202020202020202020202020202020202020202020202020202020202";
  const a = buildIdentityFromSeed({ trust_id: "did:tsl:a", key_id: "#key", seed_hex: aSeed, created_at: "2026-01-01T00:00:00Z" });
  const b = buildIdentityFromSeed({ trust_id: "did:tsl:b", key_id: "#key", seed_hex: bSeed, created_at: "2026-01-01T00:00:00Z" });
  const c = buildIdentityFromSeed({ trust_id: "did:tsl:c", key_id: "#key", seed_hex: cSeed, created_at: "2026-01-01T00:00:00Z" });
  const identities = new Map([a, b, c].map((identity) => [identity.id, identity]));
  const resolver = { resolveTrustID: (trustId: string) => identities.get(trustId) ?? null };
  const graphProfile = {
    type: "tsl.graph_profile.v2" as const,
    profile_id: "graph-default-rc4",
    edge_weight_profile: "default",
    temporal_decay_profile: "none",
    community_detection: { algorithm: "connected_components_v0" as const, resolution_bps: 10000, min_cluster_size: 1 },
    seed_sets: { trusted_seed_commitment: fakeHash, adversarial_seed_commitment: fakeHash },
    negative_edge_policy: { requires_evidence_commitment: true, requires_appeal_uri: true, max_single_negative_weight_bps: 1500, decay_days: 30 },
    privacy_policy: { raw_counterparty_upload_required: false, allows_pairwise_private_features: true },
    edge_weights: { signed_event: 6000, replied: 3000 }
  };
  const eventAB = signMessageEvent({
    sender: a.id,
    signing_key_id: "#key",
    seed_hex: aSeed,
    message: "graph-a-b",
    timestamp: "2026-05-27T12:00:00Z",
    nonce: fakeHash
  });
  const eventAC = signMessageEvent({
    sender: a.id,
    signing_key_id: "#key",
    seed_hex: aSeed,
    message: "graph-a-c",
    timestamp: "2026-05-27T12:00:02Z",
    nonce: "0x3333333333333333333333333333333333333333333333333333333333333333"
  });
  const receiptBA = signReceipt(
    {
      type: "tsl.receipt_commitment.v1",
      event_commitment: eventAB.commitment_hash,
      receiver: b.id,
      signing_key_id: "#key",
      receipt_class: "replied",
      timestamp: "2026-05-27T12:00:01Z"
    },
    bSeed
  );
  const graph = await constructGraphFromEvidenceV0({
    events: [eventAB.envelope, eventAC.envelope],
    receipts: [receiptBA],
    resolver,
    graph_profile: graphProfile,
    at_time: "2026-05-27T12:00:00Z",
    event_receivers: {
      [eventAB.commitment_hash]: b.id,
      [eventAC.commitment_hash]: c.id
    }
  });
  assert(graph.edges.length === 3, "Graph conformance must be evidence-derived from verified events/receipts");
  const vector = computeGraphFeatureVectorV0({
    subject: "did:tsl:a",
    graph,
    graph_profile_id: "graph-default-rc4",
    graph_profile: graphProfile,
    trusted_seeds: ["did:tsl:c"],
    adversarial_seeds: ["did:tsl:b"],
    computed_at: "2026-05-27T12:00:00Z"
  });
  assert(vector.reciprocity_bps === 4000, `Graph reciprocity vector mismatch: ${vector.reciprocity_bps}`);
  assert(vector.counterparty_hhi_bps === 5200, `Graph HHI vector mismatch: ${vector.counterparty_hhi_bps}`);
  assert(vector.adversarial_proximity_bps === 6000, `Graph adversarial proximity mismatch: ${vector.adversarial_proximity_bps}`);
  assert(vector.community_escape_bps === 0, `Graph community escape mismatch: ${vector.community_escape_bps}`);
  assert(vector.pagerank_bps !== undefined && vector.trusted_seed_distance_bps !== undefined, "Graph vector missing PageRank/seed-distance fields");

  const sybil = computeSybilAssessmentV0({
    subject: "did:tsl:a",
    graph: constructGraphV0({
      edges: [
        { src: "did:tsl:a", dst: "did:tsl:b", type: "receipt", timestamp: "2026-05-27T12:00:00Z", created_at: "2026-05-27T12:00:00Z", issuer: "did:tsl:i", weight_bps: 9000 },
        { src: "did:tsl:b", dst: "did:tsl:a", type: "receipt", timestamp: "2026-05-27T12:00:01Z", created_at: "2026-05-27T12:00:00Z", issuer: "did:tsl:i", weight_bps: 9000 },
        { src: "did:tsl:a", dst: "did:tsl:seed", type: "signed_event", timestamp: "2026-05-27T12:00:02Z", weight_bps: 100 }
      ]
    }),
    graph_profile: {
      type: "tsl.graph_profile.v2",
      profile_id: "graph-default-rc4",
      edge_weight_profile: "default",
      temporal_decay_profile: "none",
      community_detection: { algorithm: "connected_components", resolution_bps: 10000, min_cluster_size: 1 },
      seed_sets: { trusted_seed_commitment: fakeHash, adversarial_seed_commitment: fakeHash },
      negative_edge_policy: { requires_evidence_commitment: true, requires_appeal_uri: true, max_single_negative_weight_bps: 1500, decay_days: 30 },
      privacy_policy: { raw_counterparty_upload_required: false, allows_pairwise_private_features: true }
    },
    trusted_seeds: ["did:tsl:seed"],
    computed_at: "2026-05-27T12:00:00Z"
  });
  assert(sybil.risk_label === "high", `Sybil vector risk mismatch: ${sybil.risk_label}`);

  const drift = computeDriftReportV0({
    subject: "did:tsl:a",
    feature_history: [
      { timestamp: "2026-04-20T12:00:00Z", verified_event: true, components: { action: 1000, cadence: 900, graph: 1000 } },
      { timestamp: "2026-05-01T12:00:00Z", verified_event: true, components: { action: 1200, cadence: 1100, graph: 1000 } },
      { timestamp: "2026-05-10T12:00:00Z", verified_event: true, components: { action: 1100, cadence: 1000, graph: 900 } },
      { timestamp: "2026-05-27T11:00:00Z", high_value_action: true, components: { action: 9100, cadence: 8200, graph: 2500 } }
    ],
    baseline_window_days: 90,
    observation_window_days: 7,
    dormant_days: 1,
    computed_at: "2026-05-27T12:00:00Z"
  });
  assert(drift.drift_label === "dormant_reactivation" && drift.action === "step_up", "Dormant drift vector mismatch");

  const hashOnlyZkProof = buildThresholdProof({
    claim: "identity_age_days",
    subject: "did:tsl:a",
    value: 400,
    threshold: 365,
    witness_salt: fakeHash,
    issued_at: "2026-05-27T12:00:00Z"
  });
  const previousZkFixtureFlag = process.env.ALLOW_UNSAFE_ZK_HASH_FIXTURES;
  try {
    process.env.ALLOW_UNSAFE_ZK_HASH_FIXTURES = "false";
    assert((await verifyThresholdProofAsync(hashOnlyZkProof)) === false, "Hash-only ZK fixtures must not satisfy production verification");
  } finally {
    if (previousZkFixtureFlag === undefined) delete process.env.ALLOW_UNSAFE_ZK_HASH_FIXTURES;
    else process.env.ALLOW_UNSAFE_ZK_HASH_FIXTURES = previousZkFixtureFlag;
  }

  const fpInput = {
    subject: "did:tsl:a",
    metadata: { event_class: "message", timestamp: "2026-05-27T12:01:00Z", content_length_bytes: 300, ip_address: "127.0.0.1" },
    master_key_hex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    epoch: "2026-05-27T12:00:00.000Z",
    purpose: "pairwise_verifier" as const,
    bucket_profile: "default",
    salt_hex: "0x3333333333333333333333333333333333333333333333333333333333333333" as const,
    expires_at: "2026-08-27T12:00:00Z"
  };
  const fpOne = computeMetadataFingerprintCommitmentV0({ ...fpInput, verifier_domain: "one.example" });
  const fpTwo = computeMetadataFingerprintCommitmentV0({ ...fpInput, verifier_domain: "two.example" });
  assert(fpOne.scope_class === "pairwise_verifier" && fpOne.disclosure_policy === "selective", "Metadata fingerprint disclosure policy mismatch");
  assert(fpOne.fingerprint_commitment !== fpTwo.fingerprint_commitment, "Metadata fingerprint rotation/scope vector mismatch");

  const delegated = verifyDelegatedAgentActionV0({
    action: {
      type: "tsl.agent_action.v2",
      action_id: fakeHash,
      agent: "did:tsl:agent",
      principal: "did:tsl:principal",
      action: "pay",
      resource: "invoice/1",
      parameters_commitment: fakeHash,
      delegation_chain_root: fakeHash,
      nonce: fakeHash,
      issued_at: "2026-05-27T12:00:00Z",
      signature: "0x00"
    },
    delegation_chain: [],
    public_keys: {}
  });
  assert(delegated.error_code === "TSL_AGENT_ACTION_SIGNATURE_INVALID", "Delegation semantic failure code mismatch");
}

function assertThrows(fn: () => unknown, message: string): void {
  try {
    fn();
  } catch {
    return;
  }
  throw new Error(message);
}

async function checkGraphResearchConformance(): Promise<void> {
  const zero = "0x0000000000000000000000000000000000000000000000000000000000000000" as const;
  const profile = {
    type: "tsl.graph_profile.v2" as const,
    profile_id: "graph-research-v1",
    edge_weight_profile: "research-v1",
    temporal_decay_profile: "none",
    community_detection: {
      algorithm: "louvain_modularity_v1" as const,
      resolution_bps: 10000,
      min_cluster_size: 1,
      edge_weight_floor_bps: 100,
      deterministic_ordering: "node_id_lexicographic" as const,
      max_passes: 12,
      approximation_tolerance_bps: 0,
      projection: "undirected_sum" as const,
      negative_edge_treatment: "cap" as const
    },
    seed_sets: { trusted_seed_commitment: zero, adversarial_seed_commitment: zero },
    negative_edge_policy: { requires_evidence_commitment: true, requires_appeal_uri: true, max_single_negative_weight_bps: 1500, decay_days: 30 },
    privacy_policy: { raw_counterparty_upload_required: false, allows_pairwise_private_features: true },
    pagerank: { iterations: 8, damping_bps: 8500, personalization: "subject" as const }
  };
  const seeds = new Map([
    ["did:tsl:a", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
    ["did:tsl:b", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
    ["did:tsl:c", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"],
    ["did:tsl:d", "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"],
    ["did:tsl:e", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"],
    ["did:tsl:f", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"]
  ]);
  const identities = new Map(
    [...seeds.entries()].map(([trustId, seed]) => [
      trustId,
      buildIdentityFromSeed({ trust_id: trustId, key_id: "#key", seed_hex: seed, created_at: "2026-01-01T00:00:00Z" })
    ])
  );
  const resolver = { resolveTrustID: (trustId: string) => identities.get(trustId) ?? null };
  const events = [
    ["did:tsl:a", "did:tsl:b", "2026-05-27T12:00:00Z", "0x0000000000000000000000000000000000000000000000000000000000000001"],
    ["did:tsl:b", "did:tsl:c", "2026-05-27T12:00:01Z", "0x0000000000000000000000000000000000000000000000000000000000000002"],
    ["did:tsl:c", "did:tsl:a", "2026-05-27T12:00:02Z", "0x0000000000000000000000000000000000000000000000000000000000000003"],
    ["did:tsl:d", "did:tsl:e", "2026-05-27T12:00:03Z", "0x0000000000000000000000000000000000000000000000000000000000000004"],
    ["did:tsl:e", "did:tsl:f", "2026-05-27T12:00:04Z", "0x0000000000000000000000000000000000000000000000000000000000000005"],
    ["did:tsl:c", "did:tsl:d", "2026-05-27T12:00:05Z", "0x0000000000000000000000000000000000000000000000000000000000000006"]
  ].map(([sender, receiver, timestamp, nonce]) => ({
    receiver,
    signed: signMessageEvent({
      sender,
      signing_key_id: "#key",
      seed_hex: seeds.get(sender)!,
      message: `research-${sender}-${receiver}`,
      timestamp,
      nonce: nonce as `0x${string}`
    })
  }));
  const eventReceivers = Object.fromEntries(events.map(({ receiver, signed }) => [signed.commitment_hash, receiver]));
  const graph = await constructGraphFromEvidenceV0({
    events: events.map(({ signed }) => signed.envelope),
    resolver,
    graph_profile: profile,
    at_time: "2026-05-27T12:00:06Z",
    event_receivers: eventReceivers
  });
  assert(graph.edges.length === events.length, "Research graph conformance must construct from verified signed event evidence");
  const vector = computeGraphFeatureVectorV0({
    subject: "did:tsl:a",
    graph,
    graph_profile_id: profile.profile_id,
    graph_profile: profile,
    trusted_seeds: ["did:tsl:b"],
    adversarial_seeds: ["did:tsl:f"],
    computed_at: "2026-05-27T12:00:06Z"
  });
  assert(vector.community_algorithm_id === "louvain_modularity_v1", "Research graph profile must use explicit v1 Louvain algorithm ID");
  assert((vector.modularity_bps ?? 0) > 0, "Research graph vector must include positive modularity output");
  assert((vector.community_pass_count ?? 0) > 0, "Research graph vector must include algorithm pass count");
  assert(vector.pagerank_bps !== undefined && vector.conductance_bps !== undefined, "Research graph vector must include PageRank and conductance");
}

async function checkZkProductionConformance(): Promise<void> {
  for (const circuit of [
    "circuits/identity_age_threshold.circom",
    "circuits/reciprocal_receipt_count_threshold.circom",
    "circuits/revocation_set_non_membership.circom",
    "circuits/agent_scope_compliance.circom"
  ]) {
    assert(fs.existsSync(path.join(root, circuit)), `Production ZK circuit source missing: ${circuit}`);
  }
  const circuitWitnessFields: Record<string, string[]> = {
    "circuits/identity_age_threshold.circom": ["creation_epoch_day", "current_epoch_day", "registry_path", "public_registry_root"],
    "circuits/reciprocal_receipt_count_threshold.circom": ["receipt_leaves", "receipt_salts", "counterparty_commitments", "public_receipt_root"],
    "circuits/revocation_set_non_membership.circom": ["empty_leaf_commitment", "sibling_path", "leaf_index_bits", "public_revocation_root"],
    "circuits/agent_scope_compliance.circom": ["parameter_values_hash", "delegation_path", "delegation_chain_root", "human_approval_required"]
  };
  for (const [circuit, fields] of Object.entries(circuitWitnessFields)) {
    const source = fs.readFileSync(path.join(root, circuit), "utf8");
    for (const field of fields) assert(source.includes(field), `${circuit} missing witness-faithful field ${field}`);
  }
  const verificationKey = { protocol: "groth16", curve: "bn128", alpha_g1: ["1", "2"], beta_g2: [["1", "2"], ["3", "4"]] };
  const verificationKeyHash = zkVerificationKeyObjectHash(verificationKey);
  assert(zkVerificationKeyObjectHash({ ...verificationKey, alpha_g1: ["1", "3"] }) !== verificationKeyHash, "ZK verification-key object hash must reject key mutation");
  const manifest = {
    type: "tsl.zk.circuit_release_manifest.v1" as const,
    circuit_id: "identity-age-threshold-v1",
    claim: "identity_age_days" as const,
    version: "1.0.0",
    circuit_hash: sha256Hex("circuit"),
    r1cs_hash: sha256Hex("r1cs"),
    wasm_hash: sha256Hex("wasm"),
    zkey_hash: sha256Hex("zkey"),
    verification_key_id: "identity-age-vkey-v1",
    verification_key_hash: verificationKeyHash,
    verification_key: verificationKey,
    ceremony_transcript_hash: sha256Hex("ceremony"),
    auditor: "did:tsl:auditor:test",
    reviewer: "did:tsl:reviewer:test",
    status: "active" as const,
    issued_at: "2026-05-27T12:00:00Z"
  };
  const releaseHash = zkCircuitReleaseManifestHash(manifest);
  const proof = {
    ...buildThresholdProof({
      claim: "identity_age_days",
      subject: "did:tsl:a",
      value: 400,
      threshold: 365,
      witness_salt: releaseHash,
      issued_at: "2026-05-27T12:00:00Z"
    }),
    circuit_id: manifest.circuit_id,
    verification_key_id: manifest.verification_key_id,
    release_manifest_hash: releaseHash
  };
  assert(
    zkProofUsesRegisteredCircuit({
      proof,
      manifests: [manifest],
      registry: { type: "tsl.zk.verification_key_registry.v1", registry_id: "registry", active_manifest_hashes: [releaseHash], revoked_manifest_hashes: [], issued_at: manifest.issued_at }
    }),
    "Production ZK proof must bind to active circuit release registry"
  );
  const tree = buildSparseMerkleTree([sha256Hex("revoked-a"), sha256Hex("revoked-b")], { tree_id: "revocation-set-v1", tree_depth: 8 });
  const nonMembership = proveSparseMerkleNonMembership(sha256Hex("not-revoked"), tree, "did:tsl:a", "2026-05-27T12:00:00Z");
  assert(verifySparseMerkleProof(nonMembership, tree.root, tree.profile), "Sparse-Merkle non-membership vector must verify by root recomputation");
  assert(!verifySparseMerkleProof({ ...nonMembership, set_root: releaseHash }, tree.root, tree.profile), "Sparse-Merkle proof with wrong root must fail");
}

checkArtifactTree();
checkCoreArchitectureRequiredShapes();
checkErrorRegistry();
for (const level of levels) {
  for (const entry of requiredByLevel[level] ?? []) checkObject(entry);
}
await checkSemanticConformance();
if (requestedLevel === "graph-research" || requestedLevel === "spec" || requestedLevel === "all") await checkGraphResearchConformance();
if (requestedLevel === "zk-production" || requestedLevel === "spec" || requestedLevel === "all") await checkZkProductionConformance();

console.log(JSON.stringify({ conformance: requestedLevel, checked_levels: levels, ok: true }, null, 2));
