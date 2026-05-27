import fs from "node:fs";
import path from "node:path";
import { canonicalBytes } from "../packages/core-ts/src/canonicalize";
import { hashDomain } from "../packages/core-ts/src/crypto";
import { validateSchema, type SchemaName } from "../packages/core-ts/src/validation";
import errorCodeRegistry from "../specs/error-codes.v1.json";

const root = path.resolve(import.meta.dirname, "..");

const requiredByLevel: Record<string, Array<{ objectType: string; schemaName: SchemaName; vector: string }>> = {
  rc0: [
    { objectType: "identity.v1", schemaName: "identity", vector: "valid-local" },
    { objectType: "event_commitment.v1", schemaName: "event", vector: "deterministic-message" },
    { objectType: "proof_bundle.v1", schemaName: "proofBundleV1", vector: "valid-offline-bundle" }
  ],
  rc1: [
    { objectType: "receipt_commitment.v1", schemaName: "receipt", vector: "replied" },
    { objectType: "revocation.v1", schemaName: "revocation", vector: "compromise" },
    { objectType: "batch_checkpoint.v1", schemaName: "checkpoint", vector: "single-leaf" },
    { objectType: "inclusion_proof.v1", schemaName: "inclusionProof", vector: "single-leaf" }
  ],
  rc2: [
    { objectType: "scoring_profile.v2", schemaName: "scoringProfileV2", vector: "valid-transparent" },
    { objectType: "feature_definition.v2", schemaName: "featureDefinitionV2", vector: "identity-age" },
    { objectType: "domain_policy.v1", schemaName: "domainPolicyV1", vector: "agent-payments" },
    { objectType: "evidence_coverage.v1", schemaName: "evidenceCoverageV1", vector: "high-coverage" },
    { objectType: "trust_assessment.v2", schemaName: "trustAssessmentV2", vector: "likely-trusted" },
    { objectType: "model_card.v2", schemaName: "modelCardV2", vector: "reference-scorer" },
    { objectType: "evaluation_report.v1", schemaName: "evaluationReportV1", vector: "promotion-pass" }
  ],
  rc3: [
    { objectType: "metadata_fingerprint_commitment.v1", schemaName: "metadataFingerprintCommitmentV1", vector: "pairwise" },
    { objectType: "graph_profile.v2", schemaName: "graphProfileV2", vector: "default" },
    { objectType: "graph_feature_vector.v1", schemaName: "graphFeatureVectorV1", vector: "small-graph" },
    { objectType: "sybil_assessment.v1", schemaName: "sybilAssessmentV1", vector: "cluster-b2" },
    { objectType: "drift_report.v1", schemaName: "driftReportV1", vector: "dormant-reactivation" },
    { objectType: "attestation.v2", schemaName: "attestationV2", vector: "appealed-negative" }
  ],
  rc4: [
    { objectType: "delegation_policy.v2", schemaName: "delegationPolicyV2", vector: "invoice-agent" },
    { objectType: "agent_action.v2", schemaName: "agentActionV2", vector: "inside-scope" }
  ]
};

const requestedLevel = (process.argv[2] ?? "rc2").toLowerCase();
const conformanceOrder = ["rc0", "rc1", "rc2", "rc3", "rc4"];
const levels =
  requestedLevel === "spec" || requestedLevel === "all"
    ? conformanceOrder
    : conformanceOrder.slice(0, conformanceOrder.indexOf(requestedLevel) + 1 || 3);

const requiredArtifactPaths = [
  "Core_architecture.md",
  "specs/latex/Trust_Signature_Layer_full_implementation_v3.tex",
  "specs/error-codes.v1.json",
  "specs/openapi/relay-api.v1.yaml",
  "specs/openapi/verifier-api.v1.yaml",
  "specs/openapi/resolver-api.v1.yaml",
  "specs/openapi/scoring-provider-api.v1.yaml",
  "specs/openapi/auditor-api.v1.yaml",
  "algorithms/reference-scorer-v0.md",
  "algorithms/graph-construction-v0.md",
  "algorithms/drift-baseline-v0.md",
  "algorithms/sybil-simulation-v0.md",
  "algorithms/calibration-v0.md",
  "algorithms/leakage-score-v0.md",
  "algorithms/delegation-authorization-v0.md",
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
  "docker-compose.yml",
  "conformance/tsl-rc0.md",
  "conformance/tsl-rc1.md",
  "conformance/tsl-rc2.md",
  "conformance/tsl-rc3.md",
  "conformance/tsl-rc4.md",
  "conformance/tsl-mainnet.md"
];

const latexSchemaRequiredFields: Record<string, string[]> = {
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

const latexApiEndpoints = [
  "/v1/proof-bundles/{bundleId}",
  "/v1/scoring-profiles/{profileId}",
  "/v1/model-cards/{modelId}",
  "/v1/delegations/verify"
];

const latexDatabaseTables = [
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
  for (const artifactPath of requiredArtifactPaths) {
    assert(fs.existsSync(path.join(root, artifactPath)), `Missing required architecture artifact ${artifactPath}`);
  }
}

function checkLatexRequiredShapes(): void {
  for (const [objectType, fields] of Object.entries(latexSchemaRequiredFields)) {
    const schema = readJson(`specs/json-schema/${objectType}.schema.json`) as { required?: string[]; properties?: Record<string, unknown> };
    for (const field of fields) {
      assert(schema.required?.includes(field), `${objectType} must require ${field} from the LaTeX spec`);
      assert(schema.properties && field in schema.properties, `${objectType} must define ${field} from the LaTeX spec`);
    }
  }

  const openapiText = latexApiEndpoints.map((endpoint) => endpoint).join("\n");
  const openapiFiles = fs.readdirSync(path.join(root, "specs/openapi")).map((file) => fs.readFileSync(path.join(root, "specs/openapi", file), "utf8")).join("\n");
  for (const endpoint of latexApiEndpoints) {
    assert(openapiFiles.includes(endpoint), `Missing LaTeX endpoint ${endpoint}`);
  }
  assert(openapiText.length > 0, "LaTeX endpoint registry cannot be empty");

  const migration = fs.readFileSync(path.join(root, "infra/db/migrations/001_initial.sql"), "utf8");
  for (const table of latexDatabaseTables) {
    assert(new RegExp(`CREATE TABLE IF NOT EXISTS ${table}\\b`).test(migration), `Missing LaTeX database table ${table}`);
  }
}

function checkErrorRegistry(): void {
  const registry = new Set((errorCodeRegistry.codes as Array<{ code: string }>).map((entry) => entry.code));
  const searchRoots = ["packages", "services", "clients", "scripts"];
  const codePattern = /TSL_[A-Z0-9_]+/g;
  const nonErrorCodePatterns = [
    /^TSL_.*_(ADDRESS|URL|URI|KEY|KEY_URI|SEED_HEX|PRIVATE_KEY|RPC_URL|DEPLOYMENT|OUT|COUNT|SAMPLES|CONCURRENCY|RETRIES|BATCH|BATCH_SIZE|RUN_ID|ID|IDS|TRUST_ID|CHAIN_ID|CONTRACTS|STREAMS|MS)$/,
    /^TSL_(DATABASE_URL|EPOCH_MS|ENV_FILE|LOAD_ENV_IN_TESTS|TIMESTAMP_WINDOW_MS|GOSSIP_PEERS|LOG_CONSUMER_GROUP|RELAY_ID|RELAY_SIGNATURE|VERIFY_CONTRACTS)$/
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

function checkObject(entry: { objectType: string; schemaName: SchemaName; vector: string }): void {
  const schemaPath = `specs/json-schema/${entry.objectType}.schema.json`;
  assert(fs.existsSync(path.join(root, schemaPath)), `Missing schema ${schemaPath}`);

  const validPath = `specs/examples/valid/${entry.objectType}.json`;
  const validExample = readJson(validPath);
  const validResult = validateSchema(entry.schemaName, validExample);
  assert(validResult.valid, `${validPath} failed validation: ${validResult.errors.join("; ")}`);

  const invalidDir = path.join(root, "specs/examples/invalid", entry.objectType);
  for (const name of ["missing-required.json", "malformed-signature-or-hash.json", "unknown-field.json"]) {
    const invalidPath = path.join(invalidDir, name);
    assert(fs.existsSync(invalidPath), `Missing invalid example ${invalidPath}`);
    const invalidResult = validateSchema(entry.schemaName, JSON.parse(fs.readFileSync(invalidPath, "utf8")));
    assert(!invalidResult.valid, `${invalidPath} unexpectedly passed validation`);
  }

  const vectorRoot = `specs/test-vectors/${entry.objectType}/${entry.vector}`;
  const input = readJson(`${vectorRoot}/input.json`) as Record<string, unknown>;
  const manifest = readJson(`${vectorRoot}/manifest.json`) as {
    object_type: string;
    expected: { schema_valid: boolean; canonical_hash: string };
  };
  const vectorResult = validateSchema(entry.schemaName, input);
  assert(vectorResult.valid === manifest.expected.schema_valid, `${vectorRoot} schema result mismatch`);
  assert(input.type === manifest.object_type, `${vectorRoot} object type mismatch`);
  const canonicalHash = hashDomain(String(input.type), canonicalBytes(input));
  assert(canonicalHash === manifest.expected.canonical_hash, `${vectorRoot} canonical hash mismatch`);
}

checkArtifactTree();
checkLatexRequiredShapes();
checkErrorRegistry();
for (const level of levels) {
  for (const entry of requiredByLevel[level] ?? []) checkObject(entry);
}

console.log(JSON.stringify({ conformance: requestedLevel, checked_levels: levels, ok: true }, null, 2));
