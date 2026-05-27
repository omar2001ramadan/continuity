#!/usr/bin/env node

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const root = path.resolve(__dirname, "..");
const sourcePath = path.join(root, "Core_architecture.md");
const outputPath = path.join(root, "docs", "tsl-release-candidate.tex");
const canonicalSpecOutputPath = path.join(root, "specs", "latex", "Trust_Signature_Layer_full_implementation_v3.tex");
const buildPath = path.join(root, "docs", "tsl-release-candidate-build.md");

function readJson(relativePath, fallback = null) {
  const fullPath = path.join(root, relativePath);
  if (!fs.existsSync(fullPath)) return fallback;
  return JSON.parse(fs.readFileSync(fullPath, "utf8"));
}

function readText(relativePath, fallback = "") {
  const fullPath = path.join(root, relativePath);
  if (!fs.existsSync(fullPath)) return fallback;
  return fs.readFileSync(fullPath, "utf8");
}

function sha256File(relativePath) {
  const fullPath = path.join(root, relativePath);
  if (!fs.existsSync(fullPath)) return "missing";
  return `0x${crypto.createHash("sha256").update(fs.readFileSync(fullPath)).digest("hex")}`;
}

function latexEscape(value) {
  return String(value ?? "")
    .replace(/\\/g, "\\textbackslash{}")
    .replace(/&/g, "\\&")
    .replace(/%/g, "\\%")
    .replace(/\$/g, "\\$")
    .replace(/#/g, "\\#")
    .replace(/_/g, "\\_")
    .replace(/{/g, "\\{")
    .replace(/}/g, "\\}")
    .replace(/~/g, "\\textasciitilde{}")
    .replace(/\^/g, "\\textasciicircum{}");
}

function tt(value) {
  return `\\scriptsize\\texttt{${latexEscape(value)}}`;
}

function compactHex(value) {
  const text = String(value ?? "");
  if (!/^0x[0-9a-fA-F]{40,}$/.test(text)) return text;
  return `${text.slice(0, 18)}...${text.slice(-12)}`;
}

function ttCompact(value) {
  return tt(compactHex(value));
}

function bool(value) {
  return value ? "true" : "false";
}

function tableRows(rows) {
  return rows.map(([k, v]) => `${latexEscape(k)} & ${v} \\\\`).join("\n");
}

const deployment = readJson("deployments/base-sepolia.json", {});
const report = readJson("reports/base-sepolia-e2e-report.json", {});
const zkManifest = readJson("docs/zk-artifact-manifest.json", { artifacts: [] });
const goNoGo = readText("docs/release-go-no-go.md");
const npmAudit = readText("docs/npm-audit-risk.md");
const keyCustody = readText("docs/key-custody.md");
const auditPrep = readText("docs/audit-prep.md");

const releaseCheckRows = [
  ["Build", "`npm run build`"],
  ["Unit tests", "`npm test`"],
  ["Contracts", "`npm run contracts:compile` and `npm run contracts:test`"],
  ["ZK", "`npm run zk:test` and `npm run zk:manifest`"],
  ["Parity", "`npm run parity:python` and `npm run parity:rust`"],
  ["Browser verifier", "`npm run build:web-verifier`"],
  ["Deployment checks", "`npm run deploy:validate` and `npm run deploy:base:dry-run`"],
].map(([k, v]) => `${latexEscape(k)} & ${latexEscape(v)} \\\\`).join("\n");

const statusSection = `
% ============================================================
\\section{Implementation Status: Base Sepolia Release Candidate}
% ============================================================

This release-candidate document records the current executable state of the reference implementation. It is not a mainnet production certification. It is a public-testnet implementation snapshot for the protocol described in this specification.

\\begin{principlebox}{Current Release Candidate Status}
The current implementation proves the core trust pipeline end to end: canonical objects are signed, committed to Merkle logs, checkpointed, settled on Base Sepolia, and verified through the pure verifier with settlement required. Scoring, ZK, audit consistency, governance policy, and agent delegation remain optional verifier gates rather than requirements for cryptographic validity.
\\end{principlebox}

\\subsection{Implemented Reference Stack}

\\begin{center}
\\begin{tabularx}{\\textwidth}{>{\\bfseries}p{0.30\\textwidth} X}
\\toprule
Area & Current Implementation \\\\
\\midrule
Core verifier & TypeScript canonical verifier with schema validation, canonical JSON, domain-separated hashes, Ed25519 signatures, Merkle inclusion, checkpoint validation, revocation checks, settlement adapters, and optional policy gates. \\\\
Objects & Event commitments, receipts, attestations, revocations, trust assessments, proof bundles, audit findings, governance policies, non-membership proofs, and agent delegations. \\\\
Services & Relay, log, resolver, verifier API, checkpoint submitter, scoring provider, auditor, CLI, web verifier, browser-extension skeleton, and agent sidecar. \\\\
Storage and queues & PostgreSQL migrations and Redis Streams for the local reference stack, with Merkle nodes and public commitment state persisted separately from private message content. \\\\
Settlement & Local Hardhat and Base Sepolia EVM settlement through token-free checkpoint, identity, revocation, provider, and governance registries. \\\\
ZK selective disclosure & Groth16 circuits for \\texttt{identity\\_age\\_days >= threshold} and \\texttt{reciprocal\\_receipt\\_count >= threshold}; additional ZK claim types are represented as optional proof-bundle fields. \\\\
Parity & Rust and Python parity slices validate canonicalization, hashing, signatures, Merkle roots, and deterministic vectors against the TypeScript reference. \\\\
Release gates & Local release command covers build, tests, contract tests, ZK tests, parity, browser bundle, Docker Compose config, deployment validation, and Base mainnet dry-run. \\\\
\\bottomrule
\\end{tabularx}
\\end{center}

\\subsection{External Production Gates}

\\begin{warningbox}{Not Yet Mainnet Production Complete}
The following gates remain outside the current release-candidate implementation:
\\begin{itemize}
    \\item externally governed ZK ceremony artifacts for production use,
    \\item vendor-backed KMS/HSM signing adapters,
    \\item independent security audit and audit-remediation cycle,
    \\item manual one-million-event full-path load acceptance run,
    \\item staffed abuse-review and appeal operations,
    \\item Base mainnet deployment; current mainnet path is dry-run only,
    \\item review or replacement of the production-runtime \\texttt{ethers -> ws} moderate advisory.
\\end{itemize}
\\end{warningbox}
`;

const evidenceRows = tableRows([
  ["Network", tt(deployment.network || "base-sepolia")],
  ["Chain ID", tt(deployment.chainId || report.chain_id || "84532")],
  ["Deployer", ttCompact(deployment.deployer || "missing")],
  ["Checkpoint registry", ttCompact(deployment.checkpointRegistry || report.checkpoint_registry || "missing")],
  ["TrustID registry", ttCompact(deployment.trustIDRegistry || "missing")],
  ["Revocation registry", ttCompact(deployment.revocationRegistry || "missing")],
  ["Provider registry", ttCompact(deployment.providerRegistry || "missing")],
  ["Governance registry", ttCompact(deployment.governanceRegistry || "missing")],
  ["Authorized relay hash", ttCompact((deployment.authorizedRelays || [])[0] || "missing")],
  ["Settlement transaction", ttCompact(report.settlement_tx || "missing")],
  ["Checkpoint hash", ttCompact(report.checkpoint_hash || "missing")],
  ["Verifier result", tt(bool(report.verification && report.verification.verified))],
  ["Checkpoint settled", tt(bool(report.verification && report.verification.checks && report.verification.checks.checkpoint_settled))],
]);

const zkRows = (zkManifest.artifacts || []).map((artifact) => {
  return `${tt(artifact.claim)} & ${ttCompact(artifact.circuit_hash)} & ${ttCompact(artifact.zkey_hash)} & ${ttCompact(artifact.verification_key_hash)} \\\\`;
}).join("\n") || `${tt("missing")} & ${tt("missing")} & ${tt("missing")} & ${tt("missing")} \\\\`;

const appendixSection = `
% ============================================================
\\section{Appendix D: Release Candidate Evidence}
% ============================================================

This appendix summarizes evidence generated by the repository. Long hashes are abbreviated for page layout. Full machine-readable artifacts remain in \\texttt{deployments/}, \\texttt{reports/}, and \\texttt{docs/}.

\\subsection{Base Sepolia Deployment Evidence}

\\begin{center}
\\begin{tabularx}{\\textwidth}{>{\\bfseries}p{0.28\\textwidth} X}
\\toprule
Field & Value \\\\
\\midrule
${evidenceRows}
\\bottomrule
\\end{tabularx}
\\end{center}

\\subsection{ZK Artifact Evidence}

\\begin{center}
\\begin{tabularx}{\\textwidth}{>{\\bfseries}p{0.20\\textwidth} X X X}
\\toprule
Claim & Circuit Hash & Zkey Hash & Verification Key Hash \\\\
\\midrule
${zkRows}
\\bottomrule
\\end{tabularx}
\\end{center}

\\begin{warningbox}{ZK Ceremony Warning}
${latexEscape(zkManifest.ceremony_warning || "Development-only Groth16 setup. Replace with externally governed ceremony artifacts before production use.")}
\\end{warningbox}

\\subsection{Release Gate Evidence}

\\begin{center}
\\begin{tabularx}{\\textwidth}{>{\\bfseries}p{0.30\\textwidth} X}
\\toprule
Gate & Command \\\\
\\midrule
${releaseCheckRows}
\\bottomrule
\\end{tabularx}
\\end{center}

\\subsection{Evidence File Hashes}

\\begin{center}
\\begin{tabularx}{\\textwidth}{>{\\bfseries}p{0.32\\textwidth} X}
\\toprule
File & SHA-256 \\\\
\\midrule
${tableRows([
  ["deployments/base-sepolia.json", ttCompact(sha256File("deployments/base-sepolia.json"))],
  ["reports/base-sepolia-e2e-report.json", ttCompact(sha256File("reports/base-sepolia-e2e-report.json"))],
  ["docs/zk-artifact-manifest.json", ttCompact(sha256File("docs/zk-artifact-manifest.json"))],
  ["docs/release-go-no-go.md", ttCompact(sha256File("docs/release-go-no-go.md"))],
  ["docs/npm-audit-risk.md", ttCompact(sha256File("docs/npm-audit-risk.md"))],
])}
\\bottomrule
\\end{tabularx}
\\end{center}

\\subsection{Audit and Custody Notes}

The release checklist, audit-prep package, key-custody notes, and npm audit risk record are summarized below:

\\begin{itemize}
    \\item Release gates are documented in \\texttt{docs/release-go-no-go.md}.
    \\item Audit inputs and known limitations are documented in \\texttt{docs/audit-prep.md}.
    \\item Development signing adapters and fail-closed \\texttt{kms:}/\\texttt{hsm:} boundaries are documented in \\texttt{docs/key-custody.md}.
    \\item Runtime and development dependency advisories are documented in \\texttt{docs/npm-audit-risk.md}.
\\end{itemize}
`;

function generate() {
  let tex = fs.readFileSync(sourcePath, "utf8");
  tex = tex
    .replaceAll("title=#1", "title={#1}")
    .replace("Founder / Protocol + Engineering Implementation Specification Draft", "Base Sepolia Release Candidate Specification")
    .replace("Founder / Protocol + Engineering Implementation Specification Draft", "Base Sepolia Release Candidate Specification")
    .replace("Founder / Protocol + Hyper-Specific Robust Implementation Specification Draft", "Base Sepolia Release Candidate Specification")
    .replace("pdftitle={Trust Signature Layer: Proof of Continuity for the AI Internet - Implementation Specification}", "pdftitle={Trust Signature Layer: Proof of Continuity for the AI Internet - Base Sepolia Release Candidate}")
    .replace("pdfsubject={A transport-independent trust envelope protocol beneath applications}", "pdfsubject={A transport-independent trust envelope protocol beneath applications - public testnet release candidate}");

  const statusAnchor = "\\tableofcontents\n\\newpage";
  if (!tex.includes(statusAnchor)) {
    throw new Error(`Could not find status insertion anchor: ${statusAnchor}`);
  }
  tex = tex.replace(statusAnchor, `${statusAnchor}\n${statusSection}`);

  const appendixAnchor = "\\newpage\n\\begin{thebibliography}{9}";
  if (!tex.includes(appendixAnchor)) {
    throw new Error(`Could not find appendix insertion anchor: ${appendixAnchor}`);
  }
  tex = tex.replace(appendixAnchor, `${appendixSection}\n${appendixAnchor}`);

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.mkdirSync(path.dirname(canonicalSpecOutputPath), { recursive: true });
  fs.writeFileSync(outputPath, tex);
  fs.writeFileSync(canonicalSpecOutputPath, tex);

  const buildDoc = `# TSL Release Candidate LaTeX Build

Generated: ${new Date().toISOString()}

Source:
- Core_architecture.md
- deployments/base-sepolia.json
- reports/base-sepolia-e2e-report.json
- docs/zk-artifact-manifest.json
- docs/release-go-no-go.md
- docs/npm-audit-risk.md
- docs/key-custody.md
- docs/audit-prep.md

Outputs:
- docs/tsl-release-candidate.tex
- specs/latex/Trust_Signature_Layer_full_implementation_v3.tex
- docs/tsl-release-candidate.pdf

Evidence hashes:
- Core_architecture.md: ${sha256File("Core_architecture.md")}
- deployments/base-sepolia.json: ${sha256File("deployments/base-sepolia.json")}
- reports/base-sepolia-e2e-report.json: ${sha256File("reports/base-sepolia-e2e-report.json")}
- docs/zk-artifact-manifest.json: ${sha256File("docs/zk-artifact-manifest.json")}
- docs/release-go-no-go.md: ${sha256File("docs/release-go-no-go.md")}
- docs/npm-audit-risk.md: ${sha256File("docs/npm-audit-risk.md")}

Notes:
- This document intentionally excludes private key material and .env values.
- Base Sepolia is the only public-chain target represented as deployed evidence.
- Base mainnet remains dry-run only.
- ZK artifacts are development ceremony artifacts until replaced by an external ceremony.
`;
  fs.writeFileSync(buildPath, buildDoc);

  const unused = [goNoGo, npmAudit, keyCustody, auditPrep].filter((text) => text.length === 0);
  if (unused.length > 0) {
    throw new Error("One or more release evidence docs are missing");
  }

  console.log(JSON.stringify({
    tex: path.relative(root, outputPath),
    canonical_spec_tex: path.relative(root, canonicalSpecOutputPath),
    build: path.relative(root, buildPath),
    deployment: deployment.network || "missing",
    e2e_verified: Boolean(report.verification && report.verification.verified),
    zk_artifacts: (zkManifest.artifacts || []).length,
  }, null, 2));
}

generate();
