#!/usr/bin/env node
const { existsSync, readFileSync, writeFileSync, mkdirSync } = require("node:fs");
const { dirname, join } = require("node:path");

const root = join(__dirname, "..");
const manifestPath = join(root, "conformance", "production-readiness-evidence.json");
const outputPath = join(root, "evidence", "production-readiness-report.md");
const forbidden = /\b(draft|missing|placeholder|not implemented|non-mainnet|TODO|REPLACE)\b/i;

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function stale(date) {
  if (!date) return true;
  const ms = Date.parse(date);
  return !Number.isFinite(ms) || (Date.now() - ms) / 86400000 > 180;
}

function summarizeItem(item) {
  const missingLinks = [];
  const blockedLinks = [];
  for (const link of item.evidence_links ?? []) {
    const full = join(root, link);
    if (!existsSync(full)) {
      missingLinks.push(link);
      continue;
    }
    if (link.endsWith(".schema.json")) continue;
    const text = readFileSync(full, "utf8");
    if (forbidden.test(text)) blockedLinks.push(link);
  }
  const unresolvedHighCritical = (item.blocking_findings ?? []).filter(
    (finding) => (finding.severity === "high" || finding.severity === "critical") && finding.status !== "closed"
  );
  const blockers = [
    item.status !== "approved" ? `status=${item.status}` : null,
    item.release_decision !== "approved" ? `decision=${item.release_decision}` : null,
    item.approver ? null : "missing approver",
    stale(item.review_date) ? "missing or stale review date" : null,
    ...missingLinks.map((link) => `missing evidence link ${link}`),
    ...blockedLinks.map((link) => `unapproved evidence language in ${link}`),
    ...unresolvedHighCritical.map((finding) => `unresolved ${finding.severity} finding ${finding.id}`)
  ].filter(Boolean);
  return { ...item, blockers };
}

const manifest = readJson(manifestPath);
const items = manifest.items.map(summarizeItem);
const lines = [
  "# Production Readiness Evidence Report",
  "",
  `Generated at: ${new Date().toISOString()}`,
  `Manifest status: ${manifest.status}`,
  `Release decision: ${manifest.release_decision}`,
  `Approver: ${manifest.approver ?? "none"}`,
  `Review date: ${manifest.review_date ?? "none"}`,
  "",
  "This report is operational evidence inventory only. It is not a mainnet approval.",
  "",
  "## Items",
  ""
];

for (const item of items) {
  lines.push(`### ${item.id}`);
  lines.push(`- Owner: ${item.owner}`);
  lines.push(`- Status: ${item.status}`);
  lines.push(`- Release decision: ${item.release_decision}`);
  lines.push(`- Approver: ${item.approver ?? "none"}`);
  lines.push(`- Review date: ${item.review_date ?? "none"}`);
  lines.push(`- Evidence links: ${(item.evidence_links ?? []).join(", ")}`);
  lines.push(`- Blockers: ${item.blockers.length ? item.blockers.join("; ") : "none"}`);
  lines.push("");
}

mkdirSync(dirname(outputPath), { recursive: true });
writeFileSync(outputPath, `${lines.join("\n")}\n`);
process.stdout.write(`${JSON.stringify({ ok: true, report: "evidence/production-readiness-report.md", blocked_items: items.filter((item) => item.blockers.length).map((item) => item.id) }, null, 2)}\n`);
