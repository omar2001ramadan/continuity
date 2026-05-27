#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { Command } from "commander";
import { createSignedMessageProof, decodeProofLink, encodeProofLink, NodeSqliteLocalStore } from "../../../packages/client-sdk-ts/src/index";
import {
  ZERO_HASH,
  buildConsistencyProof,
  buildAgentDelegation,
  buildGroth16ThresholdProof,
  buildIdentityFromSeed,
  buildRevocation,
  buildThresholdProof,
  buildInclusionProof,
  buildMerkleTree,
  buildNonMembershipProof,
  checkpointHash,
  createSettlementBackendFromEnv,
  deriveEd25519PublicKey,
  InMemoryRelayStore,
  LocalEvmSettlementBackend,
  randomHex32,
  signAgentDelegation,
  signAuditFinding,
  signGovernancePolicy,
  signMessageEvent,
  signRevocation,
  revocationCommitmentHash,
  MemoryTrustResolver,
  verifyAgentDelegation,
  verifyConsistencyProof,
  verifyNonMembershipProof,
  verifyThresholdProof,
  verifyThresholdProofAsync,
  verifyTSL,
  type BatchCheckpointV1,
  type Hex32,
  type IdentityDocumentV1,
  type GovernancePolicyUnsignedV1,
  type ZkThresholdProofV1,
  type VerifyTSLInput,
  type VerifierPolicy
} from "../../../packages/core-ts/src/index";

const VECTOR = {
  seedHex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  contentSaltHex: "1111111111111111111111111111111111111111111111111111111111111111",
  nonce: "0x2222222222222222222222222222222222222222222222222222222222222222" as Hex32,
  timestamp: "2026-05-25T00:01:00Z",
  sender: "did:tsl:test:alice",
  keyId: "#test-key-1",
  message: "hello-tsl"
};

function printJson(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

function readJsonFile<T = Record<string, unknown>>(file: string): T {
  return JSON.parse(readFileSync(file, "utf8")) as T;
}

function sha256File(file: string): string {
  return `0x${createHash("sha256").update(readFileSync(file)).digest("hex")}`;
}

async function postJson(url: string, body: unknown): Promise<unknown> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  const payload = await response.json() as unknown;
  if (!response.ok) {
    throw new Error(JSON.stringify(payload));
  }
  return payload;
}

async function getJson(url: string): Promise<unknown> {
  const response = await fetch(url);
  const payload = await response.json() as unknown;
  if (!response.ok) {
    throw new Error(JSON.stringify(payload));
  }
  return payload;
}

function createCheckpoint(commitments: Hex32[], epochStartMs: number, epochDurationMs: number, shard: string): BatchCheckpointV1 {
  const tree = buildMerkleTree(commitments);
  return {
    type: "tsl.batch_checkpoint.v1",
    epoch_start_ms: epochStartMs,
    epoch_duration_ms: epochDurationMs,
    shard,
    event_root: tree.root,
    receipt_root: ZERO_HASH,
    attestation_root: ZERO_HASH,
    revocation_root: ZERO_HASH,
    event_count: commitments.length,
    receipt_count: 0,
    previous_checkpoint: ZERO_HASH,
    relay_id: "did:tsl:relay:test",
    relay_signature: "0x00"
  };
}

function deterministicBundle() {
  const identity = buildIdentityFromSeed({
    trust_id: VECTOR.sender,
    key_id: VECTOR.keyId,
    seed_hex: VECTOR.seedHex,
    created_at: "2026-05-25T00:00:00Z"
  });
  const signed = signMessageEvent({
    sender: VECTOR.sender,
    signing_key_id: VECTOR.keyId,
    message: VECTOR.message,
    seed_hex: VECTOR.seedHex,
    timestamp: VECTOR.timestamp,
    nonce: VECTOR.nonce,
    content_salt: VECTOR.contentSaltHex,
    disclosure_policy: "commitment_only"
  });
  const epochStartMs = Date.parse("2026-05-25T00:00:00Z");
  const epochDurationMs = 300000;
  const shard = "00af";
  const checkpoint = createCheckpoint([signed.commitment_hash], epochStartMs, epochDurationMs, shard);
  const proof = buildInclusionProof({
    commitments: [signed.commitment_hash],
    leaf_index: 0,
    tree_kind: "event",
    epoch_start_ms: epochStartMs,
    epoch_duration_ms: epochDurationMs,
    shard,
    checkpoint_hash: checkpointHash(checkpoint)
  });

  return {
    identity,
    envelope: signed.envelope,
    proof,
    checkpoint,
    message_disclosure: {
      raw_message: VECTOR.message,
      content_salt: VECTOR.contentSaltHex
    },
    vector: {
      public_key_hex: deriveEd25519PublicKey(VECTOR.seedHex),
      content_commitment_hex: signed.envelope.content_commitment,
      canonical_unsigned_event: signed.canonical_unsigned_event,
      event_hash_hex: signed.event_hash,
      signature_hex: signed.envelope.signature,
      commitment_hash_hex: signed.commitment_hash,
      single_leaf_merkle_root_hex: proof.root
    }
  };
}

async function verifyBundle(bundle: Record<string, unknown>, defaultPolicy: VerifierPolicy = {}) {
  const identities: IdentityDocumentV1[] = [];
  if (bundle.identity_document) identities.push(bundle.identity_document as IdentityDocumentV1);
  if (bundle.identity) identities.push(bundle.identity as IdentityDocumentV1);
  if (Array.isArray(bundle.identities)) identities.push(...(bundle.identities as IdentityDocumentV1[]));

  const resolver = new MemoryTrustResolver(identities);
  const input: VerifyTSLInput = {
    envelope: bundle.envelope as VerifyTSLInput["envelope"],
    proof: bundle.proof as VerifyTSLInput["proof"],
    checkpoint: bundle.checkpoint as VerifyTSLInput["checkpoint"],
    message_disclosure: bundle.message_disclosure as VerifyTSLInput["message_disclosure"],
    receipts: bundle.receipts as VerifyTSLInput["receipts"],
    attestations: bundle.attestations as VerifyTSLInput["attestations"],
    revocations: bundle.revocations as VerifyTSLInput["revocations"],
    assessment: bundle.assessment as VerifyTSLInput["assessment"],
    zk_proofs: bundle.zk_proofs as VerifyTSLInput["zk_proofs"],
    delegations: bundle.delegations as VerifyTSLInput["delegations"],
    audit_findings: bundle.audit_findings as VerifyTSLInput["audit_findings"],
    consistency_proofs: bundle.consistency_proofs as VerifyTSLInput["consistency_proofs"],
    non_membership_proofs: bundle.non_membership_proofs as VerifyTSLInput["non_membership_proofs"],
    governance_policy: bundle.governance_policy as VerifyTSLInput["governance_policy"]
  };

  const policy = (bundle.policy as VerifierPolicy | undefined) ?? defaultPolicy;
  const settlementBackend = createSettlementBackendFromEnv();
  return verifyTSL(input, resolver, policy, settlementBackend ?? undefined);
}

const program = new Command();
program
  .name("tsl")
  .description("Trust Signature Layer reference CLI")
  .version("0.1.0");

program
  .command("vector")
  .description("Print the deterministic event compliance vector generated by the implementation")
  .action(() => {
    printJson(deterministicBundle().vector);
  });

program
  .command("demo")
  .description("Generate and verify a complete deterministic proof bundle")
  .action(async () => {
    const bundle = deterministicBundle();
    const result = await verifyBundle(bundle, {
      require_inclusion: true,
      require_checkpoint: true,
      require_settlement: false
    });
    printJson({ ...bundle, verification: result });
  });

program
  .command("demo-settlement")
  .description("Run a local EVM settlement demo against a deployed CheckpointRegistry")
  .requiredOption("--registry-address <address>", "CheckpointRegistry contract address")
  .option("--rpc-url <url>", "Hardhat RPC URL", "http://127.0.0.1:8545")
  .option("--private-key <hex>", "optional submitter private key")
  .action(async (options) => {
    const settlement = new LocalEvmSettlementBackend({
      rpcUrl: options.rpcUrl,
      checkpointRegistryAddress: options.registryAddress,
      privateKey: options.privateKey,
      chainId: 31337
    });
    const store = new InMemoryRelayStore({
      relay_id: "did:tsl:relay:test",
      timestamp_window_ms: Number.MAX_SAFE_INTEGER,
      settlement_backend: settlement
    });
    const identity = buildIdentityFromSeed({
      trust_id: VECTOR.sender,
      key_id: VECTOR.keyId,
      seed_hex: VECTOR.seedHex,
      created_at: "2026-05-25T00:00:00Z"
    });
    store.upsertIdentity(identity);
    const signed = signMessageEvent({
      sender: VECTOR.sender,
      signing_key_id: VECTOR.keyId,
      message: VECTOR.message,
      seed_hex: VECTOR.seedHex,
      timestamp: VECTOR.timestamp,
      nonce: VECTOR.nonce,
      content_salt: VECTOR.contentSaltHex,
      disclosure_policy: "commitment_only"
    });
    const accepted = await store.acceptEvent(signed.envelope);
    const beforeSettlement = store.proofFor(accepted.commitment_hash);
    if (!beforeSettlement) throw new Error("Failed to build inclusion proof before settlement");

    const beforeVerification = await verifyTSL(
      {
        envelope: signed.envelope,
        proof: beforeSettlement.proof,
        checkpoint: beforeSettlement.checkpoint,
        message_disclosure: {
          raw_message: VECTOR.message,
          content_salt: VECTOR.contentSaltHex
        }
      },
      store.resolver,
      { require_inclusion: true, require_checkpoint: true, require_settlement: true },
      settlement
    );

    const settledCheckpoint = await store.submitCheckpoint(accepted.epoch_start_ms, accepted.shard);
    const afterSettlement = store.proofFor(accepted.commitment_hash);
    if (!afterSettlement) throw new Error("Failed to build inclusion proof after settlement");

    const afterVerification = await verifyTSL(
      {
        envelope: signed.envelope,
        proof: afterSettlement.proof,
        checkpoint: afterSettlement.checkpoint,
        message_disclosure: {
          raw_message: VECTOR.message,
          content_salt: VECTOR.contentSaltHex
        }
      },
      store.resolver,
      { require_inclusion: true, require_checkpoint: true, require_settlement: true },
      settlement
    );

    printJson({
      accepted,
      before_settlement_verified: beforeVerification.verified,
      before_settlement_errors: beforeVerification.errors,
      settled_checkpoint: settledCheckpoint,
      after_settlement_verified: afterVerification.verified,
      after_settlement_errors: afterVerification.errors
    });
  });

program
  .command("sign-message")
  .description("Sign a message into a TSL event envelope")
  .requiredOption("--message <message>", "message to commit")
  .requiredOption("--seed-hex <hex>", "32-byte Ed25519 seed hex")
  .option("--sender <trustId>", "sender TrustID")
  .option("--key-id <keyId>", "signing key id", "#device-key-1")
  .option("--timestamp <rfc3339>", "event timestamp")
  .option("--nonce <hex32>", "event nonce")
  .action((options) => {
    const publicKey = deriveEd25519PublicKey(options.seedHex);
    const sender = options.sender ?? `did:tsl:local:0x${publicKey}`;
    const identity = buildIdentityFromSeed({
      trust_id: sender,
      key_id: options.keyId,
      seed_hex: options.seedHex,
      created_at: options.timestamp ?? new Date().toISOString()
    });
    const signed = signMessageEvent({
      sender,
      signing_key_id: options.keyId,
      message: options.message,
      seed_hex: options.seedHex,
      timestamp: options.timestamp,
      nonce: options.nonce,
      disclosure_policy: "commitment_only"
    });
    printJson({ identity, ...signed });
  });

program
  .command("create-identity")
  .description("Create a deterministic local TrustID document and optionally submit it to a relay")
  .requiredOption("--seed-hex <hex>", "32-byte Ed25519 seed hex")
  .option("--trust-id <trustId>", "TrustID to create")
  .option("--key-id <keyId>", "signing key id", "#device-key-1")
  .option("--relay-url <url>", "relay base URL to submit to")
  .action(async (options) => {
    const publicKey = deriveEd25519PublicKey(options.seedHex);
    const identity = buildIdentityFromSeed({
      trust_id: options.trustId ?? `did:tsl:local:0x${publicKey}`,
      key_id: options.keyId,
      seed_hex: options.seedHex
    });
    if (options.relayUrl) {
      const submitted = await postJson(`${options.relayUrl.replace(/\/$/, "")}/v1/identity/create`, { identity });
      printJson({ identity, submitted });
      return;
    }
    printJson({ identity });
  });

program
  .command("submit-event")
  .description("Submit an event envelope JSON file to a relay")
  .argument("<file>", "JSON file containing { envelope } or an event object")
  .requiredOption("--relay-url <url>", "relay base URL")
  .action(async (file, options) => {
    const payload = readJsonFile<Record<string, unknown>>(file);
    const event = payload.envelope ?? payload.event ?? payload;
    printJson(await postJson(`${options.relayUrl.replace(/\/$/, "")}/v1/commitments`, { event }));
  });

program
  .command("submit-receipt")
  .description("Submit a receipt commitment JSON file to a relay")
  .argument("<file>", "JSON file containing { receipt } or a receipt object")
  .requiredOption("--relay-url <url>", "relay base URL")
  .action(async (file, options) => {
    const payload = readJsonFile<Record<string, unknown>>(file);
    printJson(await postJson(`${options.relayUrl.replace(/\/$/, "")}/v1/receipts`, { receipt: payload.receipt ?? payload }));
  });

program
  .command("submit-attestation")
  .description("Submit an attestation JSON file to a relay")
  .argument("<file>", "JSON file containing { attestation } or an attestation object")
  .requiredOption("--relay-url <url>", "relay base URL")
  .action(async (file, options) => {
    const payload = readJsonFile<Record<string, unknown>>(file);
    printJson(await postJson(`${options.relayUrl.replace(/\/$/, "")}/v1/attestations`, { attestation: payload.attestation ?? payload }));
  });

program
  .command("revoke-key")
  .description("Build and optionally submit a signed key revocation")
  .requiredOption("--trust-id <trustId>", "TrustID")
  .requiredOption("--key-id <keyId>", "revoked key id")
  .requiredOption("--seed-hex <hex>", "signing seed")
  .option("--reason <reason>", "rotation | compromise | device_loss | policy_update", "compromise")
  .option("--replacement-key <keyId>", "replacement key id for rotation")
  .option("--relay-url <url>", "relay base URL")
  .action(async (options) => {
    const unsigned = buildRevocation({
      trust_id: options.trustId,
      revoked_key: options.keyId,
      replacement_key: options.replacementKey,
      reason_class: options.reason,
      effective_at: new Date().toISOString()
    });
    const revocation = signRevocation(unsigned, options.seedHex);
    const payload = { revocation, revocation_hash: revocationCommitmentHash(revocation) };
    if (options.relayUrl) {
      printJson({
        ...payload,
        submitted: await postJson(`${options.relayUrl.replace(/\/$/, "")}/v1/keys/revoke`, { revocation })
      });
      return;
    }
    printJson(payload);
  });

program
  .command("close-epoch")
  .description("Ask a log-node to close an epoch/shard into a checkpoint")
  .requiredOption("--log-url <url>", "log-node base URL")
  .requiredOption("--epoch-start-ms <ms>", "epoch start milliseconds")
  .requiredOption("--shard <hex>", "shard prefix")
  .option("--epoch-duration-ms <ms>", "epoch duration milliseconds", "300000")
  .action(async (options) => {
    printJson(await postJson(`${options.logUrl.replace(/\/$/, "")}/v1/log/close-epoch`, {
      epoch_start_ms: Number(options.epochStartMs),
      epoch_duration_ms: Number(options.epochDurationMs),
      shard: options.shard
    }));
  });

program
  .command("fetch-proof")
  .description("Fetch a portable proof bundle from a relay or log-node")
  .requiredOption("--base-url <url>", "relay or log-node base URL")
  .requiredOption("--commitment <hex32>", "commitment hash")
  .option("--tree-kind <kind>", "event | receipt | attestation | revocation")
  .action(async (options) => {
    const base = options.baseUrl.replace(/\/$/, "");
    const path = options.treeKind ? `/v1/proofs/${options.treeKind}/${options.commitment}` : `/v1/proofs/${options.commitment}`;
    printJson(await getJson(`${base}${path}`));
  });

program
  .command("verify-proof")
  .description("Verify a portable proof bundle file")
  .argument("<file>", "proof bundle JSON file")
  .option("--require-settlement", "require configured settlement backend verification")
  .action(async (file, options) => {
    const bundle = readJsonFile<Record<string, unknown>>(file);
    const result = await verifyBundle(bundle, {
      require_inclusion: Boolean(bundle.proof),
      require_checkpoint: Boolean(bundle.checkpoint),
      require_settlement: Boolean(options.requireSettlement)
    });
    printJson(result);
    if (!result.verified) process.exitCode = 1;
  });

program
  .command("proof-link:create")
  .description("Create a portable TSL proof link for a signed message")
  .requiredOption("--message <message>", "message to commit")
  .requiredOption("--seed-hex <hex>", "32-byte Ed25519 seed hex")
  .option("--sender <trustId>", "sender TrustID")
  .option("--key-id <keyId>", "signing key id", "#device-key-1")
  .option("--base-url <url>", "proof link base URL", "http://localhost:8090/p/")
  .action((options) => {
    const publicKey = deriveEd25519PublicKey(options.seedHex);
    const sender = options.sender ?? `did:tsl:local:0x${publicKey}`;
    const proof = createSignedMessageProof({
      trust_id: sender,
      key_id: options.keyId,
      seed_hex: options.seedHex,
      message: options.message
    });
    const { proof_link: _defaultProofLink, ...bundle } = proof;
    printJson({ ...bundle, proof_link: encodeProofLink(bundle, options.baseUrl) });
  });

program
  .command("proof-link:inspect")
  .description("Decode and inspect a TSL proof link payload")
  .argument("<proofLink>", "proof link URL or base64url payload")
  .action((proofLink) => {
    printJson(decodeProofLink(proofLink));
  });

program
  .command("zk:prove")
  .description("Build a local threshold selective-disclosure proof object")
  .requiredOption("--claim <claim>", "identity_age_days | reciprocal_receipt_count")
  .requiredOption("--subject <trustId>", "subject TrustID")
  .requiredOption("--value <n>", "private value used by the prover")
  .requiredOption("--threshold <n>", "public threshold")
  .option("--salt <hex32>", "witness salt")
  .option("--wasm <path>", "compiled circuit wasm path")
  .option("--zkey <path>", "Groth16 proving key path")
  .action(async (options) => {
    const input = {
      claim: options.claim,
      subject: options.subject,
      value: Number(options.value),
      threshold: Number(options.threshold),
      witness_salt: (options.salt ?? randomHex32()) as Hex32
    };
    if (options.wasm && options.zkey) {
      printJson(await buildGroth16ThresholdProof({ ...input, wasm_path: options.wasm, zkey_path: options.zkey }));
      return;
    }
    printJson(buildThresholdProof(input));
  });

program
  .command("zk:verify")
  .description("Verify a local threshold proof object")
  .argument("<file>", "proof JSON file")
  .action(async (file) => {
    const proof = readJsonFile<ZkThresholdProofV1>(file);
    const valid = proof.groth16 ? await verifyThresholdProofAsync(proof) : verifyThresholdProof(proof);
    printJson({ valid });
    if (!valid) process.exitCode = 1;
  });

program
  .command("zk:prove-receipt-count")
  .description("Build a Groth16 proof for reciprocal_receipt_count >= threshold")
  .requiredOption("--subject <trustId>", "subject TrustID")
  .requiredOption("--value <n>", "private reciprocal receipt count")
  .requiredOption("--threshold <n>", "public threshold")
  .option("--salt <hex32>", "witness salt")
  .option("--wasm <path>", "compiled circuit wasm path", "circuits/build/reciprocal_receipt_count_threshold_js/reciprocal_receipt_count_threshold.wasm")
  .option("--zkey <path>", "Groth16 proving key path", "circuits/build/reciprocal_receipt_count_threshold.zkey")
  .action(async (options) => {
    printJson(await buildGroth16ThresholdProof({
      claim: "reciprocal_receipt_count",
      subject: options.subject,
      value: Number(options.value),
      threshold: Number(options.threshold),
      witness_salt: (options.salt ?? randomHex32()) as Hex32,
      wasm_path: options.wasm,
      zkey_path: options.zkey
    }));
  });

program
  .command("zk:verify-receipt-count")
  .description("Verify a reciprocal receipt count threshold proof")
  .argument("<file>", "proof JSON file")
  .action(async (file) => {
    const proof = readJsonFile<ZkThresholdProofV1>(file);
    const valid = proof.claim === "reciprocal_receipt_count" && (await verifyThresholdProofAsync(proof));
    printJson({ valid });
    if (!valid) process.exitCode = 1;
  });

program
  .command("zk:manifest")
  .description("Print release hashes for ZK circuit artifacts")
  .action(() => {
    const artifacts = [
      {
        claim: "identity_age_days",
        circuit: "circuits/identity_age_threshold.circom",
        r1cs: "circuits/build/identity_age_threshold.r1cs",
        zkey: "circuits/build/identity_age_threshold.zkey",
        verification_key: "circuits/build/identity_age_threshold.vkey.json"
      },
      {
        claim: "reciprocal_receipt_count",
        circuit: "circuits/reciprocal_receipt_count_threshold.circom",
        r1cs: "circuits/build/reciprocal_receipt_count_threshold.r1cs",
        zkey: "circuits/build/reciprocal_receipt_count_threshold.zkey",
        verification_key: "circuits/build/reciprocal_receipt_count_threshold.vkey.json"
      }
    ];
    printJson({
      type: "tsl.zk.release_manifest.v1",
      ceremony_warning: "Development-only Groth16 setup. Use an external trusted setup before production.",
      artifacts: artifacts.map((artifact) => ({
        ...artifact,
        circuit_hash: sha256File(artifact.circuit),
        r1cs_hash: sha256File(artifact.r1cs),
        zkey_hash: sha256File(artifact.zkey),
        verification_key_hash: sha256File(artifact.verification_key)
      }))
    });
  });

program
  .command("agent:delegate")
  .description("Create a signed agent delegation")
  .requiredOption("--controller <trustId>", "controller TrustID")
  .requiredOption("--controller-key-id <keyId>", "controller key id")
  .requiredOption("--controller-seed-hex <hex>", "controller Ed25519 seed")
  .requiredOption("--agent <trustId>", "agent TrustID")
  .requiredOption("--agent-key-id <keyId>", "agent key id")
  .requiredOption("--agent-seed-hex <hex>", "agent Ed25519 seed")
  .requiredOption("--scope <scope>", "comma-separated scopes")
  .requiredOption("--expires-at <rfc3339>", "delegation expiry")
  .option("--nonce <hex32>", "delegation nonce")
  .action((options) => {
    const delegation = signAgentDelegation(
      buildAgentDelegation({
        controller: options.controller,
        controller_key_id: options.controllerKeyId,
        agent: options.agent,
        agent_key_id: options.agentKeyId,
        scope: String(options.scope).split(",").map((scope) => scope.trim()).filter(Boolean),
        expires_at: options.expiresAt,
        nonce: (options.nonce ?? randomHex32()) as Hex32
      }),
      options.controllerSeedHex,
      options.agentSeedHex
    );
    printJson({ delegation });
  });

program
  .command("agent:sign-action")
  .description("Sign an agent action event after checking a delegation scope")
  .requiredOption("--delegation-file <file>", "delegation JSON file")
  .requiredOption("--controller-identity-file <file>", "controller identity JSON file")
  .requiredOption("--agent-identity-file <file>", "agent identity JSON file")
  .requiredOption("--agent-seed-hex <hex>", "agent Ed25519 seed")
  .requiredOption("--scope <scope>", "required scope")
  .requiredOption("--message <message>", "agent action payload to commit")
  .option("--timestamp <rfc3339>", "event timestamp")
  .action(async (options) => {
    const delegationPayload = readJsonFile<Record<string, unknown>>(options.delegationFile);
    const delegation = (delegationPayload.delegation ?? delegationPayload) as NonNullable<VerifyTSLInput["delegations"]>[number];
    const controllerIdentity = readJsonFile<IdentityDocumentV1>(options.controllerIdentityFile);
    const agentIdentity = readJsonFile<IdentityDocumentV1>(options.agentIdentityFile);
    const resolver = new MemoryTrustResolver([controllerIdentity, agentIdentity]);
    const timestamp = options.timestamp ?? new Date().toISOString();
    const delegationValid = await verifyAgentDelegation(delegation, resolver, options.scope, timestamp);
    if (!delegationValid) {
      printJson({ accepted: false, error: { code: "TSL_AGENT_SCOPE_INVALID", message: "Delegation does not authorize this action" } });
      process.exitCode = 1;
      return;
    }
    const signed = signMessageEvent({
      sender: delegation.agent,
      signing_key_id: delegation.agent_key_id,
      message: options.message,
      seed_hex: options.agentSeedHex,
      event_class: "agent_call",
      timestamp,
      disclosure_policy: "commitment_only"
    });
    printJson({ accepted: true, delegation, ...signed });
  });

program
  .command("audit:gossip")
  .description("Create or submit a signed audit finding")
  .requiredOption("--auditor <trustId>", "auditor TrustID")
  .requiredOption("--auditor-seed-hex <hex>", "auditor Ed25519 seed")
  .requiredOption("--class <class>", "finding class")
  .requiredOption("--severity <severity>", "info | warning | critical")
  .requiredOption("--evidence-commitment <hex32>", "evidence commitment")
  .option("--checkpoint-hash <hex32>", "checkpoint hash")
  .option("--epoch-start-ms <ms>", "checkpoint epoch")
  .option("--shard <shard>", "checkpoint shard")
  .option("--relay-url <url>", "relay/auditor base URL to submit to")
  .action(async (options) => {
    const finding = signAuditFinding(
      {
        type: "tsl.audit.finding.v1",
        auditor: options.auditor,
        finding_class: options.class,
        severity: options.severity,
        evidence_commitment: options.evidenceCommitment,
        ...(options.checkpointHash ? { checkpoint_hash: options.checkpointHash } : {}),
        ...(options.epochStartMs ? { epoch_start_ms: Number(options.epochStartMs) } : {}),
        ...(options.shard ? { shard: options.shard } : {}),
        issued_at: new Date().toISOString()
      },
      options.auditorSeedHex
    );
    if (options.relayUrl) {
      printJson({
        finding,
        submitted: await postJson(`${options.relayUrl.replace(/\/$/, "")}/v1/gossip/audit-finding`, { finding })
      });
      return;
    }
    printJson({ finding });
  });

program
  .command("audit:sync-peers")
  .description("Ask a log or auditor node to sync gossip peers")
  .requiredOption("--node-url <url>", "log/auditor node URL")
  .option("--peer-url <url>", "optional single peer to sync")
  .action(async (options) => {
    printJson(await postJson(`${options.nodeUrl.replace(/\/$/, "")}/v1/gossip/sync`, options.peerUrl ? { peer_url: options.peerUrl } : {}));
  });

program
  .command("consistency:audit")
  .description("Build or verify a checkpoint consistency proof")
  .requiredOption("--checkpoints-file <file>", "JSON array of checkpoints, or object with checkpoints")
  .option("--verify-only", "verify an existing consistency proof file instead of building from checkpoints")
  .action((options) => {
    const payload = readJsonFile<Record<string, unknown> | BatchCheckpointV1[]>(options.checkpointsFile);
    if (options.verifyOnly) {
      const proof = (payload as Record<string, unknown>).proof ?? payload;
      printJson({ valid: verifyConsistencyProof(proof as never) });
      return;
    }
    const checkpoints = Array.isArray(payload) ? payload : (payload.checkpoints as BatchCheckpointV1[]);
    const proof = buildConsistencyProof(checkpoints);
    printJson({ proof, valid: verifyConsistencyProof(proof) });
  });

program
  .command("zk:prove-non-membership")
  .description("Build a local revocation-set non-membership proof")
  .requiredOption("--subject <trustId>", "subject TrustID")
  .requiredOption("--value-commitment <hex32>", "value commitment to prove absent")
  .option("--set-file <file>", "JSON array of sorted or unsorted hex32 values", "")
  .action((options) => {
    const setValues = options.setFile ? readJsonFile<Hex32[]>(options.setFile) : [];
    const proof = buildNonMembershipProof({
      subject: options.subject,
      value_commitment: options.valueCommitment,
      set_values: setValues
    });
    printJson({ proof, valid: verifyNonMembershipProof(proof) });
  });

program
  .command("governance:sign-policy")
  .description("Sign a governance policy commitment object")
  .requiredOption("--authority <trustId>", "authority TrustID")
  .requiredOption("--authority-key-id <keyId>", "authority key id")
  .requiredOption("--authority-seed-hex <hex>", "authority Ed25519 seed")
  .requiredOption("--policy-id <id>", "policy id")
  .requiredOption("--schema-commitment <hex32>", "protocol schema commitment")
  .requiredOption("--provider-rules-commitment <hex32>", "provider rules commitment")
  .requiredOption("--appeal-policy-commitment <hex32>", "appeal policy commitment")
  .option("--model-card-commitment <hex32>", "model card commitment")
  .option("--emergency-pause", "mark policy as emergency paused")
  .option("--expires-at <rfc3339>", "policy expiry")
  .action((options) => {
    const unsigned: GovernancePolicyUnsignedV1 = {
      type: "tsl.governance_policy.v1",
      policy_id: options.policyId,
      authority: options.authority,
      authority_key_id: options.authorityKeyId,
      protocol_schema_commitment: options.schemaCommitment,
      provider_rules_commitment: options.providerRulesCommitment,
      appeal_policy_commitment: options.appealPolicyCommitment,
      ...(options.modelCardCommitment ? { model_card_commitment: options.modelCardCommitment } : {}),
      emergency_pause: Boolean(options.emergencyPause),
      issued_at: new Date().toISOString(),
      ...(options.expiresAt ? { expires_at: options.expiresAt } : {})
    };
    printJson({ governance_policy: signGovernancePolicy(unsigned, options.authoritySeedHex) });
  });

program
  .command("local-store:set")
  .description("Write an encrypted value to the Node SQLite local privacy store")
  .requiredOption("--db <path>", "SQLite database path")
  .requiredOption("--passphrase <passphrase>", "local encryption passphrase")
  .requiredOption("--key <key>", "record key")
  .requiredOption("--json-file <file>", "JSON value file")
  .action(async (options) => {
    const store = await NodeSqliteLocalStore.open(options.db, options.passphrase);
    store.set(options.key, readJsonFile(options.jsonFile));
    printJson({ status: "accepted", key: options.key });
  });

program
  .command("local-store:get")
  .description("Read and decrypt a value from the Node SQLite local privacy store")
  .requiredOption("--db <path>", "SQLite database path")
  .requiredOption("--passphrase <passphrase>", "local encryption passphrase")
  .requiredOption("--key <key>", "record key")
  .option("--out <file>", "optional output file")
  .action(async (options) => {
    const store = await NodeSqliteLocalStore.open(options.db, options.passphrase);
    const value = store.get(options.key);
    if (options.out) writeFileSync(options.out, `${JSON.stringify(value, null, 2)}\n`);
    printJson({ key: options.key, value });
  });

program
  .command("verify-file")
  .description("Verify a JSON proof bundle with identity/envelope/proof/checkpoint fields")
  .argument("<file>", "path to JSON bundle")
  .option("--require-settlement", "require configured settlement backend verification")
  .action(async (file, options) => {
    const bundle = JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>;
    const result = await verifyBundle(bundle, {
      require_inclusion: Boolean(bundle.proof),
      require_checkpoint: Boolean(bundle.checkpoint),
      require_settlement: Boolean(options.requireSettlement)
    });
    printJson(result);
    if (!result.verified) {
      process.exitCode = 1;
    }
  });

program
  .command("submit-checkpoint")
  .description("Submit a checkpoint or proof bundle checkpoint to a local EVM CheckpointRegistry")
  .argument("<file>", "path to checkpoint JSON or proof bundle JSON")
  .requiredOption("--registry-address <address>", "CheckpointRegistry contract address")
  .option("--rpc-url <url>", "Hardhat RPC URL", "http://127.0.0.1:8545")
  .option("--private-key <hex>", "optional submitter private key")
  .action(async (file, options) => {
    const payload = JSON.parse(readFileSync(file, "utf8")) as { checkpoint?: BatchCheckpointV1 } | BatchCheckpointV1;
    const checkpoint = (payload as { checkpoint?: BatchCheckpointV1 }).checkpoint ?? (payload as BatchCheckpointV1);
    if (!checkpoint) throw new Error("No checkpoint found in input file");
    const settlement = new LocalEvmSettlementBackend({
      rpcUrl: options.rpcUrl,
      checkpointRegistryAddress: options.registryAddress,
      privateKey: options.privateKey,
      chainId: 31337
    });
    const settled = await settlement.submitCheckpoint(checkpoint);
    printJson(settled);
  });

await program.parseAsync(process.argv);
