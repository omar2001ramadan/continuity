import "./load-env.cjs";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { ethers } from "ethers";
import {
  LocalEvmSettlementBackend,
  MemoryTrustResolver,
  ZERO_HASH,
  buildIdentityFromSeed,
  buildInclusionProof,
  buildMerkleTree,
  checkpointHash,
  signMessageEvent,
  verifyTSL,
  type BatchCheckpointV1,
  type Hex32
} from "../packages/core-ts/src/index";

const deploymentPath = process.env.TSL_BASE_SEPOLIA_DEPLOYMENT ?? "deployments/base-sepolia.json";
const deployment = JSON.parse(readFileSync(deploymentPath, "utf8")) as { checkpointRegistry: string; chainId: number };
const rpcUrl = process.env.BASE_SEPOLIA_RPC_URL ?? process.env.TSL_BASE_SEPOLIA_RPC_URL ?? process.env.TSL_SETTLEMENT_RPC_URL;
if (!rpcUrl) throw new Error("BASE_SEPOLIA_RPC_URL or TSL_SETTLEMENT_RPC_URL is required");

const seedHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const trustId = "did:tsl:base-sepolia:e2e";
const keyId = "#base-sepolia-key-1";
const identity = buildIdentityFromSeed({ trust_id: trustId, key_id: keyId, seed_hex: seedHex });
const signed = signMessageEvent({
  sender: trustId,
  signing_key_id: keyId,
  seed_hex: seedHex,
  message: "base-sepolia-settlement-e2e",
  disclosure_policy: "commitment_only"
});
const epochStartMs = Math.floor(Date.now() / 300000) * 300000;
const shard = "beef";
const tree = buildMerkleTree([signed.commitment_hash]);
const checkpoint: BatchCheckpointV1 = {
  type: "tsl.batch_checkpoint.v1",
  epoch_start_ms: epochStartMs,
  epoch_duration_ms: 300000,
  shard,
  event_root: tree.root,
  receipt_root: ZERO_HASH,
  attestation_root: ZERO_HASH,
  revocation_root: ZERO_HASH,
  event_count: 1,
  receipt_count: 0,
  previous_checkpoint: ZERO_HASH,
  relay_id: (process.env.TSL_BASE_SEPOLIA_RELAY_IDS ?? "did:tsl:relay:base-sepolia").split(",")[0].trim(),
  relay_signature: "0x01"
};
const proof = buildInclusionProof({
  commitments: [signed.commitment_hash],
  leaf_index: 0,
  tree_kind: "event",
  epoch_start_ms: epochStartMs,
  epoch_duration_ms: 300000,
  shard,
  checkpoint_hash: checkpointHash(checkpoint)
});

const settlement = new LocalEvmSettlementBackend({
  rpcUrl,
  checkpointRegistryAddress: deployment.checkpointRegistry,
  privateKey: process.env.TSL_BASE_SEPOLIA_PRIVATE_KEY ?? process.env.TSL_SETTLEMENT_PRIVATE_KEY,
  chainId: deployment.chainId
});
const settledCheckpoint = await settlement.submitCheckpoint(checkpoint);
const result = await verifyTSL(
  { envelope: signed.envelope, proof, checkpoint: settledCheckpoint },
  new MemoryTrustResolver([identity]),
  { require_inclusion: true, require_checkpoint: true, require_settlement: true },
  settlement
);

const provider = new ethers.JsonRpcProvider(rpcUrl);
const network = await provider.getNetwork();
const report = {
  type: "tsl.base_sepolia.deployment_report.v1",
  generated_at: new Date().toISOString(),
  chain_id: Number(network.chainId),
  configured_chain_id: deployment.chainId,
  checkpoint_registry: deployment.checkpointRegistry,
  deployer: process.env.TSL_DEPLOYER_ADDRESS,
  relay_id: checkpoint.relay_id,
  checkpoint_hash: checkpointHash(settledCheckpoint),
  settlement_tx: settledCheckpoint.settlement_tx,
  verification: result
};
mkdirSync("reports", { recursive: true });
writeFileSync("reports/base-sepolia-e2e-report.json", `${JSON.stringify(report, null, 2)}\n`);
process.stdout.write(`${JSON.stringify({ settled_checkpoint: settledCheckpoint, verification: result, report_path: "reports/base-sepolia-e2e-report.json" }, null, 2)}\n`);
if (!result.verified) process.exitCode = 1;
