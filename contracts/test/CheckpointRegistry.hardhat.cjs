const assert = require("node:assert/strict");
const { ethers } = require("hardhat");

const ZERO = "0x0000000000000000000000000000000000000000000000000000000000000000";

function bytes32(value) {
  return ethers.zeroPadValue(value, 32);
}

function sampleInput(overrides = {}) {
  return {
    epochStartMs: 1779667200000n,
    epochDurationMs: 300000,
    shard: bytes32("0x00af"),
    eventRoot: "0xc09632a2beaaf0c4702e673a7a1661673c80be478f1136b60677f38c5bb5914f",
    receiptRoot: ZERO,
    attestationRoot: ZERO,
    revocationRoot: ZERO,
    eventCount: 1n,
    receiptCount: 0n,
    previousCheckpoint: ZERO,
    relayId: ethers.id("did:tsl:relay:test"),
    ...overrides
  };
}

async function deployRegistry() {
  const [owner, submitter, stranger] = await ethers.getSigners();
  const factory = await ethers.getContractFactory("CheckpointRegistry");
  const registry = await factory.deploy();
  await registry.waitForDeployment();
  await (await registry.setAuthorizedRelay(ethers.id("did:tsl:relay:test"), true)).wait();
  await (await registry.setRelaySigner(ethers.id("did:tsl:relay:test"), owner.address)).wait();
  return { registry, owner, submitter, stranger };
}

async function relaySignature(registry, signer, input) {
  const checkpointHash = await registry.hashCheckpoint(input);
  return signer.signMessage(ethers.getBytes(checkpointHash));
}

describe("CheckpointRegistry", function () {
  it("submits and queries a checkpoint from an authorized submitter", async function () {
    const { registry, owner } = await deployRegistry();
    const input = sampleInput();
    const expectedHash = await registry.hashCheckpoint(input);

    const tx = await registry.submitCheckpoint(input, await relaySignature(registry, owner, input));
    await tx.wait();

    const storedHash = await registry.checkpointHashByEpochShard(await registry.epochShardKey(input.epochStartMs, input.shard));
    const stored = await registry.getCheckpoint(expectedHash);

    assert.equal(storedHash, expectedHash);
    assert.equal(stored.epochStartMs, input.epochStartMs);
    assert.equal(stored.epochDurationMs, BigInt(input.epochDurationMs));
    assert.equal(stored.shard, input.shard);
    assert.equal(stored.eventRoot, input.eventRoot);
    assert.equal(stored.eventCount, input.eventCount);
    assert.equal(stored.relayId, input.relayId);
    assert.notEqual(stored.submittedAt, 0n);
  });

  it("allows exact duplicate checkpoint submission idempotently", async function () {
    const { registry, owner } = await deployRegistry();
    const input = sampleInput();
    const signature = await relaySignature(registry, owner, input);

    await (await registry.submitCheckpoint(input, signature)).wait();
    await (await registry.submitCheckpoint(input, signature)).wait();

    assert.equal(await registry.hasCheckpoint(input.epochStartMs, input.shard), true);
  });

  it("rejects conflicting checkpoint roots for the same epoch and shard", async function () {
    const { registry, owner } = await deployRegistry();
    const input = sampleInput();
    const conflict = sampleInput({
      eventRoot: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    });

    await (await registry.submitCheckpoint(input, await relaySignature(registry, owner, input))).wait();
    await assert.rejects(
      registry.submitCheckpoint(conflict, await relaySignature(registry, owner, conflict)),
      /CheckpointConflict|execution reverted/
    );
  });

  it("rejects unauthorized submitters", async function () {
    const { registry, owner, stranger } = await deployRegistry();
    const input = sampleInput();
    await assert.rejects(
      registry.connect(stranger).submitCheckpoint(input, await relaySignature(registry, owner, input)),
      /UnauthorizedSubmitter|execution reverted/
    );
  });

  it("can authorize another submitter without token logic", async function () {
    const { registry, owner, submitter } = await deployRegistry();
    const input = sampleInput();
    await (await registry.setAuthorizedSubmitter(submitter.address, true)).wait();
    await (await registry.connect(submitter).submitCheckpoint(input, await relaySignature(registry, owner, input))).wait();

    assert.equal(await registry.hasCheckpoint(1779667200000n, bytes32("0x00af")), true);
  });

  it("rejects unauthorized relay ids and empty relay signatures", async function () {
    const { registry, owner } = await deployRegistry();
    const input = sampleInput({ relayId: ethers.id("did:tsl:relay:unknown") });
    await assert.rejects(
      registry.submitCheckpoint(input, await relaySignature(registry, owner, input)),
      /UnauthorizedRelay|execution reverted/
    );
    await assert.rejects(
      registry.submitCheckpoint(sampleInput(), "0x"),
      /EmptyRelaySignature|execution reverted/
    );
  });

  it("rejects a relay signature from the wrong signer", async function () {
    const { registry, stranger } = await deployRegistry();
    const input = sampleInput();
    await assert.rejects(
      registry.submitCheckpoint(input, await relaySignature(registry, stranger, input)),
      /InvalidRelaySignature|execution reverted/
    );
  });
});

describe("TrustIDRegistry", function () {
  it("registers, rotates, and revokes keys", async function () {
    const [owner] = await ethers.getSigners();
    const factory = await ethers.getContractFactory("TrustIDRegistry");
    const registry = await factory.deploy();
    await registry.waitForDeployment();
    const trustId = ethers.id("did:tsl:test:alice");
    const key1 = ethers.id("#key-1");
    const key2 = ethers.id("#key-2");

    await (await registry.register(trustId, key1, ethers.ZeroHash)).wait();
    assert.equal((await registry.identities(trustId)).controller, owner.address);
    assert.equal(await registry.getActiveKey(trustId), key1);

    await (await registry.rotateKey(trustId, key1, key2)).wait();
    assert.equal(await registry.getActiveKey(trustId), key2);
    assert.equal(await registry.isRevoked(trustId, key1), true);

    await (await registry.revokeKey(trustId, key2, 1)).wait();
    assert.equal(await registry.isRevoked(trustId, key2), true);
    assert.equal(await registry.getActiveKey(trustId), ethers.ZeroHash);
  });
});

describe("RevocationRegistry", function () {
  it("reports revocation state by effective time", async function () {
    const factory = await ethers.getContractFactory("RevocationRegistry");
    const registry = await factory.deploy();
    await registry.waitForDeployment();
    const trustId = ethers.id("did:tsl:test:alice");
    const key = ethers.id("#key-1");
    await (await registry.recordRevocation(trustId, key, 1, 1000, ethers.ZeroHash)).wait();
    assert.equal(await registry.isRevoked(trustId, key, 999), false);
    assert.equal(await registry.isRevoked(trustId, key, 1000), true);
  });
});

describe("ProviderRegistry", function () {
  it("registers providers and models and revokes providers", async function () {
    const factory = await ethers.getContractFactory("ProviderRegistry");
    const registry = await factory.deploy();
    await registry.waitForDeployment();
    const providerId = ethers.id("did:tsl:provider:local");
    const modelId = ethers.id("reference-weighted-v1");
    const modelCard = ethers.id("model-card");
    await (await registry.registerProvider(providerId, ethers.id("provider-key"), ethers.id("policy"))).wait();
    await (await registry.registerModel(providerId, modelId, modelCard)).wait();
    assert.equal(await registry.modelCards(providerId, modelId), modelCard);
    assert.equal((await registry.providers(providerId)).active, true);
    await (await registry.revokeProvider(providerId, 1)).wait();
    assert.equal((await registry.providers(providerId)).active, false);
  });
});

describe("GovernanceRegistry", function () {
  it("stores protocol policy commitments", async function () {
    const factory = await ethers.getContractFactory("GovernanceRegistry");
    const registry = await factory.deploy();
    await registry.waitForDeployment();
    const policyId = ethers.id("protocol-schema-v1");
    const commitment = ethers.id("policy-doc");
    await (await registry.setPolicyCommitment(policyId, commitment)).wait();
    assert.equal(await registry.policyCommitments(policyId), commitment);
  });
});
