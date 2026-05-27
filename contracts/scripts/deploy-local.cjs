const { writeFileSync, mkdirSync } = require("node:fs");
const path = require("node:path");
const { ethers } = require("hardhat");

async function deploy(name) {
  const factory = await ethers.getContractFactory(name);
  const contract = await factory.deploy();
  await contract.waitForDeployment();
  return contract;
}

async function main() {
  const network = await ethers.provider.getNetwork();
  const [deployer] = await ethers.getSigners();

  const checkpointRegistry = await deploy("CheckpointRegistry");
  const trustIDRegistry = await deploy("TrustIDRegistry");
  const revocationRegistry = await deploy("RevocationRegistry");
  const providerRegistry = await deploy("ProviderRegistry");
  const governanceRegistry = await deploy("GovernanceRegistry");
  const relayIds = [
    ethers.id("did:tsl:relay:dev"),
    ethers.id("did:tsl:relay:test")
  ];
  for (const relayId of relayIds) {
    await (await checkpointRegistry.setAuthorizedRelay(relayId, true)).wait();
    await (await checkpointRegistry.setRelaySigner(relayId, deployer.address)).wait();
  }

  const deployment = {
    network: "localhost",
    chainId: Number(network.chainId),
    deployer: deployer.address,
    checkpointRegistry: await checkpointRegistry.getAddress(),
    trustIDRegistry: await trustIDRegistry.getAddress(),
    revocationRegistry: await revocationRegistry.getAddress(),
    providerRegistry: await providerRegistry.getAddress(),
    governanceRegistry: await governanceRegistry.getAddress(),
    authorizedRelays: relayIds,
    relaySigners: Object.fromEntries(relayIds.map((relayId) => [relayId, deployer.address]))
  };

  const deploymentsDir = path.resolve(process.cwd(), "deployments");
  mkdirSync(deploymentsDir, { recursive: true });
  writeFileSync(path.join(deploymentsDir, "local.json"), `${JSON.stringify(deployment, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify(deployment, null, 2)}\n`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
