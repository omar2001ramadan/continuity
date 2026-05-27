const { writeFileSync, mkdirSync } = require("node:fs");
const path = require("node:path");
const { ethers, run } = require("hardhat");

async function deploy(name) {
  const factory = await ethers.getContractFactory(name);
  const contract = await factory.deploy();
  await contract.waitForDeployment();
  return contract;
}

async function verify(address, args = []) {
  if (process.env.TSL_VERIFY_CONTRACTS !== "true") return;
  try {
    await run("verify:verify", { address, constructorArguments: args });
  } catch (error) {
    console.error(`verify failed for ${address}:`, error.message ?? error);
  }
}

async function main() {
  const network = await ethers.provider.getNetwork();
  if (Number(network.chainId) !== 84532) {
    throw new Error(`Expected Base Sepolia chain id 84532, got ${network.chainId}`);
  }
  const [deployer] = await ethers.getSigners();
  const checkpointRegistry = await deploy("CheckpointRegistry");
  const trustIDRegistry = await deploy("TrustIDRegistry");
  const revocationRegistry = await deploy("RevocationRegistry");
  const providerRegistry = await deploy("ProviderRegistry");
  const governanceRegistry = await deploy("GovernanceRegistry");

  const relayIds = (process.env.TSL_BASE_SEPOLIA_RELAY_IDS ?? "did:tsl:relay:base-sepolia")
    .split(",")
    .map((relayId) => ethers.id(relayId.trim()))
    .filter(Boolean);
  for (const relayId of relayIds) {
    await (await checkpointRegistry.setAuthorizedRelay(relayId, true)).wait();
    await (await checkpointRegistry.setRelaySigner(relayId, process.env.TSL_BASE_SEPOLIA_RELAY_SIGNER ?? deployer.address)).wait();
  }

  const deployment = {
    network: "base-sepolia",
    chainId: Number(network.chainId),
    deployer: deployer.address,
    checkpointRegistry: await checkpointRegistry.getAddress(),
    trustIDRegistry: await trustIDRegistry.getAddress(),
    revocationRegistry: await revocationRegistry.getAddress(),
    providerRegistry: await providerRegistry.getAddress(),
    governanceRegistry: await governanceRegistry.getAddress(),
    authorizedRelays: relayIds
  };

  const deploymentsDir = path.resolve(process.cwd(), "deployments");
  mkdirSync(deploymentsDir, { recursive: true });
  writeFileSync(path.join(deploymentsDir, "base-sepolia.json"), `${JSON.stringify(deployment, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify(deployment, null, 2)}\n`);

  await verify(deployment.checkpointRegistry);
  await verify(deployment.trustIDRegistry);
  await verify(deployment.revocationRegistry);
  await verify(deployment.providerRegistry);
  await verify(deployment.governanceRegistry);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
