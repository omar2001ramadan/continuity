require("./scripts/load-env.cjs");
require("@nomicfoundation/hardhat-ethers");

/** @type import("hardhat/config").HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200
      }
    }
  },
  networks: {
    hardhat: {
      chainId: 31337
    },
    localhost: {
      url: process.env.TSL_SETTLEMENT_RPC_URL || "http://127.0.0.1:8545",
      chainId: 31337
    },
    baseSepolia: {
      url: process.env.BASE_SEPOLIA_RPC_URL || process.env.TSL_BASE_SEPOLIA_RPC_URL || "https://sepolia.base.org",
      chainId: 84532,
      accounts: process.env.TSL_BASE_SEPOLIA_PRIVATE_KEY ? [process.env.TSL_BASE_SEPOLIA_PRIVATE_KEY] : []
    },
    base: {
      url: process.env.BASE_RPC_URL || process.env.TSL_BASE_RPC_URL || "https://mainnet.base.org",
      chainId: 8453,
      accounts: process.env.TSL_BASE_PRIVATE_KEY ? [process.env.TSL_BASE_PRIVATE_KEY] : []
    }
  },
  paths: {
    sources: "./contracts/src",
    tests: "./contracts/test",
    cache: "./contracts/cache",
    artifacts: "./contracts/artifacts"
  }
};
