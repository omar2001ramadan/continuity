import "./load-env.cjs";

const config = {
  network: "base",
  chain_id: 8453,
  rpc_url_configured: Boolean(process.env.BASE_RPC_URL || process.env.TSL_BASE_RPC_URL),
  private_key_configured: Boolean(process.env.TSL_BASE_PRIVATE_KEY),
  will_broadcast: false,
  required_manual_gates: [
    "external security audit complete",
    "production ZK ceremony accepted",
    "KMS/HSM signing adapter configured",
    "abuse and appeal operator process staffed",
    "Base Sepolia release report accepted"
  ]
};

process.stdout.write(JSON.stringify(config, null, 2) + "\n");
