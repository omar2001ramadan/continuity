import express from "express";
import {
  buildAgentDelegation,
  buildIdentityFromSeed,
  MemoryTrustResolver,
  randomHex32,
  signAgentDelegation,
  signMessageEvent,
  verifyAgentDelegation,
  type AgentDelegationV1,
  type IdentityDocumentV1
} from "../../../packages/core-ts/src/index";

export function createAgentSidecar() {
  const app = express();
  app.use(express.json({ limit: "1mb" }));
  app.get("/health", (_req, res) => res.json({ ok: true, service: "tsl-agent-sidecar" }));

  function defaultIdentities(): IdentityDocumentV1[] {
    const identities: IdentityDocumentV1[] = [];
    if (process.env.TSL_AGENT_CONTROLLER_ID && process.env.TSL_AGENT_CONTROLLER_KEY_ID && process.env.TSL_AGENT_CONTROLLER_SEED_HEX) {
      identities.push(
        buildIdentityFromSeed({
          trust_id: process.env.TSL_AGENT_CONTROLLER_ID,
          key_id: process.env.TSL_AGENT_CONTROLLER_KEY_ID,
          seed_hex: process.env.TSL_AGENT_CONTROLLER_SEED_HEX
        })
      );
    }
    if (process.env.TSL_AGENT_ID && process.env.TSL_AGENT_KEY_ID && process.env.TSL_AGENT_SEED_HEX) {
      identities.push(
        buildIdentityFromSeed({
          trust_id: process.env.TSL_AGENT_ID,
          key_id: process.env.TSL_AGENT_KEY_ID,
          seed_hex: process.env.TSL_AGENT_SEED_HEX
        })
      );
    }
    return identities;
  }

  app.post("/v1/agent/delegations", (req, res) => {
    try {
      const controllerSeed = req.body.controller_seed_hex ?? process.env.TSL_AGENT_CONTROLLER_SEED_HEX;
      const agentSeed = req.body.agent_seed_hex ?? process.env.TSL_AGENT_SEED_HEX;
      if (!controllerSeed || !agentSeed) throw new Error("controller and agent seeds are required for local sidecar signing");
      const delegation = signAgentDelegation(
        buildAgentDelegation({
          controller: req.body.controller_trust_id ?? process.env.TSL_AGENT_CONTROLLER_ID,
          controller_key_id: req.body.controller_key_id ?? process.env.TSL_AGENT_CONTROLLER_KEY_ID ?? "#controller-key-1",
          agent: req.body.agent_trust_id ?? process.env.TSL_AGENT_ID,
          agent_key_id: req.body.agent_key_id ?? process.env.TSL_AGENT_KEY_ID ?? "#agent-key-1",
          scope: req.body.scope ?? [],
          session_key: req.body.session_key,
          max_uses: req.body.max_uses,
          spending_limit_commitment: req.body.spending_limit_commitment,
          expires_at: req.body.expires_at,
          nonce: req.body.nonce ?? randomHex32()
        }),
        controllerSeed,
        agentSeed
      );
      res.json({ status: "accepted", delegation });
    } catch (error) {
      res.status(400).json({ error: { code: "TSL_AGENT_DELEGATION_FAILED", message: error instanceof Error ? error.message : String(error) } });
    }
  });

  app.post("/v1/agent/sign-action", async (req, res) => {
    try {
      const delegation = req.body.delegation as AgentDelegationV1;
      const identities = [...defaultIdentities(), ...(req.body.identities ?? [])];
      const resolver = new MemoryTrustResolver(identities);
      const requiredScope = String(req.body.scope);
      if (req.body.action_scope && req.body.action_scope !== requiredScope) {
        res.status(422).json({ error: { code: "TSL_AGENT_SCOPE_INVALID", message: "Action scope does not match requested signing scope" } });
        return;
      }
      const timestamp = req.body.timestamp ?? new Date().toISOString();
      const valid = await verifyAgentDelegation(delegation, resolver, requiredScope, timestamp);
      if (!valid) {
        res.status(422).json({ error: { code: "TSL_AGENT_SCOPE_INVALID", message: "Delegation does not authorize this action" } });
        return;
      }
      const agentSeed = req.body.agent_seed_hex ?? process.env.TSL_AGENT_SEED_HEX;
      if (!agentSeed) throw new Error("agent seed is required for local sidecar signing");
      const signed = signMessageEvent({
        sender: delegation.agent,
        signing_key_id: delegation.agent_key_id,
        seed_hex: agentSeed,
        message: String(req.body.message ?? req.body.action ?? requiredScope),
        event_class: "agent_call",
        timestamp,
        disclosure_policy: "commitment_only"
      });
      res.json({ status: "accepted", delegation, ...signed });
    } catch (error) {
      res.status(400).json({ error: { code: "TSL_AGENT_ACTION_FAILED", message: error instanceof Error ? error.message : String(error) } });
    }
  });
  return app;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT ?? 8091);
  createAgentSidecar().listen(port, () => process.stdout.write(`tsl agent-sidecar listening on http://localhost:${port}\n`));
}
