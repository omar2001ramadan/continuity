import express from "express";
import { rateLimit } from "express-rate-limit";
import {
  buildAgentActionV2,
  buildAgentDelegation,
  buildDelegationPolicyV2,
  buildIdentityFromSeed,
  canonicalBytes,
  delegationPolicyV2Hash,
  hashDomain,
  MemoryTrustResolver,
  randomHex32,
  sha256Hex,
  signAgentActionV2,
  signAgentDelegation,
  signDelegationPolicyV2,
  signMessageEvent,
  verifyDelegatedAgentActionV0,
  verifyAgentDelegation,
  type AgentActionV2,
  type AgentDelegationV1,
  type DelegationPolicyV2,
  type IdentityDocumentV1
} from "../../../packages/core-ts/src/index";

export function createAgentSidecar() {
  const app = express();
  app.use(express.json({ limit: "1mb" }));
  app.use(rateLimit({
    windowMs: Number(process.env.TSL_HTTP_RATE_LIMIT_WINDOW_MS ?? 60_000),
    limit: Number(process.env.TSL_HTTP_RATE_LIMIT_MAX ?? 1000),
    standardHeaders: true,
    legacyHeaders: false
  }));
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

  app.post("/v1/agent/delegation-policies/v2", (req, res) => {
    try {
      const principalSeed = req.body.principal_seed_hex ?? process.env.TSL_AGENT_CONTROLLER_SEED_HEX;
      if (!principalSeed) throw new Error("principal seed is required for delegation_policy.v2 signing");
      const policy = signDelegationPolicyV2(
        buildDelegationPolicyV2({
          principal: req.body.principal ?? req.body.principal_trust_id ?? process.env.TSL_AGENT_CONTROLLER_ID,
          delegate: req.body.delegate ?? req.body.agent_trust_id ?? process.env.TSL_AGENT_ID,
          effect: req.body.effect ?? "allow",
          actions: req.body.actions ?? [],
          resources: req.body.resources ?? [],
          constraints: req.body.constraints ?? {},
          ...(req.body.subdelegation ? { subdelegation: req.body.subdelegation } : {}),
          ...(req.body.parent_policy_id ? { parent_policy_id: req.body.parent_policy_id } : {}),
          valid_from: req.body.valid_from ?? new Date().toISOString(),
          valid_until: req.body.valid_until,
          revocation_pointer: req.body.revocation_pointer,
          ...(req.body.nonce ? { nonce: req.body.nonce } : {})
        }),
        principalSeed
      );
      res.json({ status: "accepted", policy, policy_hash: delegationPolicyV2Hash(policy) });
    } catch (error) {
      res.status(400).json({ error: { code: "TSL_DELEGATION_POLICY_FAILED", message: error instanceof Error ? error.message : String(error) } });
    }
  });

  app.post("/v1/agent/actions/v2", (req, res) => {
    try {
      const agentSeed = req.body.agent_seed_hex ?? process.env.TSL_AGENT_SEED_HEX;
      if (!agentSeed) throw new Error("agent seed is required for agent_action.v2 signing");
      const delegationChain = (req.body.delegation_chain ?? req.body.delegation_policies ?? []) as DelegationPolicyV2[];
      const parameters = req.body.parameters ?? {};
      const action = signAgentActionV2(
        buildAgentActionV2({
          agent: req.body.agent ?? req.body.agent_trust_id ?? process.env.TSL_AGENT_ID,
          principal: req.body.principal ?? req.body.principal_trust_id ?? process.env.TSL_AGENT_CONTROLLER_ID,
          action: req.body.action,
          resource: req.body.resource,
          ...(req.body.tool ? { tool: req.body.tool } : {}),
          parameters_commitment: req.body.parameters_commitment ?? hashDomain("tsl.agent.parameters.v1", canonicalBytes(parameters)),
          parameter_disclosure_policy: req.body.parameter_disclosure_policy ?? "selective",
          delegation_chain_root: req.body.delegation_chain_root ?? sha256Hex(canonicalBytes(delegationChain.map((policy) => delegationPolicyV2Hash(policy)))),
          nonce: req.body.nonce ?? randomHex32(),
          ...(req.body.value_minor_units !== undefined ? { value_minor_units: Number(req.body.value_minor_units) } : {}),
          ...(req.body.human_approval_proof ? { human_approval_proof: req.body.human_approval_proof } : {}),
          issued_at: req.body.issued_at
        }),
        agentSeed
      );
      res.json({ status: "accepted", action, parameters });
    } catch (error) {
      res.status(400).json({ error: { code: "TSL_AGENT_ACTION_V2_FAILED", message: error instanceof Error ? error.message : String(error) } });
    }
  });

  app.post("/v1/agent/actions/v2/verify", (req, res) => {
    try {
      const identities: IdentityDocumentV1[] = [...defaultIdentities(), ...((req.body.identities ?? []) as IdentityDocumentV1[])];
      const publicKeys: Record<string, string> = {};
      for (const identity of identities) {
        const key = identity.verification_methods.find((method) => method.type === "ed25519" && method.status === "active");
        if (key) publicKeys[identity.id] = key.public_key;
      }
      const result = verifyDelegatedAgentActionV0({
        action: req.body.action as AgentActionV2,
        delegation_chain: (req.body.delegation_chain ?? req.body.delegation_policies ?? []) as DelegationPolicyV2[],
        public_keys: publicKeys,
        parameters: req.body.parameters,
        revoked_policy_ids: req.body.revoked_policy_ids,
        revoked_pointers: req.body.revoked_pointers
      });
      res.status(result.ok ? 200 : 422).json({ status: result.ok ? "agent_inside_scope" : "agent_outside_scope", result });
    } catch (error) {
      res.status(400).json({ error: { code: "TSL_AGENT_ACTION_V2_VERIFY_FAILED", message: error instanceof Error ? error.message : String(error) } });
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
