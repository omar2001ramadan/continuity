import { agentDelegationHash, verifyEd25519 } from "./crypto";
import { findVerificationMethod, keyActiveAt } from "./identity";
import type { AgentDelegationUnsignedV1, AgentDelegationV1, Hex32, TrustResolver } from "./types";

export function buildAgentDelegation(input: Omit<AgentDelegationUnsignedV1, "type" | "issued_at" | "nonce"> & {
  issued_at?: string;
  nonce: Hex32;
}): AgentDelegationUnsignedV1 {
  return {
    type: "tsl.agent_delegation.v1",
    controller: input.controller,
    controller_key_id: input.controller_key_id,
    agent: input.agent,
    agent_key_id: input.agent_key_id,
    scope: [...input.scope].sort(),
    ...(input.session_key ? { session_key: input.session_key } : {}),
    ...(input.max_uses !== undefined ? { max_uses: input.max_uses } : {}),
    ...(input.spending_limit_commitment ? { spending_limit_commitment: input.spending_limit_commitment } : {}),
    issued_at: input.issued_at ?? new Date().toISOString(),
    expires_at: input.expires_at,
    nonce: input.nonce
  };
}

export async function verifyAgentDelegation(
  delegation: AgentDelegationV1,
  resolver: TrustResolver,
  requiredScope?: string,
  atTime = new Date().toISOString()
): Promise<boolean> {
  if (delegation.type !== "tsl.agent_delegation.v1") return false;
  if (Date.parse(delegation.expires_at) <= Date.parse(atTime)) return false;
  if (requiredScope && !delegation.scope.includes(requiredScope)) return false;
  const controller = await resolver.resolveTrustID(delegation.controller, delegation.issued_at);
  const agent = await resolver.resolveTrustID(delegation.agent, delegation.issued_at);
  const controllerKey = controller ? findVerificationMethod(controller, delegation.controller_key_id) : null;
  const agentKey = agent ? findVerificationMethod(agent, delegation.agent_key_id) : null;
  const hash = agentDelegationHash(delegation);
  return Boolean(
    controllerKey?.type === "ed25519" &&
      agentKey?.type === "ed25519" &&
      keyActiveAt(controllerKey, delegation.issued_at) &&
      keyActiveAt(agentKey, delegation.issued_at) &&
      verifyEd25519(controllerKey.public_key, hash, delegation.controller_signature) &&
      verifyEd25519(agentKey.public_key, hash, delegation.agent_signature)
  );
}
