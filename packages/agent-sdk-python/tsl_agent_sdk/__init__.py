from dataclasses import dataclass


@dataclass(frozen=True)
class AgentDelegation:
    agent_trust_id: str
    controller_trust_id: str
    scope: list[str]
    expires_at: str


def build_agent_delegation(agent_trust_id: str, controller_trust_id: str, scope: list[str], expires_at: str) -> AgentDelegation:
    return AgentDelegation(
        agent_trust_id=agent_trust_id,
        controller_trust_id=controller_trust_id,
        scope=scope,
        expires_at=expires_at,
    )
