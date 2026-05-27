import type { IdentityDocumentV1, RFC3339, TrustID, TrustResolver, VerificationMethodV1 } from "./types";

export class MemoryTrustResolver implements TrustResolver {
  private readonly identities = new Map<TrustID, IdentityDocumentV1>();

  constructor(identities: IdentityDocumentV1[] = []) {
    for (const identity of identities) {
      this.upsertIdentity(identity);
    }
  }

  upsertIdentity(identity: IdentityDocumentV1): void {
    this.identities.set(identity.id, structuredClone(identity));
  }

  resolveTrustID(trustId: TrustID): IdentityDocumentV1 | null {
    const identity = this.identities.get(trustId);
    return identity ? structuredClone(identity) : null;
  }

  revokeKey(trustId: TrustID, keyId: string): void {
    const identity = this.identities.get(trustId);
    if (!identity) return;
    const key = identity.verification_methods.find((method) => method.id === keyId);
    if (key) {
      key.status = "revoked";
    }
  }
}

export function findVerificationMethod(identity: IdentityDocumentV1, keyId: string): VerificationMethodV1 | null {
  return identity.verification_methods.find((method) => method.id === keyId) ?? null;
}

export function keyActiveAt(key: VerificationMethodV1 | null, timestamp: RFC3339): boolean {
  if (!key) return false;
  if (key.status !== "active") return false;

  const at = Date.parse(timestamp);
  const created = Date.parse(key.created_at);
  if (!Number.isFinite(at) || !Number.isFinite(created)) return false;
  if (created > at) return false;

  if (key.expires_at) {
    const expires = Date.parse(key.expires_at);
    if (!Number.isFinite(expires) || at >= expires) return false;
  }

  return true;
}

export function notRevokedAt(key: VerificationMethodV1 | null): boolean {
  return key?.status !== "revoked";
}
