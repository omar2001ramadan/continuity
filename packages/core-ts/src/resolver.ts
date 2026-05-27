import type { PostgresRepository } from "./persistence/postgres";
import type { IdentityDocumentV1, RFC3339, TrustID, TrustResolver } from "./types";

export class PostgresTrustResolver implements TrustResolver {
  constructor(private readonly repo: PostgresRepository) {}

  async resolveTrustID(trustId: TrustID, _atTime?: RFC3339): Promise<IdentityDocumentV1 | null> {
    return this.repo.getIdentity(trustId);
  }
}

export class CompositeTrustResolver implements TrustResolver {
  constructor(private readonly resolvers: TrustResolver[]) {}

  async resolveTrustID(trustId: TrustID, atTime?: RFC3339): Promise<IdentityDocumentV1 | null> {
    for (const resolver of this.resolvers) {
      const identity = await resolver.resolveTrustID(trustId, atTime);
      if (identity) return identity;
    }
    return null;
  }
}
