export { verifyTSL } from "../../core-ts/src/verifier";

export { MemoryTrustResolver } from "../../core-ts/src/identity";
export { LocalEvmSettlementBackend } from "../../core-ts/src/settlement";
export { verifyInclusion } from "../../core-ts/src/merkle";
export { validateSchema } from "../../core-ts/src/validation";
export { canonicalize } from "../../core-ts/src/canonicalize";
export {
  eventHash,
  receiptHash,
  attestationHash,
  revocationHash,
  assessmentHash,
  commitmentHash,
  contentCommitment
} from "../../core-ts/src/crypto";

export type {
  VerifyTSLInput,
  VerificationResult,
  VerifierPolicy,
  TrustResolver,
  ProofBundleV1,
  InclusionProofV1,
  BatchCheckpointV1,
  IdentityDocumentV1
} from "../../core-ts/src/types";
