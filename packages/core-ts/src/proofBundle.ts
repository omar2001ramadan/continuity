import type {
  AttestationV1,
  DisclosureConsentV1,
  IdentityDocumentV1,
  ProofBundleV1,
  TrustID
} from "./types";
import { keyActiveAt, notRevokedAt } from "./identity";
import { verifyEd25519 } from "./crypto";
import { validateSchema } from "./validation";
import { disclosureConsentV1Hash } from "./v2";

export interface ProofBundleDisclosureOptions {
  disclosure_consents?: DisclosureConsentV1[];
  consent_identities?: IdentityDocumentV1[];
  resolve_identity?: (trustId: TrustID, atTime?: string) => IdentityDocumentV1 | null | undefined;
  include_receipts?: boolean;
  include_attestations?: boolean;
  verifier_or_provider?: TrustID;
  purpose?: string;
  disclosure_purpose?: string;
  at_time_ms?: number;
  revoked_disclosure_pointers?: string[];
}

function resolveConsentIdentity(subject: TrustID, options: ProofBundleDisclosureOptions, atTime?: string): IdentityDocumentV1 | null {
  return options.resolve_identity?.(subject, atTime) ?? options.consent_identities?.find((identity) => identity.id === subject) ?? null;
}

function consentSignatureValid(consent: DisclosureConsentV1, options: ProofBundleDisclosureOptions): boolean {
  const validation = validateSchema("disclosureConsentV1", consent);
  if (!validation.valid) return false;
  const identity = resolveConsentIdentity(consent.subject, options, consent.issued_at);
  const key = identity?.verification_methods.find((method) => method.type === "ed25519" && keyActiveAt(method, consent.issued_at) && notRevokedAt(method, consent.issued_at));
  return Boolean(key && verifyEd25519(key.public_key, disclosureConsentV1Hash(consent), consent.signature));
}

function consentAllows(input: {
  consents?: DisclosureConsentV1[];
  subject: TrustID;
  field_classes: string[];
  options: ProofBundleDisclosureOptions;
  verifier_or_provider?: TrustID;
  purpose?: string;
  at_time_ms?: number;
  revoked_disclosure_pointers?: string[];
}): boolean {
  const at = input.at_time_ms ?? Date.now();
  if (!input.verifier_or_provider || !input.purpose) return false;
  for (const consent of input.consents ?? []) {
    if (consent.subject !== input.subject) continue;
    if (!consentSignatureValid(consent, input.options)) continue;
    if (input.verifier_or_provider && consent.verifier_or_provider !== input.verifier_or_provider) continue;
    if (input.purpose && consent.purpose !== input.purpose) continue;
    if (Date.parse(consent.issued_at) > at || Date.parse(consent.expires_at) <= at) continue;
    if (input.revoked_disclosure_pointers?.includes(consent.revocation_pointer)) continue;
    const allowed = new Set(consent.allowed_field_classes);
    const forbidden = new Set(consent.forbidden_field_classes);
    if (input.field_classes.every((field) => allowed.has(field) && !forbidden.has(field))) return true;
  }
  return false;
}

export function proofBundleAllowsFieldClass(
  subject: TrustID,
  fieldClasses: string[],
  options: ProofBundleDisclosureOptions = {}
): boolean {
  return consentAllows({
    consents: options.disclosure_consents,
    subject,
    field_classes: fieldClasses,
    options,
    verifier_or_provider: options.verifier_or_provider,
    purpose: options.purpose ?? options.disclosure_purpose,
    at_time_ms: options.at_time_ms,
    revoked_disclosure_pointers: options.revoked_disclosure_pointers
  });
}

export function filterProofBundleDisclosures(
  bundle: ProofBundleV1,
  options: ProofBundleDisclosureOptions = {}
): ProofBundleV1 {
  const subject = bundle.envelope.sender;
  const canDiscloseCounterparties =
    options.include_receipts === true &&
    proofBundleAllowsFieldClass(subject, ["exact_counterparties"], options);
  const canDiscloseRestrictedAttestations =
    options.include_attestations === true &&
    proofBundleAllowsFieldClass(subject, ["attestations"], options);
  const canDiscloseRawContent =
    Boolean(bundle.message_disclosure?.raw_message) &&
    proofBundleAllowsFieldClass(subject, ["raw_content"], options);
  const canDiscloseContentSalt =
    Boolean(bundle.message_disclosure?.content_salt) &&
    proofBundleAllowsFieldClass(subject, ["content_salt"], options);
  const canDisclosePrivateGraph =
    !bundle.graph_feature_vector ||
    bundle.graph_feature_vector.privacy_disclosure_level === "aggregate_only" ||
    bundle.graph_feature_vector.privacy_disclosure_level === "public" ||
    proofBundleAllowsFieldClass(subject, ["private_graph"], options);
  const canDisclosePrivateMetadata =
    !bundle.metadata_fingerprints?.some((fingerprint) => fingerprint.scope_class !== "public_commitment") ||
    proofBundleAllowsFieldClass(subject, ["private_metadata"], options);

  const receipts = canDiscloseCounterparties ? bundle.receipts : undefined;
  const attestations = filterAttestations(bundle.attestations, canDiscloseRestrictedAttestations);
  const graphFeatureVector = canDisclosePrivateGraph ? bundle.graph_feature_vector : undefined;
  const metadataFingerprints = canDisclosePrivateMetadata ? bundle.metadata_fingerprints : undefined;
  const metadataFieldsRedacted = new Set<string>();
  if (!canDiscloseRawContent) metadataFieldsRedacted.add("raw_content");
  if (!canDiscloseContentSalt) metadataFieldsRedacted.add("content_salt");
  if (!canDiscloseCounterparties) metadataFieldsRedacted.add("exact_counterparties");
  if (!canDiscloseRestrictedAttestations && (bundle.attestations ?? []).some((attestation) => attestation.visibility !== "public")) {
    metadataFieldsRedacted.add("restricted_attestations");
  }
  if (!canDisclosePrivateGraph && bundle.graph_feature_vector) metadataFieldsRedacted.add("private_graph");
  if (!canDisclosePrivateMetadata && bundle.metadata_fingerprints?.length) metadataFieldsRedacted.add("private_metadata");
  for (const field of ["platform", "ip_address", "user_agent"]) metadataFieldsRedacted.add(field);

  const message_disclosure =
    canDiscloseRawContent || canDiscloseContentSalt
      ? {
          ...(canDiscloseRawContent ? { raw_message: bundle.message_disclosure?.raw_message } : {}),
          ...(canDiscloseContentSalt ? { content_salt: bundle.message_disclosure?.content_salt } : {})
        }
      : undefined;
  const redacted: ProofBundleV1 = {
    ...bundle,
    ...(receipts ? { receipts } : { receipts: undefined }),
    ...(attestations.length ? { attestations } : { attestations: undefined }),
    ...(metadataFingerprints ? { metadata_fingerprints: metadataFingerprints } : { metadata_fingerprints: undefined }),
    ...(graphFeatureVector ? { graph_feature_vector: graphFeatureVector } : { graph_feature_vector: undefined }),
    ...(message_disclosure ? { message_disclosure } : { message_disclosure: undefined }),
    redaction_manifest: {
      raw_content_included: canDiscloseRawContent,
      content_salt_included: canDiscloseContentSalt,
      exact_counterparties_included: Boolean(receipts?.length),
      metadata_fields_redacted: [...metadataFieldsRedacted].sort()
    }
  };
  return stripUndefinedProofBundle(redacted);
}

function filterAttestations(attestations: AttestationV1[] | undefined, includeRestricted: boolean): AttestationV1[] {
  return (attestations ?? []).filter((attestation) => attestation.visibility === "public" || includeRestricted);
}

function stripUndefinedProofBundle(bundle: ProofBundleV1): ProofBundleV1 {
  return Object.fromEntries(Object.entries(bundle).filter(([, value]) => value !== undefined)) as ProofBundleV1;
}

export function proofBundleHasPrivateDisclosureWithoutConsent(bundle: ProofBundleV1, options: ProofBundleDisclosureOptions = {}): boolean {
  const subject = bundle.envelope.sender;
  const hasReceipts = Boolean(bundle.receipts?.length);
  const hasRestrictedAttestations = Boolean(bundle.attestations?.some((attestation) => attestation.visibility !== "public"));
  const hasRawContent = Boolean(bundle.message_disclosure?.raw_message);
  const hasContentSalt = Boolean(bundle.message_disclosure?.content_salt);
  const hasPrivateGraph = Boolean(bundle.graph_feature_vector && !["aggregate_only", "public"].includes(bundle.graph_feature_vector.privacy_disclosure_level));
  const hasPrivateMetadata = Boolean(bundle.metadata_fingerprints?.some((fingerprint) => fingerprint.scope_class !== "public_commitment"));
  return (
    (hasReceipts && !proofBundleAllowsFieldClass(subject, ["exact_counterparties"], options)) ||
    (hasRestrictedAttestations && !proofBundleAllowsFieldClass(subject, ["attestations"], options)) ||
    (hasRawContent && !proofBundleAllowsFieldClass(subject, ["raw_content"], options)) ||
    (hasContentSalt && !proofBundleAllowsFieldClass(subject, ["content_salt"], options)) ||
    (hasPrivateGraph && !proofBundleAllowsFieldClass(subject, ["private_graph"], options)) ||
    (hasPrivateMetadata && !proofBundleAllowsFieldClass(subject, ["private_metadata"], options))
  );
}
