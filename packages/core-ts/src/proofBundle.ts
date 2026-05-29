import type {
  AttestationV1,
  DisclosureConsentV1,
  ProofBundleV1,
  TrustID
} from "./types";

export interface ProofBundleDisclosureOptions {
  disclosure_consents?: DisclosureConsentV1[];
  include_receipts?: boolean;
  include_attestations?: boolean;
  verifier_or_provider?: TrustID;
  purpose?: string;
  at_time_ms?: number;
  revoked_disclosure_pointers?: string[];
}

function consentAllows(input: {
  consents?: DisclosureConsentV1[];
  subject: TrustID;
  field_classes: string[];
  verifier_or_provider?: TrustID;
  purpose?: string;
  at_time_ms?: number;
  revoked_disclosure_pointers?: string[];
}): boolean {
  const at = input.at_time_ms ?? Date.now();
  for (const consent of input.consents ?? []) {
    if (consent.subject !== input.subject) continue;
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
    verifier_or_provider: options.verifier_or_provider,
    purpose: options.purpose,
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
    Boolean(bundle.message_disclosure?.raw_message || bundle.message_disclosure?.content_salt) &&
    proofBundleAllowsFieldClass(subject, ["raw_content", "content_salt"], options);

  const receipts = canDiscloseCounterparties ? bundle.receipts : undefined;
  const attestations = filterAttestations(bundle.attestations, canDiscloseRestrictedAttestations);
  const metadataFieldsRedacted = new Set<string>();
  if (!canDiscloseRawContent) {
    metadataFieldsRedacted.add("raw_content");
    metadataFieldsRedacted.add("content_salt");
  }
  if (!canDiscloseCounterparties) metadataFieldsRedacted.add("exact_counterparties");
  if (!canDiscloseRestrictedAttestations && (bundle.attestations ?? []).some((attestation) => attestation.visibility !== "public")) {
    metadataFieldsRedacted.add("restricted_attestations");
  }
  for (const field of ["platform", "ip_address", "user_agent"]) metadataFieldsRedacted.add(field);

  const redacted: ProofBundleV1 = {
    ...bundle,
    ...(receipts ? { receipts } : { receipts: undefined }),
    ...(attestations.length ? { attestations } : { attestations: undefined }),
    ...(canDiscloseRawContent ? {} : { message_disclosure: undefined }),
    redaction_manifest: {
      raw_content_included: canDiscloseRawContent,
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
  const hasRawContent = Boolean(bundle.message_disclosure?.raw_message || bundle.message_disclosure?.content_salt);
  return (
    (hasReceipts && !proofBundleAllowsFieldClass(subject, ["exact_counterparties"], options)) ||
    (hasRestrictedAttestations && !proofBundleAllowsFieldClass(subject, ["attestations"], options)) ||
    (hasRawContent && !proofBundleAllowsFieldClass(subject, ["raw_content", "content_salt"], options))
  );
}
