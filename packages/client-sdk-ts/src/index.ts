import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from "node:crypto";
import {
  signMessageEvent,
  buildIdentityFromSeed,
  buildInclusionProof,
	  ZERO_HASH,
	  type DisclosureConsentV1,
	  type ProofBundleV1
	} from "../../core-ts/src/index";

export function encodeProofLink(bundle: ProofBundleV1, baseUrl = "http://localhost:8090/p/"): string {
  const payload = Buffer.from(JSON.stringify(bundle), "utf8").toString("base64url");
  return `${baseUrl}${payload}`;
}

export function decodeProofLink(urlOrPayload: string): ProofBundleV1 {
  const payload = urlOrPayload.includes("/p/") ? urlOrPayload.slice(urlOrPayload.lastIndexOf("/p/") + 3) : urlOrPayload;
  return JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as ProofBundleV1;
}

export function createSignedMessageProof(input: {
  trust_id: string;
  key_id: string;
  seed_hex: string;
  message: string;
  include_message_disclosure?: boolean;
  disclosure_consent?: DisclosureConsentV1;
}): ProofBundleV1 & { proof_link: string } {
  const identity = buildIdentityFromSeed({ trust_id: input.trust_id, key_id: input.key_id, seed_hex: input.seed_hex });
  const signed = signMessageEvent({
    sender: input.trust_id,
    signing_key_id: input.key_id,
    seed_hex: input.seed_hex,
    message: input.message
  });
  const epochDurationMs = 300000;
  const epochStartMs = Math.floor(Date.parse(signed.envelope.timestamp) / epochDurationMs) * epochDurationMs;
  const proof = buildInclusionProof({
    commitments: [signed.commitment_hash],
    leaf_index: 0,
    tree_kind: "event",
    epoch_start_ms: epochStartMs,
    epoch_duration_ms: epochDurationMs,
    shard: "local"
  });
  const mayDiscloseMessage =
    input.include_message_disclosure === true &&
    disclosureConsentAllows({
      consent: input.disclosure_consent,
      subject: input.trust_id,
      field_classes: ["raw_content", "content_salt"]
    });
  const bundle: ProofBundleV1 = {
    type: "tsl.proof_bundle.v1",
    bundle_id: signed.commitment_hash,
    created_at: signed.envelope.timestamp,
    identity,
    envelope: signed.envelope,
    proof,
    checkpoint: {
      type: "tsl.batch_checkpoint.v1",
      epoch_start_ms: epochStartMs,
      epoch_duration_ms: epochDurationMs,
      shard: "local",
      event_root: proof.root,
      receipt_root: ZERO_HASH,
      attestation_root: ZERO_HASH,
      revocation_root: ZERO_HASH,
      event_count: 1,
      receipt_count: 0,
      previous_checkpoint: ZERO_HASH,
      relay_id: "did:tsl:relay:local",
      relay_signature: "0x00"
	    },
	    redaction_manifest: {
	      raw_content_included: mayDiscloseMessage,
	      exact_counterparties_included: false,
	      metadata_fields_redacted: mayDiscloseMessage ? ["platform", "ip_address", "user_agent"] : ["raw_content", "content_salt", "platform", "ip_address", "user_agent"]
	    },
	    local_disclosure_warnings: ["local_unsigned_fixture_checkpoint"],
		    ...(mayDiscloseMessage
		      ? {
		          disclosure_consents: input.disclosure_consent ? [input.disclosure_consent] : undefined,
		          message_disclosure: {
		            raw_message: input.message,
		            content_salt: signed.content_salt
	          }
	        }
	      : {})
	  };
  return { ...bundle, proof_link: encodeProofLink(bundle) };
}

export function disclosureConsentAllows(input: {
  consent?: DisclosureConsentV1 | null;
  subject: string;
  field_classes: string[];
  at_time_ms?: number;
  revoked?: boolean;
}): boolean {
  if (!input.consent || input.revoked === true) return false;
  const now = input.at_time_ms ?? Date.now();
  if (input.consent.subject !== input.subject) return false;
  if (Date.parse(input.consent.issued_at) > now || Date.parse(input.consent.expires_at) <= now) return false;
  const allowed = new Set(input.consent.allowed_field_classes);
  const forbidden = new Set(input.consent.forbidden_field_classes);
  return input.field_classes.every((field) => allowed.has(field) && !forbidden.has(field));
}

export class EncryptedLocalStore {
  private readonly key: Buffer;
  private readonly records = new Map<string, string>();

  constructor(passphrase: string, salt = "tsl-local-store-v1") {
    this.key = pbkdf2Sync(passphrase, salt, 100000, 32, "sha256");
  }

  set(key: string, value: unknown): void {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    this.records.set(key, Buffer.concat([iv, tag, ciphertext]).toString("base64url"));
  }

  get<T>(key: string): T | null {
    const encoded = this.records.get(key);
    if (!encoded) return null;
    const data = Buffer.from(encoded, "base64url");
    const iv = data.subarray(0, 12);
    const tag = data.subarray(12, 28);
    const ciphertext = data.subarray(28);
    const decipher = createDecipheriv("aes-256-gcm", this.key, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
    return JSON.parse(plaintext) as T;
  }
}

export interface BrowserLocalStore {
  set(key: string, value: unknown): Promise<void>;
  get<T>(key: string): Promise<T | null>;
}

export class NodeSqliteLocalStore {
  private constructor(
    private readonly db: any,
    private readonly crypto: EncryptedLocalStore
  ) {}

  static async open(filePath: string, passphrase: string): Promise<NodeSqliteLocalStore> {
    const dynamicImport = new Function("specifier", "return import(specifier)") as (specifier: string) => Promise<any>;
    const sqlite = await dynamicImport("node:sqlite");
    const db = new sqlite.DatabaseSync(filePath);
    db.exec(`
      CREATE TABLE IF NOT EXISTS local_private_events (
        local_event_id TEXT PRIMARY KEY,
        commitment_hash TEXT NOT NULL,
        raw_message_encrypted TEXT,
        private_metadata_encrypted TEXT,
        receiver_trust_id TEXT,
        content_salt_encrypted TEXT,
        metadata_salt_encrypted TEXT,
        receiver_salt_encrypted TEXT,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS local_settings (
        key TEXT PRIMARY KEY,
        value_encrypted TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS disclosure_consents (
        consent_key TEXT PRIMARY KEY,
        subject TEXT NOT NULL,
        verifier_or_provider TEXT NOT NULL,
        revocation_pointer TEXT NOT NULL,
        consent_encrypted TEXT NOT NULL,
        revoked_at INTEGER
      );
    `);
    return new NodeSqliteLocalStore(db, new EncryptedLocalStore(passphrase));
  }

  set(key: string, value: unknown): void {
    this.crypto.set(key, value);
    const encrypted = (this.crypto as unknown as { records: Map<string, string> }).records.get(key);
    this.db.prepare("INSERT OR REPLACE INTO local_settings(key, value_encrypted) VALUES (?, ?)").run(key, encrypted);
  }

  get<T>(key: string): T | null {
    const row = this.db.prepare("SELECT value_encrypted FROM local_settings WHERE key = ?").get(key);
    if (!row?.value_encrypted) return null;
    (this.crypto as unknown as { records: Map<string, string> }).records.set(key, row.value_encrypted);
    return this.crypto.get<T>(key);
  }

  storeDisclosureConsent(consent: DisclosureConsentV1): void {
    const key = `${consent.subject}:${consent.verifier_or_provider}:${consent.revocation_pointer}`;
    this.crypto.set(`disclosure_consent:${key}`, consent);
    const encrypted = (this.crypto as unknown as { records: Map<string, string> }).records.get(`disclosure_consent:${key}`);
    this.db
      .prepare(
        "INSERT OR REPLACE INTO disclosure_consents(consent_key, subject, verifier_or_provider, revocation_pointer, consent_encrypted, revoked_at) VALUES (?, ?, ?, ?, ?, COALESCE((SELECT revoked_at FROM disclosure_consents WHERE consent_key = ?), NULL))"
      )
      .run(key, consent.subject, consent.verifier_or_provider, consent.revocation_pointer, encrypted, key);
  }

  getDisclosureConsent(subject: string, verifierOrProvider: string, revocationPointer: string): DisclosureConsentV1 | null {
    const key = `${subject}:${verifierOrProvider}:${revocationPointer}`;
    const row = this.db.prepare("SELECT consent_encrypted FROM disclosure_consents WHERE consent_key = ?").get(key);
    if (!row?.consent_encrypted) return null;
    (this.crypto as unknown as { records: Map<string, string> }).records.set(`disclosure_consent:${key}`, row.consent_encrypted);
    return this.crypto.get<DisclosureConsentV1>(`disclosure_consent:${key}`);
  }

  revokeDisclosureConsent(subject: string, verifierOrProvider: string, revocationPointer: string, revokedAtMs = Date.now()): void {
    const key = `${subject}:${verifierOrProvider}:${revocationPointer}`;
    this.db.prepare("UPDATE disclosure_consents SET revoked_at = ? WHERE consent_key = ?").run(revokedAtMs, key);
  }

  isDisclosureConsentRevoked(subject: string, verifierOrProvider: string, revocationPointer: string): boolean {
    const key = `${subject}:${verifierOrProvider}:${revocationPointer}`;
    const row = this.db.prepare("SELECT revoked_at FROM disclosure_consents WHERE consent_key = ?").get(key);
    return row?.revoked_at !== null && row?.revoked_at !== undefined;
  }
}

export class IndexedDBLocalStore implements BrowserLocalStore {
  private readonly dbName: string;

  constructor(
    dbName = "tsl-local-store",
    private readonly passphrase: string
  ) {
    this.dbName = dbName;
  }

  async set(key: string, value: unknown): Promise<void> {
    const encrypted = await encryptBrowserJson(value, this.passphrase);
    const db = await openBrowserDb(this.dbName);
    await requestToPromise(db.transaction("settings", "readwrite").objectStore("settings").put(encrypted, key));
    db.close();
  }

  async get<T>(key: string): Promise<T | null> {
    const db = await openBrowserDb(this.dbName);
    const encrypted = await requestToPromise<string | undefined>(db.transaction("settings", "readonly").objectStore("settings").get(key));
    db.close();
    return encrypted ? (await decryptBrowserJson(encrypted, this.passphrase)) as T : null;
  }
}

async function openBrowserDb(dbName: string): Promise<any> {
  const indexedDB = (globalThis as any).indexedDB;
  if (!indexedDB) throw new Error("IndexedDB is not available in this runtime");
  const request = indexedDB.open(dbName, 1);
  request.onupgradeneeded = () => {
    request.result.createObjectStore("settings");
  };
  return requestToPromise(request);
}

function requestToPromise<T>(request: any): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result as T);
    request.onerror = () => reject(request.error);
  });
}

async function browserKey(passphrase: string, salt: Uint8Array): Promise<any> {
  const crypto = (globalThis as any).crypto;
  const baseKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptBrowserJson(value: unknown, passphrase: string): Promise<string> {
  const crypto = (globalThis as any).crypto;
  if (!crypto?.subtle) throw new Error("WebCrypto is not available in this runtime");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await browserKey(passphrase, salt);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify(value))));
  return JSON.stringify({
    salt: Buffer.from(salt).toString("base64url"),
    iv: Buffer.from(iv).toString("base64url"),
    ciphertext: Buffer.from(ciphertext).toString("base64url")
  });
}

async function decryptBrowserJson(encoded: string, passphrase: string): Promise<unknown> {
  const crypto = (globalThis as any).crypto;
  const payload = JSON.parse(encoded) as { salt: string; iv: string; ciphertext: string };
  const salt = Uint8Array.from(Buffer.from(payload.salt, "base64url"));
  const iv = Uint8Array.from(Buffer.from(payload.iv, "base64url"));
  const ciphertext = Uint8Array.from(Buffer.from(payload.ciphertext, "base64url"));
  const key = await browserKey(passphrase, salt);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return JSON.parse(new TextDecoder().decode(plaintext));
}
