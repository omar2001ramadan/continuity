import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from "node:crypto";
import {
  signMessageEvent,
  buildIdentityFromSeed,
  buildInclusionProof,
  ZERO_HASH,
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
      raw_content_included: true,
      exact_counterparties_included: false,
      metadata_fields_redacted: ["platform", "ip_address", "user_agent"]
    },
    message_disclosure: {
      raw_message: input.message,
      content_salt: signed.content_salt
    }
  };
  return { ...bundle, proof_link: encodeProofLink(bundle) };
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
