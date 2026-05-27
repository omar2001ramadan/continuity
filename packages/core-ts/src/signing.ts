import { readFileSync } from "node:fs";
import { signEd25519 } from "./crypto";
import type { Hex32, HexSig } from "./types";

export interface SigningAdapter {
  readonly key_uri: string;
  sign(message: Hex32 | Uint8Array): Promise<HexSig>;
}

export class EnvSigningAdapter implements SigningAdapter {
  readonly key_uri: string;

  constructor(readonly envVar: string) {
    this.key_uri = `env:${envVar}`;
  }

  async sign(message: Hex32 | Uint8Array): Promise<HexSig> {
    const seed = process.env[this.envVar];
    if (!seed) throw new Error(`Missing signing seed env var ${this.envVar}`);
    return signEd25519(message, seed);
  }
}

export class FileSigningAdapter implements SigningAdapter {
  readonly key_uri: string;

  constructor(readonly path: string) {
    this.key_uri = `file:${path}`;
  }

  async sign(message: Hex32 | Uint8Array): Promise<HexSig> {
    return signEd25519(message, readFileSync(this.path, "utf8").trim());
  }
}

export interface KmsSigningAdapter extends SigningAdapter {
  readonly provider: "aws-kms" | "gcp-kms" | "azure-keyvault" | "hsm";
  readonly key_id: string;
}

export class FailClosedKmsSigningAdapter implements KmsSigningAdapter {
  readonly provider: "aws-kms" | "gcp-kms" | "azure-keyvault";
  readonly key_id: string;

  constructor(readonly key_uri: string) {
    const [, provider = "aws-kms", keyId = ""] = key_uri.split(":", 3);
    this.provider = provider === "gcp-kms" || provider === "azure-keyvault" ? provider : "aws-kms";
    this.key_id = keyId;
  }

  async sign(): Promise<HexSig> {
    throw new Error(`TSL_SIGNING_ADAPTER_UNAVAILABLE: ${this.key_uri} is configured but no production KMS implementation is installed`);
  }
}

export class FailClosedHsmSigningAdapter implements KmsSigningAdapter {
  readonly provider = "hsm" as const;
  readonly key_id: string;

  constructor(readonly key_uri: string) {
    this.key_id = key_uri.slice("hsm:".length);
  }

  async sign(): Promise<HexSig> {
    throw new Error(`TSL_SIGNING_ADAPTER_UNAVAILABLE: ${this.key_uri} is configured but no HSM implementation is installed`);
  }
}

export function createSigningAdapter(uri: string): SigningAdapter {
  if (uri.startsWith("env:")) return new EnvSigningAdapter(uri.slice("env:".length));
  if (uri.startsWith("file:")) return new FileSigningAdapter(uri.slice("file:".length));
  if (uri.startsWith("kms:")) return new FailClosedKmsSigningAdapter(uri);
  if (uri.startsWith("hsm:")) return new FailClosedHsmSigningAdapter(uri);
  throw new Error(`Unsupported signing adapter URI: ${uri}`);
}

export function createDevSigningAdapter(uri: string): SigningAdapter {
  return createSigningAdapter(uri);
}
