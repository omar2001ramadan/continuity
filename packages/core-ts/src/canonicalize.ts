function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object") return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function encodeCanonical(value: unknown): string {
  if (value === null) return "null";

  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";

  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new Error("TSL canonicalization only allows safe integers in signed core objects");
    }
    if (Object.is(value, -0)) {
      throw new Error("TSL canonicalization rejects negative zero");
    }
    return String(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => encodeCanonical(item)).join(",")}]`;
  }

  if (isPlainObject(value)) {
    const keys = Object.keys(value).sort();
    const fields = keys.map((key) => {
      const child = value[key];
      if (child === undefined) {
        throw new Error(`TSL canonicalization rejects undefined field: ${key}`);
      }
      return `${JSON.stringify(key)}:${encodeCanonical(child)}`;
    });
    return `{${fields.join(",")}}`;
  }

  throw new Error(`Unsupported value in TSL canonicalization: ${typeof value}`);
}

export function canonicalize(value: unknown): string {
  return encodeCanonical(value);
}

export function canonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}

export function withoutField<T extends Record<string, unknown>>(value: T, field: string): Record<string, unknown> {
  const copy: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value)) {
    if (key !== field && child !== undefined) {
      copy[key] = child;
    }
  }
  return copy;
}

export function withoutSignature<T extends Record<string, unknown>>(value: T): Record<string, unknown> {
  return withoutField(value, "signature");
}
