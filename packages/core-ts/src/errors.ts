import errorCodeRegistry from "../../../specs/error-codes.v1.json";

export interface TslErrorCodeEntry {
  code: string;
  class: string;
  retryable: boolean;
}

export const TSL_ERROR_CODE_REGISTRY = errorCodeRegistry.codes as TslErrorCodeEntry[];
export const TSL_ERROR_CODES = new Set(TSL_ERROR_CODE_REGISTRY.map((entry) => entry.code));

export function isTslErrorCode(code: string): boolean {
  return TSL_ERROR_CODES.has(code);
}
