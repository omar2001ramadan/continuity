import Ajv, { type ErrorObject } from "ajv";
import addFormats from "ajv-formats";
import { schemas, type SchemaName } from "./schemas";

const ajv = new Ajv({
  allErrors: true,
  strict: false
});
addFormats(ajv);

const validators = Object.fromEntries(
  Object.entries(schemas).map(([name, schema]) => [name, ajv.compile(schema)])
) as Record<SchemaName, ReturnType<Ajv["compile"]>>;

export interface SchemaValidationResult {
  valid: boolean;
  errors: string[];
  rawErrors?: ErrorObject[];
}

export function validateSchema(name: SchemaName, value: unknown): SchemaValidationResult {
  const validate = validators[name];
  const validationResult = validate(value);
  if (validationResult instanceof Promise) {
    throw new Error("TSL schemas must be synchronous validators");
  }
  const valid = validationResult === true;
  return {
    valid,
    errors: valid
      ? []
      : (validate.errors ?? []).map((error) => {
          const path = error.instancePath || "/";
          return `${path} ${error.message ?? "failed validation"}`;
        }),
    rawErrors: validate.errors ?? undefined
  };
}
