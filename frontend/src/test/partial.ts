/**
 * Cast a partial fixture to a full generated response type.
 *
 * The scan API types are generated from the backend's OpenAPI schema, so a test
 * fixture that spells out only the fields under test no longer type-checks
 * against them. Spelling out every field would assert nothing extra and would
 * hide which fields the test is actually about, so the cast is explicit, named,
 * and confined to test code.
 */
export function partial<T>(value: unknown): T {
  return value as T;
}
