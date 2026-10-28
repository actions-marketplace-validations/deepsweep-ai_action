export declare function sha256Hex(text: string): string;
/**
 * sha256Hex(canonicalize(value)), without building the canonical string
 * (TEAM-ADR-069 fix pass 8): the canonical text goes to the hash in pieces of
 * about 64 Ki code units, so memory no longer grows with the number of values
 * (a 2.8-million-value result made millions of temporary strings). The same
 * digest and the same throws as the two-step form for every input the
 * two-step form can hash; nested past the depth where canonicalize()
 * overflows its stack, it still returns the digest of the text canonicalize()
 * would have built (fix pass 9). The value must be acyclic, as JSON.parse
 * output always is: on a cycle the walk grows until the heap runs out, where
 * the recursive forms threw a RangeError (fix pass 10).
 */
export declare function sha256Canonical(value: unknown): string;
/**
 * Canonicalize a parsed-JSON value into a deterministic string.
 * Throws on values that cannot appear in parsed JSON (functions, symbols,
 * non-finite numbers) — callers only pass values from JSON.parse.
 */
export declare function canonicalize(value: unknown): string;
/** Max duplicate key names reported per document (bounds attacker fan-out). */
export declare const MAX_DUPLICATE_KEYS = 10;
/**
 * Detect duplicate keys within a single JSON object (ADR-003: parsing is
 * deterministic last-wins, but duplicates are a review finding). Operates on
 * raw text with string/escape/JSONC-comment awareness; keys are compared in
 * their raw escaped form (an escape-variant duplicate simply goes unflagged —
 * parsing behavior is unaffected). Returns duplicate key names, bounded.
 */
export declare function findDuplicateJsonKeys(text: string, max?: number): string[];
