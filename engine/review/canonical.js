/**
 * RFC 8785 (JCS)-style canonicalization + SHA-256 hashing for the pinned
 * baseline identity (ADR-003). Pure, deterministic, zero dependencies.
 *
 * Contract (ADR-003 "Hashing and canonicalization"):
 *  - Object keys sorted by UTF-16 code unit (default Array.prototype.sort).
 *  - No insignificant whitespace; numbers in shortest round-trip form and
 *    strings with minimal JSON escaping (both via JSON.stringify, which
 *    matches JCS serialization for ECMAScript values).
 *  - String VALUES are byte-preserved: no Unicode normalization, no
 *    whitespace collapsing, no escape folding beyond JSON's mandatory
 *    escapes. Two descriptions differing in ANY code point (zero-width,
 *    bidi, CRLF…) hash differently — that is drift, not noise.
 *  - Canonicalization operates only on JSON structure, never on string
 *    content.
 */
import { createHash } from "node:crypto";
export function sha256Hex(text) {
    return createHash("sha256").update(text, "utf8").digest("hex");
}
/** The canonical text is handed to the hash in pieces of about this many UTF-16 code units. */
const CANONICAL_FLUSH_UNITS = 65536;
function put(sink, piece) {
    sink.pending += piece;
    if (sink.pending.length >= CANONICAL_FLUSH_UNITS) {
        sink.hash.update(sink.pending, "utf8");
        sink.pending = "";
    }
}
/**
 * Write one value: a scalar whole, or the opening of a container whose
 * members writeCanonical then walks. Throws what canonicalize() throws.
 */
function openValue(value, sink, open) {
    if (value === null) {
        put(sink, "null");
        return;
    }
    switch (typeof value) {
        case "boolean":
            put(sink, value ? "true" : "false");
            return;
        case "number":
            if (!Number.isFinite(value)) {
                throw new TypeError("Cannot canonicalize non-finite number");
            }
            put(sink, JSON.stringify(value));
            return;
        case "string":
            put(sink, JSON.stringify(value));
            return;
        case "object":
            if (Array.isArray(value)) {
                put(sink, "[");
                open.push({ kind: "array", items: value, next: 0 });
                return;
            }
            put(sink, "{");
            open.push({ kind: "object", rec: value, keys: Object.keys(value).sort(), next: 0, first: true });
            return;
        default:
            throw new TypeError(`Cannot canonicalize value of type ${typeof value}`);
    }
}
/**
 * canonicalize(), written piece by piece, with an explicit stack of open
 * containers instead of recursion (TEAM-ADR-069 fix pass 9, R9-3): no
 * nesting depth can overflow the call stack. Members are visited in
 * canonicalize()'s order, so the text is the same and so is the first throw;
 * where canonicalize() itself overflows its stack, this still writes the text
 * canonicalize() would have built. Every piece is a whole token, so no
 * surrogate pair is ever split between two updates.
 */
function writeCanonical(root, sink) {
    const open = [];
    openValue(root, sink, open);
    while (open.length > 0) {
        const top = open[open.length - 1];
        if (top.kind === "array") {
            if (top.next >= top.items.length) {
                put(sink, "]");
                open.pop();
                continue;
            }
            const i = top.next;
            top.next += 1;
            if (i > 0)
                put(sink, ",");
            // A hole writes nothing, as Array.prototype.map and join do in canonicalize().
            if (!(i in top.items))
                continue;
            const v = top.items[i];
            openValue(v === undefined ? null : v, sink, open);
            continue;
        }
        // The next member whose value is defined, as canonicalize() skips undefined ones.
        let member;
        while (member === undefined && top.next < top.keys.length) {
            const key = top.keys[top.next];
            top.next += 1;
            const v = top.rec[key];
            if (v !== undefined)
                member = { key, value: v };
        }
        if (member === undefined) {
            put(sink, "}");
            open.pop();
            continue;
        }
        if (!top.first)
            put(sink, ",");
        top.first = false;
        put(sink, `${JSON.stringify(member.key)}:`);
        openValue(member.value, sink, open);
    }
}
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
export function sha256Canonical(value) {
    const sink = { hash: createHash("sha256"), pending: "" };
    writeCanonical(value, sink);
    sink.hash.update(sink.pending, "utf8");
    return sink.hash.digest("hex");
}
/**
 * Canonicalize a parsed-JSON value into a deterministic string.
 * Throws on values that cannot appear in parsed JSON (functions, symbols,
 * non-finite numbers) — callers only pass values from JSON.parse.
 */
export function canonicalize(value) {
    if (value === null)
        return "null";
    switch (typeof value) {
        case "boolean":
            return value ? "true" : "false";
        case "number":
            if (!Number.isFinite(value)) {
                throw new TypeError("Cannot canonicalize non-finite number");
            }
            return JSON.stringify(value);
        case "string":
            return JSON.stringify(value);
        case "object": {
            if (Array.isArray(value)) {
                return `[${value.map((v) => canonicalize(v === undefined ? null : v)).join(",")}]`;
            }
            const rec = value;
            const parts = [];
            for (const key of Object.keys(rec).sort()) {
                const v = rec[key];
                if (v === undefined)
                    continue;
                parts.push(`${JSON.stringify(key)}:${canonicalize(v)}`);
            }
            return `{${parts.join(",")}}`;
        }
        default:
            throw new TypeError(`Cannot canonicalize value of type ${typeof value}`);
    }
}
/** Max duplicate key names reported per document (bounds attacker fan-out). */
export const MAX_DUPLICATE_KEYS = 10;
/**
 * Detect duplicate keys within a single JSON object (ADR-003: parsing is
 * deterministic last-wins, but duplicates are a review finding). Operates on
 * raw text with string/escape/JSONC-comment awareness; keys are compared in
 * their raw escaped form (an escape-variant duplicate simply goes unflagged —
 * parsing behavior is unaffected). Returns duplicate key names, bounded.
 */
export function findDuplicateJsonKeys(text, max = MAX_DUPLICATE_KEYS) {
    const dups = [];
    /** Stack of open containers: a Set of seen keys for objects, null for arrays. */
    const stack = [];
    const n = text.length;
    let i = 0;
    while (i < n && dups.length < max) {
        const ch = text[i];
        if (ch === '"') {
            let j = i + 1;
            let escaped = false;
            let raw = "";
            while (j < n) {
                const c = text[j];
                if (escaped) {
                    raw += `\\${c}`;
                    escaped = false;
                    j++;
                    continue;
                }
                if (c === "\\") {
                    escaped = true;
                    j++;
                    continue;
                }
                if (c === '"')
                    break;
                raw += c;
                j++;
            }
            i = j + 1;
            // Look ahead (skipping whitespace/comments) for ':' → this string is a key.
            let k = i;
            while (k < n) {
                const c = text[k];
                if (c === " " || c === "\t" || c === "\n" || c === "\r") {
                    k++;
                    continue;
                }
                if (c === "/" && text[k + 1] === "/") {
                    while (k < n && text[k] !== "\n")
                        k++;
                    continue;
                }
                if (c === "/" && text[k + 1] === "*") {
                    k += 2;
                    while (k < n && !(text[k] === "*" && text[k + 1] === "/"))
                        k++;
                    k += 2;
                    continue;
                }
                break;
            }
            if (text[k] === ":") {
                const top = stack[stack.length - 1];
                if (top instanceof Set) {
                    if (top.has(raw)) {
                        if (!dups.includes(raw))
                            dups.push(raw);
                    }
                    else {
                        top.add(raw);
                    }
                }
            }
            continue;
        }
        if (ch === "/" && text[i + 1] === "/") {
            while (i < n && text[i] !== "\n")
                i++;
            continue;
        }
        if (ch === "/" && text[i + 1] === "*") {
            i += 2;
            while (i < n && !(text[i] === "*" && text[i + 1] === "/"))
                i++;
            i += 2;
            continue;
        }
        if (ch === "{") {
            stack.push(new Set());
            i++;
            continue;
        }
        if (ch === "[") {
            stack.push(null);
            i++;
            continue;
        }
        if (ch === "}" || ch === "]") {
            stack.pop();
            i++;
            continue;
        }
        i++;
    }
    return dups;
}
