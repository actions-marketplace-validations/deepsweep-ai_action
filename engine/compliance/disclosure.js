/**
 * Selective disclosure (TEAM-ADR-038) — how content enters a packet WITHOUT
 * ever having entered the ledger.
 *
 * The ledger is metadata-first by contract: a `gateway.tool_call` entry
 * carries `argsHash`, `serverHash`, `toolHash`, `principalHash`; a
 * `gateway.tool_result` carries `resultHash`. A 72-hour GDPR or 15-day AI Act
 * report nevertheless needs SOME content (what data actually moved). The
 * resolution: the customer attaches content from its OWN vault; the compiler
 * re-hashes it exactly as the gateway did and cites only what reproduces the
 * recorded digest. A disclosure that does not reproduce is REFUSED and listed
 * as such — never silently dropped, never cited.
 *
 * Hashing must match the gateway byte-for-byte: strings (server, tool,
 * principal) → sha256Hex(string); JSON values (args, result) →
 * sha256Hex(canonicalize(value)). Pure; zero dependencies.
 */
import { canonicalize, sha256Hex } from "../review/canonical.js";
const FIELDS = new Set(["server", "tool", "principal", "args", "result"]);
/** The digest the gateway would have recorded for this field and value. */
export function disclosureHash(field, value) {
    if (field === "args" || field === "result")
        return sha256Hex(canonicalize(value));
    return typeof value === "string" ? sha256Hex(value) : undefined;
}
export function verifyDisclosures(entries, disclosures) {
    const byHash = new Map();
    for (const e of entries)
        byHash.set(e.entryHash, e);
    const verified = [];
    const refused = [];
    for (const raw of disclosures) {
        if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
            refused.push({ entryHash: "", field: "", verdict: "malformed" });
            continue;
        }
        const d = raw;
        const entryHash = typeof d["entryHash"] === "string" ? d["entryHash"] : "";
        const field = typeof d["field"] === "string" ? d["field"] : "";
        if (entryHash === "" || !FIELDS.has(field) || !("value" in d)) {
            refused.push({ entryHash, field, verdict: "malformed" });
            continue;
        }
        const entry = byHash.get(entryHash);
        if (entry === undefined) {
            refused.push({ entryHash, field, verdict: "unknown-entry" });
            continue;
        }
        const recorded = entry.payload[`${field}Hash`];
        if (typeof recorded !== "string") {
            refused.push({ entryHash, field, verdict: "field-not-recorded" });
            continue;
        }
        const actual = disclosureHash(field, d["value"]);
        if (actual !== recorded) {
            refused.push({ entryHash, field, verdict: "mismatch" });
            continue;
        }
        verified.push({ entryHash, field: field, value: d["value"], recordedHash: recorded });
    }
    return { verified, refused };
}
