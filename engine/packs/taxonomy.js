/**
 * Rule-pack taxonomy (TEAM-ADR-041) — the closed, versioned class list a pack
 * classifies tools into.
 *
 * A taxonomy names WHAT A TOOL DOES BY CONSTRUCTION (a send tool sends; a
 * list tool reads in bulk). It never names what one call's ARGUMENTS say —
 * argument-level classification is not available in taxonomy v1 and is
 * recorded as a gap, not approximated. Classes are the vocabulary the pack's
 * rules are written against (`class/<id>`), so the engine's policy grammar is
 * untouched: a class is just a logical resource identifier (ADR-009).
 *
 * PREFIX-FREEDOM is a validated invariant, not a convention: narrowing rules
 * are compiled with a trailing wildcard (`class/<id>*`) so the lower-
 * confidence heuristic alias (`class/<id>#heuristic`) is caught by the same
 * rule; if one class id were a prefix of another, a rule for the shorter id
 * would silently govern the longer one. Validation refuses such a taxonomy.
 *
 * Strict validation, whole-document refusal, bounded reasons — the same
 * discipline as ADR-009: a pack is AUTHORED SECURITY INPUT, and a tolerated
 * typo is a vanished protection.
 */
import { sanitizeField } from "../review/sanitize.js";
export const TAXONOMY_SCHEMA_VERSION = 1;
/** The threat-pattern references a pack may cite (closed; §4 of the EXEC-1 spec). */
export const THREAT_REFS = ["P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9"];
/** Class ids are lower-case dot paths of at least two segments (`mail.send.external`). */
export const CLASS_ID_RE = /^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)+$/;
/** Pack / taxonomy / binding ids: lower-case, digits, hyphens; no dots (they name store files). */
export const PACK_ID_RE = /^[a-z][a-z0-9-]{1,40}$/;
export const MAX_TAXONOMY_REASONS = 20;
export function isPlainObject(v) {
    return typeof v === "object" && v !== null && !Array.isArray(v);
}
export function isThreatRef(v) {
    return typeof v === "string" && THREAT_REFS.includes(v);
}
const tok = (s) => sanitizeField(s);
/**
 * Strict, deterministic validation of a taxonomy document. Whole-document
 * refusal on any problem; reasons are bounded and sanitized.
 */
export function validateTaxonomy(parsed) {
    const reasons = [];
    const push = (r) => {
        if (reasons.length < MAX_TAXONOMY_REASONS)
            reasons.push(tok(r));
    };
    if (!isPlainObject(parsed))
        return { ok: false, reasons: ["taxonomy must be a JSON object"] };
    if (parsed["schemaVersion"] !== TAXONOMY_SCHEMA_VERSION) {
        push(`unknown taxonomy schemaVersion ${String(parsed["schemaVersion"])}; this runtime speaks ${TAXONOMY_SCHEMA_VERSION}`);
    }
    if (typeof parsed["taxonomyId"] !== "string" || !PACK_ID_RE.test(parsed["taxonomyId"])) {
        push("taxonomyId must match ^[a-z][a-z0-9-]{1,40}$");
    }
    if (typeof parsed["version"] !== "string" || parsed["version"].length === 0)
        push("version must be a non-empty string");
    if (parsed["note"] !== undefined && typeof parsed["note"] !== "string")
        push("note, when present, must be a string");
    for (const k of Object.keys(parsed)) {
        if (k !== "schemaVersion" && k !== "taxonomyId" && k !== "version" && k !== "note" && k !== "classes") {
            push(`unknown top-level field "${k}"`);
        }
    }
    const classes = parsed["classes"];
    if (!Array.isArray(classes) || classes.length === 0) {
        push("classes must be a non-empty array");
        return { ok: false, reasons };
    }
    const ids = [];
    classes.forEach((c, i) => {
        if (!isPlainObject(c)) {
            push(`class #${i} must be an object`);
            return;
        }
        const id = c["id"];
        const loc = typeof id === "string" && id.length > 0 ? `class "${id}"` : `class #${i}`;
        if (typeof id !== "string" || !CLASS_ID_RE.test(id))
            push(`${loc}: id must be a lower-case dot path of at least two segments`);
        else if (ids.includes(id))
            push(`${loc}: duplicate class id`);
        else
            ids.push(id);
        if (typeof c["summary"] !== "string" || c["summary"].length === 0)
            push(`${loc}: summary is required`);
        if (typeof c["external"] !== "boolean")
            push(`${loc}: external must be a boolean`);
        const refs = c["threatRefs"];
        if (!Array.isArray(refs) || !refs.every(isThreatRef))
            push(`${loc}: threatRefs must be an array of P1–P9`);
        for (const k of Object.keys(c)) {
            if (k !== "id" && k !== "summary" && k !== "external" && k !== "threatRefs")
                push(`${loc}: unknown field "${k}"`);
        }
    });
    // Prefix-freedom: no class id may be a prefix of another (see module note).
    for (const a of ids) {
        const longer = ids.find((b) => b !== a && b.startsWith(a));
        if (longer !== undefined)
            push(`class "${a}" is a prefix of "${longer}" — narrowing rules match class/<id>* so this would silently widen`);
    }
    if (reasons.length > 0)
        return { ok: false, reasons };
    return { ok: true, taxonomy: parsed };
}
/** The set of class ids a validated taxonomy defines. */
export function taxonomyClassIds(t) {
    return new Set(t.classes.map((c) => c.id));
}
