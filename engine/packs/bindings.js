/**
 * Taxonomy bindings (TEAM-ADR-041) — DATA that maps observed MCP tool names
 * to taxonomy classes. Adding a vendor is adding a JSON document to a pack;
 * the engine changes nothing.
 *
 * Two grades, kept structurally apart:
 *  - VENDOR bindings match by EXACT tool name (optionally confirmed by the
 *    TEAM-ADR-039 pinned description hash → "pinned"). They resolve to the
 *    alias `class/<id>`, which pack ALLOW rules match exactly.
 *  - HEURISTIC bindings match by case-insensitive glob over the name and
 *    resolve to `class/<id>#heuristic`. Pack NARROWING rules are compiled
 *    `class/<id>*` and so catch it; allow rules never do. A guess can hold or
 *    deny; it can never broaden (ADR-009 crux, preserved at the data layer).
 * Heuristics are consulted ONLY when no vendor binding named the tool — a
 * verified name is the better evidence and must not be second-guessed by a
 * substring.
 *
 * Pure, deterministic, zero dependencies. Never reads the tool's description
 * or arguments — the classification is over the NAME (and, when present, a
 * hash the gateway already holds).
 */
import { sanitizeField } from "../review/sanitize.js";
import { CLASS_ID_RE, PACK_ID_RE, isPlainObject } from "./taxonomy.js";
export const BINDING_SCHEMA_VERSION = 1;
/** Alias namespace pack rules are written against. */
export const CLASS_ALIAS_PREFIX = "class/";
/** Suffix that marks a heuristic (name-pattern) classification. */
export const HEURISTIC_ALIAS_SUFFIX = "#heuristic";
export const MAX_BINDING_REASONS = 20;
const HEX64 = /^[0-9a-f]{64}$/;
const tok = (s) => sanitizeField(s);
function classesError(v, known) {
    if (!Array.isArray(v) || v.length === 0)
        return "classes must be a non-empty array";
    for (const c of v) {
        if (typeof c !== "string" || !CLASS_ID_RE.test(c))
            return `class "${typeof c === "string" ? tok(c) : String(c)}" is not a class id`;
        if (!known.has(c))
            return `class "${tok(c)}" is not in the taxonomy`;
    }
    return undefined;
}
/**
 * Strict validation of ONE binding document against a taxonomy's class set.
 * Whole-document refusal on any problem; reasons bounded and sanitized.
 */
export function validateBinding(parsed, knownClasses) {
    const reasons = [];
    const push = (r) => {
        if (reasons.length < MAX_BINDING_REASONS)
            reasons.push(tok(r));
    };
    if (!isPlainObject(parsed))
        return { ok: false, reasons: ["binding must be a JSON object"] };
    if (parsed["schemaVersion"] !== BINDING_SCHEMA_VERSION)
        push(`unknown binding schemaVersion ${String(parsed["schemaVersion"])}`);
    for (const f of ["bindingId", "vendorClass", "taxonomyId"]) {
        if (typeof parsed[f] !== "string" || !PACK_ID_RE.test(parsed[f]))
            push(`${f} must match ^[a-z][a-z0-9-]{1,40}$`);
    }
    for (const f of ["title", "taxonomyVersion"]) {
        if (typeof parsed[f] !== "string" || parsed[f].length === 0)
            push(`${f} must be a non-empty string`);
    }
    if (parsed["note"] !== undefined && typeof parsed["note"] !== "string")
        push("note, when present, must be a string");
    const confidence = parsed["confidence"];
    if (confidence !== "vendor" && confidence !== "heuristic")
        push('confidence must be "vendor" or "heuristic"');
    const KNOWN = new Set(["schemaVersion", "bindingId", "vendorClass", "title", "taxonomyId", "taxonomyVersion", "confidence", "note", "sources", "tools", "patterns"]);
    for (const k of Object.keys(parsed))
        if (!KNOWN.has(k))
            push(`unknown top-level field "${k}"`);
    const sources = parsed["sources"];
    if (!Array.isArray(sources))
        push("sources must be an array");
    else {
        sources.forEach((s, i) => {
            if (!isPlainObject(s) || ["server", "url", "checkedAt", "method"].some((f) => typeof s[f] !== "string" || s[f].length === 0)) {
                push(`source #${i} must carry server, url, checkedAt and method`);
            }
        });
    }
    const tools = parsed["tools"];
    const names = new Set();
    if (!Array.isArray(tools))
        push("tools must be an array");
    else {
        tools.forEach((t, i) => {
            if (!isPlainObject(t)) {
                push(`tool #${i} must be an object`);
                return;
            }
            const name = t["name"];
            const loc = typeof name === "string" && name.length > 0 ? `tool "${name}"` : `tool #${i}`;
            if (typeof name !== "string" || name.length === 0)
                push(`${loc}: name is required`);
            else if (names.has(name))
                push(`${loc}: duplicate tool name in this binding`);
            else
                names.add(name);
            const cErr = classesError(t["classes"], knownClasses);
            if (cErr)
                push(`${loc}: ${cErr}`);
            if (t["descriptionHash"] !== undefined && (typeof t["descriptionHash"] !== "string" || !HEX64.test(t["descriptionHash"]))) {
                push(`${loc}: descriptionHash must be 64 hex chars`);
            }
            for (const k of Object.keys(t)) {
                if (k !== "name" && k !== "classes" && k !== "source" && k !== "descriptionHash" && k !== "note")
                    push(`${loc}: unknown field "${k}"`);
            }
        });
    }
    const patterns = parsed["patterns"];
    if (patterns !== undefined) {
        if (!Array.isArray(patterns))
            push("patterns, when present, must be an array");
        else {
            if (confidence === "vendor" && patterns.length > 0)
                push("a vendor binding may not carry patterns — name patterns are heuristic by nature");
            patterns.forEach((p, i) => {
                if (!isPlainObject(p)) {
                    push(`pattern #${i} must be an object`);
                    return;
                }
                const pat = p["pattern"];
                const loc = typeof pat === "string" && pat.length > 0 ? `pattern "${pat}"` : `pattern #${i}`;
                if (typeof pat !== "string" || pat.length === 0 || pat.replace(/\*/g, "").length === 0)
                    push(`${loc}: pattern must contain at least one literal character`);
                const cErr = classesError(p["classes"], knownClasses);
                if (cErr)
                    push(`${loc}: ${cErr}`);
                for (const k of Object.keys(p))
                    if (k !== "pattern" && k !== "classes" && k !== "note")
                        push(`${loc}: unknown field "${k}"`);
            });
        }
    }
    if (reasons.length > 0)
        return { ok: false, reasons };
    return { ok: true, binding: parsed };
}
/** Case-insensitive glob (`*` only) → anchored RegExp. Everything else is literal. */
export function globToRegExp(glob) {
    const src = glob
        .split("*")
        .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
        .join(".*");
    return new RegExp(`^${src}$`, "i");
}
const CONFIDENCE_RANK = { heuristic: 0, vendor: 1, pinned: 2 };
/**
 * Resolve the classes a tool NAME belongs to. Vendor name-matches take the
 * union across all bindings that name the tool; heuristics run only when no
 * binding named it. Returns null when nothing matched — the caller then
 * evaluates the raw `mcp/<server>/<tool>` resource alone and the pack's
 * default decides (default-deny-unknown).
 */
export function resolveClasses(bindings, toolName, descriptionHash) {
    const exact = new Set();
    const heuristic = new Set();
    const contributing = new Set();
    let best;
    const bump = (c) => {
        if (best === undefined || CONFIDENCE_RANK[c] > CONFIDENCE_RANK[best])
            best = c;
    };
    for (const b of bindings) {
        for (const t of b.tools) {
            if (t.name !== toolName)
                continue;
            contributing.add(b.bindingId);
            const pinned = t.descriptionHash !== undefined && descriptionHash !== undefined && t.descriptionHash === descriptionHash;
            const grade = pinned ? "pinned" : b.confidence;
            bump(grade);
            for (const c of t.classes)
                (grade === "heuristic" ? heuristic : exact).add(c);
        }
    }
    if (contributing.size === 0) {
        for (const b of bindings) {
            for (const p of b.patterns ?? []) {
                if (!globToRegExp(p.pattern).test(toolName))
                    continue;
                contributing.add(b.bindingId);
                bump("heuristic");
                for (const c of p.classes)
                    heuristic.add(c);
            }
        }
    }
    if (best === undefined)
        return null;
    const aliases = [
        ...[...exact].map((c) => `${CLASS_ALIAS_PREFIX}${c}`),
        ...[...heuristic].filter((c) => !exact.has(c)).map((c) => `${CLASS_ALIAS_PREFIX}${c}${HEURISTIC_ALIAS_SUFFIX}`),
    ].sort();
    return {
        classes: [...new Set([...exact, ...heuristic])].sort(),
        confidence: best,
        bindings: [...contributing].sort(),
        aliases,
    };
}
