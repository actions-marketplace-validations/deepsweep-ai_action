import { canonicalize, sha256Hex } from "../review/canonical.js";
import { sealBundle } from "../review/bundle.js";
import { sanitizeField } from "../review/sanitize.js";
import { CLASS_ALIAS_PREFIX, validateBinding } from "./bindings.js";
import { isPlainObject, isThreatRef, PACK_ID_RE, taxonomyClassIds, validateTaxonomy } from "./taxonomy.js";
export const PACK_SCHEMA_VERSION = 1;
export const SEMVER_RE = /^\d+\.\d+\.\d+$/;
export const RULE_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$/;
export const MAX_PACK_REASONS = 20;
const tok = (s) => sanitizeField(s);
function manifestErrors(m, out) {
    if (!isPlainObject(m)) {
        out("manifest must be an object");
        return false;
    }
    let ok = true;
    const bad = (r) => {
        ok = false;
        out(`manifest: ${r}`);
    };
    if (m["schemaVersion"] !== PACK_SCHEMA_VERSION)
        bad(`unknown schemaVersion ${String(m["schemaVersion"])}`);
    if (typeof m["packId"] !== "string" || !PACK_ID_RE.test(m["packId"]))
        bad("packId must match ^[a-z][a-z0-9-]{1,40}$");
    if (typeof m["version"] !== "string" || !SEMVER_RE.test(m["version"]))
        bad("version must be MAJOR.MINOR.PATCH");
    for (const f of ["title", "description", "taxonomyVersion", "standing"]) {
        if (typeof m[f] !== "string" || m[f].length === 0)
            bad(`${f} must be a non-empty string`);
    }
    const eng = m["engine"];
    if (!isPlainObject(eng) || eng["policySchemaVersion"] !== 1 || eng["action"] !== "tool.invoke" || eng["resourcePrefix"] !== CLASS_ALIAS_PREFIX) {
        bad('engine must be { policySchemaVersion: 1, action: "tool.invoke", resourcePrefix: "class/" }');
    }
    const d = m["defaults"];
    if (!isPlainObject(d) || (d["mode"] !== "observe" && d["mode"] !== "enforce") || (d["defaultEffect"] !== "require-approval" && d["defaultEffect"] !== "deny")) {
        bad("defaults must be { mode: observe|enforce, defaultEffect: require-approval|deny } — a pack default may never be observe or allow");
    }
    const refs = m["threatRefs"];
    if (!Array.isArray(refs) || refs.length === 0)
        bad("threatRefs must be a non-empty array");
    else {
        const seen = new Set();
        refs.forEach((r, i) => {
            if (!isPlainObject(r) || !isThreatRef(r["id"]) || typeof r["title"] !== "string" || typeof r["mechanism"] !== "string") {
                bad(`threatRefs #${i} must be { id: P1–P9, title, mechanism }`);
            }
            else if (seen.has(r["id"]))
                bad(`threatRefs: duplicate ${r["id"]}`);
            else
                seen.add(r["id"]);
        });
    }
    if (m["wording"] !== undefined && !isPlainObject(m["wording"]))
        bad("wording, when present, must be an object");
    if (m["note"] !== undefined && typeof m["note"] !== "string")
        bad("note, when present, must be a string");
    const KNOWN = new Set(["schemaVersion", "packId", "version", "title", "description", "taxonomyVersion", "engine", "defaults", "threatRefs", "standing", "wording", "note"]);
    for (const k of Object.keys(m))
        if (!KNOWN.has(k))
            bad(`unknown field "${k}"`);
    return ok;
}
function rulesErrors(r, packId, classes, out) {
    if (!isPlainObject(r)) {
        out("rules must be an object");
        return false;
    }
    let ok = true;
    const bad = (s) => {
        ok = false;
        out(`rules: ${s}`);
    };
    if (r["schemaVersion"] !== PACK_SCHEMA_VERSION)
        bad(`unknown schemaVersion ${String(r["schemaVersion"])}`);
    if (r["packId"] !== packId)
        bad("packId must equal the manifest packId");
    if (r["note"] !== undefined && typeof r["note"] !== "string")
        bad("note, when present, must be a string");
    for (const k of Object.keys(r))
        if (k !== "schemaVersion" && k !== "packId" && k !== "note" && k !== "rules")
            bad(`unknown field "${k}"`);
    const list = r["rules"];
    if (!Array.isArray(list) || list.length === 0) {
        bad("rules must be a non-empty array");
        return false;
    }
    const names = new Set();
    list.forEach((x, i) => {
        if (!isPlainObject(x)) {
            bad(`rule #${i} must be an object`);
            return;
        }
        const name = x["name"];
        const loc = typeof name === "string" && name.length > 0 ? `rule "${name}"` : `rule #${i}`;
        if (typeof name !== "string" || !RULE_NAME_RE.test(name))
            bad(`${loc}: name must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$`);
        else if (names.has(name))
            bad(`${loc}: duplicate rule name`);
        else
            names.add(name);
        if (!isThreatRef(x["threatRef"]))
            bad(`${loc}: threatRef must be P1–P9`);
        const role = x["role"];
        const effect = x["effect"];
        if (role !== "narrow" && role !== "allow-counterpart")
            bad(`${loc}: role must be narrow or allow-counterpart`);
        if (effect !== "allow" && effect !== "deny" && effect !== "require-approval")
            bad(`${loc}: effect must be allow, deny or require-approval`);
        else if (role === "narrow" && effect === "allow")
            bad(`${loc}: a narrow rule cannot allow`);
        else if (role === "allow-counterpart" && effect !== "allow")
            bad(`${loc}: an allow-counterpart rule must allow`);
        if (typeof x["class"] !== "string" || !classes.has(x["class"]))
            bad(`${loc}: class "${typeof x["class"] === "string" ? x["class"] : String(x["class"])}" is not in the taxonomy`);
        if (typeof x["rationale"] !== "string" || x["rationale"].length === 0)
            bad(`${loc}: rationale is required`);
        for (const k of Object.keys(x)) {
            if (k !== "name" && k !== "threatRef" && k !== "role" && k !== "effect" && k !== "class" && k !== "rationale")
                bad(`${loc}: unknown field "${k}"`);
        }
    });
    return ok;
}
/**
 * Strict, whole-block validation of a pack block (manifest + taxonomy +
 * rules + bindings), cross-checking ids and classes. Reasons bounded and
 * sanitized; nothing partial is ever returned.
 */
export function validatePackBlock(parsed) {
    const reasons = [];
    const push = (r) => {
        if (reasons.length < MAX_PACK_REASONS)
            reasons.push(tok(r));
    };
    if (!isPlainObject(parsed))
        return { ok: false, reasons: ["pack block must be an object"] };
    if (parsed["schemaVersion"] !== PACK_SCHEMA_VERSION)
        push(`unknown pack schemaVersion ${String(parsed["schemaVersion"])}`);
    for (const k of Object.keys(parsed)) {
        if (k !== "schemaVersion" && k !== "manifest" && k !== "taxonomy" && k !== "rules" && k !== "bindings")
            push(`unknown pack field "${k}"`);
    }
    const manifest = parsed["manifest"];
    const manifestOk = manifestErrors(manifest, push);
    const tax = validateTaxonomy(parsed["taxonomy"]);
    if (!tax.ok)
        for (const r of tax.reasons)
            push(`taxonomy: ${r}`);
    if (!manifestOk || !tax.ok)
        return { ok: false, reasons };
    const m = manifest;
    if (m.taxonomyVersion !== tax.taxonomy.version)
        push(`manifest taxonomyVersion ${m.taxonomyVersion} does not match taxonomy version ${tax.taxonomy.version}`);
    if (m.packId !== tax.taxonomy.taxonomyId)
        push(`taxonomy id ${tax.taxonomy.taxonomyId} does not match packId ${m.packId}`);
    const classes = taxonomyClassIds(tax.taxonomy);
    rulesErrors(parsed["rules"], m.packId, classes, push);
    const bindings = parsed["bindings"];
    if (!Array.isArray(bindings))
        push("bindings must be an array");
    else {
        const ids = new Set();
        bindings.forEach((b, i) => {
            const v = validateBinding(b, classes);
            if (!v.ok) {
                for (const r of v.reasons)
                    push(`binding #${i}: ${r}`);
                return;
            }
            if (ids.has(v.binding.bindingId))
                push(`binding "${v.binding.bindingId}": duplicate bindingId`);
            ids.add(v.binding.bindingId);
            if (v.binding.taxonomyId !== m.packId || v.binding.taxonomyVersion !== tax.taxonomy.version) {
                push(`binding "${v.binding.bindingId}": taxonomyId/taxonomyVersion do not match this pack`);
            }
        });
    }
    if (reasons.length > 0)
        return { ok: false, reasons };
    return { ok: true, pack: parsed };
}
/** Resource matcher a compiled rule carries for a class: exact for allow, trailing-wildcard for narrowing. */
export function classResourceMatcher(cls, effect) {
    return effect === "allow" ? `${CLASS_ALIAS_PREFIX}${cls}` : `${CLASS_ALIAS_PREFIX}${cls}*`;
}
/**
 * Compile a VALIDATED pack block into an ADR-009 PolicySet. Deterministic:
 * rules sorted by name; the policy `name` is `<packId>@<version>`; mode and
 * defaultEffect come from the manifest defaults. The result is validated by
 * the loader through the ONE policy validator (never here — no cycle).
 */
export function compilePackPolicy(pack) {
    const rules = [...pack.rules.rules]
        .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
        .map((r) => r.effect === "allow"
        ? { effect: "allow", name: r.name, rationale: r.rationale, principal: "*", action: "tool.invoke", resource: classResourceMatcher(r.class, r.effect) }
        : { effect: r.effect, name: r.name, rationale: r.rationale, principal: "*", action: "tool.invoke", resource: classResourceMatcher(r.class, r.effect) });
    return {
        schemaVersion: 1,
        name: `${pack.manifest.packId}@${pack.manifest.version}`,
        mode: pack.manifest.defaults.mode,
        defaultEffect: pack.manifest.defaults.defaultEffect,
        rules,
    };
}
/** SHA-256 over the canonical bytes of the signed bundle — the pack's content identity. */
export function packBundleHash(bundle) {
    return sha256Hex(canonicalize(bundle));
}
/**
 * Seal a validated pack: compile, wrap with the pack block in the ADR-016
 * envelope, sign. `bundleVersion` is the strictly-monotonic replay counter
 * (distinct from the manifest's semver, which is the human release label).
 */
export function sealPack(pack, privateKey, bundleVersion) {
    const bundle = { schemaVersion: 1, bundleVersion, policy: compilePackPolicy(pack), pack };
    return { sealed: sealBundle(bundle, privateKey), bundle, bundleHash: packBundleHash(bundle) };
}
/** Assemble a pack block from its source documents (as read from packs/<id>/). Validates. */
export function assemblePack(source) {
    return validatePackBlock({ schemaVersion: PACK_SCHEMA_VERSION, manifest: source.manifest, taxonomy: source.taxonomy, rules: source.rules, bindings: source.bindings });
}
