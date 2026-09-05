/**
 * Pack layer loader (TEAM-ADR-041) — the store side of rule packs.
 *
 * Store layout, FLAT under `.deepsweep/` (the contained store is flat by
 * design; every file inherits TEAM-ADR-028 self-protection automatically):
 *   pack-keys.json              trust pins for pack signing keys (ADR-016 shape;
 *                               deliberately NOT policy-keys.json — pinning a
 *                               pack key must not turn a plain workspace
 *                               policy.json into a downgrade refusal)
 *   pack.<id>.json              the sealed pack (ADR-016 envelope; DeepSweep-signed)
 *   pack.<id>.config.json       the CUSTOMER's config: { schemaVersion: 1, mode? }
 *                               — the one-line observe → enforce toggle
 *   pack.<id>.accepted.json     engine-written replay floor for that pack
 *
 * FAIL-CLOSED CONTRACT (mirrors loadPolicy): a pack whose signature, key,
 * version floor, block, id or config does not verify is REFUSED whole — zero
 * rules contributed, surfaced loudly as a `pack` layer refusal — and
 * `loadLayeredPolicy` treats a refused pack like a refused primary layer
 * (mode forced to enforce, ADR-010 safe default). Nothing here validates the
 * compiled POLICY: that is `validatePolicy`'s job in policy.ts, so this
 * module imports nothing from policy.ts at runtime and no cycle can form.
 */
import { readdirSync } from "node:fs";
import { parseTrustConfig, verifyBundle } from "../review/bundle.js";
import { checkedStorePaths, readStoreText, STORE_DIR, writeStoreAtomic } from "../review/store.js";
import { sanitizeField } from "../review/sanitize.js";
import { isPlainObject } from "./taxonomy.js";
import { packBundleHash, validatePackBlock } from "./pack.js";
export const PACK_KEYS_FILE = "pack-keys.json";
export const PACK_KEYS_REL_PATH = `${STORE_DIR}/${PACK_KEYS_FILE}`;
/** `pack.<id>.json` — the id grammar excludes dots so `.config` / `.accepted` never collide. */
const PACK_FILE_RE = /^pack\.([a-z][a-z0-9-]{1,40})\.json$/;
export const packFileName = (packId) => `pack.${packId}.json`;
export const packConfigFileName = (packId) => `pack.${packId}.config.json`;
export const packAcceptedFileName = (packId) => `pack.${packId}.accepted.json`;
export class PackRefusalError extends Error {
    constructor(reason) {
        super(`pack store refused: ${reason} — remove the offending symlink/path and re-run`);
        this.name = "PackRefusalError";
    }
}
const refuse = (reason) => new PackRefusalError(reason);
const tok = (s) => sanitizeField(s);
/** Enumerate sealed pack files in the store, sorted. Absent store → none. */
export function listPackIds(workspaceRoot) {
    const { dir } = checkedStorePaths(workspaceRoot, PACK_KEYS_FILE, refuse);
    let names;
    try {
        names = readdirSync(dir);
    }
    catch {
        return [];
    }
    const ids = [];
    for (const n of names) {
        const m = PACK_FILE_RE.exec(n);
        if (m !== null)
            ids.push(m[1]);
    }
    return ids.sort();
}
function readAcceptedFloor(workspaceRoot, packId) {
    const text = readStoreText(workspaceRoot, packAcceptedFileName(packId), refuse);
    if (text === undefined)
        return 0;
    try {
        const parsed = JSON.parse(text);
        const v = parsed?.["acceptedBundleVersion"];
        return typeof v === "number" && Number.isInteger(v) && v >= 0 ? v : 0;
    }
    catch {
        return 0; // torn floor degrades to 0 — the CONFIG floor (minBundleVersion) still holds
    }
}
function readConfig(workspaceRoot, packId) {
    const text = readStoreText(workspaceRoot, packConfigFileName(packId), refuse);
    if (text === undefined)
        return { ok: true, config: undefined };
    let parsed;
    try {
        parsed = JSON.parse(text);
    }
    catch {
        return { ok: false, reason: `${packConfigFileName(packId)} is not valid JSON` };
    }
    if (!isPlainObject(parsed) || parsed["schemaVersion"] !== 1)
        return { ok: false, reason: `${packConfigFileName(packId)} must be { schemaVersion: 1, mode? }` };
    const mode = parsed["mode"];
    if (mode !== undefined && mode !== "observe" && mode !== "enforce")
        return { ok: false, reason: `${packConfigFileName(packId)}: mode must be observe or enforce (got "${tok(String(mode))}")` };
    for (const k of Object.keys(parsed)) {
        if (k !== "schemaVersion" && k !== "mode")
            return { ok: false, reason: `${packConfigFileName(packId)}: unknown field "${tok(k)}" (a typo here would silently un-configure the pack, so it refuses)` };
    }
    return { ok: true, config: mode === undefined ? { schemaVersion: 1 } : { schemaVersion: 1, mode } };
}
/**
 * Load every sealed pack in the store. Total over arbitrary on-disk input:
 * every failure is a typed, per-pack refusal; containment violations throw
 * PackRefusalError (exit-3 class). Advances the per-pack accepted floor only
 * after the ENTIRE chain (envelope → key → signature → version → block →
 * id → config) succeeds, and only when it actually moved.
 */
export function loadPacks(workspaceRoot) {
    const ids = listPackIds(workspaceRoot);
    if (ids.length === 0)
        return { packs: [], refusals: [] };
    const packs = [];
    const refusals = [];
    const trustText = readStoreText(workspaceRoot, PACK_KEYS_FILE, refuse);
    const trust = trustText === undefined ? undefined : parseTrustConfig(trustText);
    for (const packId of ids) {
        const source = `${STORE_DIR}/${packFileName(packId)}`;
        const refused = (reason) => {
            refusals.push({ packId, source, reasons: [tok(reason)] });
        };
        if (trust === undefined) {
            refused(`no ${PACK_KEYS_REL_PATH} pins a pack signing key — a sealed pack cannot be trusted (never fail open)`);
            continue;
        }
        if (trust === "malformed") {
            refused(`${PACK_KEYS_REL_PATH} is malformed — pack signing is unverifiable, refusing (never fail open)`);
            continue;
        }
        const text = readStoreText(workspaceRoot, packFileName(packId), refuse);
        let parsed;
        try {
            parsed = text === undefined ? undefined : JSON.parse(text);
        }
        catch {
            parsed = undefined;
        }
        if (parsed === undefined) {
            refused(`${source} is unreadable or not valid JSON`);
            continue;
        }
        const floor = Math.max(trust.minBundleVersion, readAcceptedFloor(workspaceRoot, packId));
        const verdict = verifyBundle(parsed, trust.keys, floor);
        if (!verdict.ok) {
            refused(`sealed pack refused (${verdict.reason}): ${verdict.detail}`);
            continue;
        }
        const bundle = verdict.bundle;
        const block = validatePackBlock(bundle.pack);
        if (!block.ok) {
            refusals.push({ packId, source, reasons: block.reasons.map((r) => `pack block: ${r}`) });
            continue;
        }
        if (block.pack.manifest.packId !== packId) {
            refused(`file names pack "${packId}" but the signed manifest says "${block.pack.manifest.packId}"`);
            continue;
        }
        const cfg = readConfig(workspaceRoot, packId);
        if (!cfg.ok) {
            refused(cfg.reason);
            continue;
        }
        if (bundle.bundleVersion > readAcceptedFloor(workspaceRoot, packId)) {
            writeStoreAtomic(workspaceRoot, packAcceptedFileName(packId), `${JSON.stringify({ schemaVersion: 1, acceptedBundleVersion: bundle.bundleVersion }, null, 2)}\n`, refuse);
        }
        const policyMode = isPlainObject(bundle.policy) && (bundle.policy["mode"] === "observe" || bundle.policy["mode"] === "enforce") ? bundle.policy["mode"] : undefined;
        packs.push({
            packId,
            version: block.pack.manifest.version,
            bundleVersion: bundle.bundleVersion,
            keyId: verdict.keyId,
            bundleHash: packBundleHash(bundle),
            mode: cfg.config?.mode ?? policyMode,
            config: cfg.config,
            policyDoc: bundle.policy,
            pack: block.pack,
            bindings: block.pack.bindings,
            source,
        });
    }
    return { packs, refusals };
}
/**
 * Install helper for hosts and tests: write the sealed pack, the trust pin
 * and (optionally) the config into a workspace store. Plain contained writes;
 * the loader re-verifies everything on the next decision — installing never
 * pre-trusts.
 */
export function installPack(workspaceRoot, packId, sealed, trust, config) {
    writeStoreAtomic(workspaceRoot, packFileName(packId), `${JSON.stringify(sealed, null, 2)}\n`, refuse);
    writeStoreAtomic(workspaceRoot, PACK_KEYS_FILE, `${JSON.stringify({ schemaVersion: 1, keys: [{ keyId: trust.keyId, publicKey: trust.publicKey }], minBundleVersion: trust.minBundleVersion ?? 0 }, null, 2)}\n`, refuse);
    if (config !== undefined)
        writeStoreAtomic(workspaceRoot, packConfigFileName(packId), `${JSON.stringify(config, null, 2)}\n`, refuse);
}
