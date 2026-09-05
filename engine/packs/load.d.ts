import type { PolicyMode } from "../review/policy.js";
import type { TaxonomyBinding } from "./bindings.js";
import { type PackBlock } from "./pack.js";
export declare const PACK_KEYS_FILE = "pack-keys.json";
export declare const PACK_KEYS_REL_PATH = ".deepsweep/pack-keys.json";
export declare const packFileName: (packId: string) => string;
export declare const packConfigFileName: (packId: string) => string;
export declare const packAcceptedFileName: (packId: string) => string;
export declare class PackRefusalError extends Error {
    constructor(reason: string);
}
/** The customer's per-pack configuration. Strict: an unknown field or a bad mode refuses the PACK (loudly), never degrades silently. */
export interface PackConfig {
    readonly schemaVersion: 1;
    readonly mode?: PolicyMode;
}
export interface LoadedPack {
    readonly packId: string;
    readonly version: string;
    readonly bundleVersion: number;
    readonly keyId: string;
    /** SHA-256 over the canonical signed bundle — the pack's content identity. */
    readonly bundleHash: string;
    /** Effective mode this pack asks for: config.mode ?? the compiled policy's mode. Org/workspace declarations still outrank it. */
    readonly mode: PolicyMode | undefined;
    readonly config: PackConfig | undefined;
    /** The compiled policy document, NOT yet validated (policy.ts validates it). */
    readonly policyDoc: unknown;
    readonly pack: PackBlock;
    readonly bindings: readonly TaxonomyBinding[];
    readonly source: string;
}
export interface PackRefusal {
    readonly packId: string;
    readonly source: string;
    readonly reasons: readonly string[];
}
export interface PackLayerLoad {
    readonly packs: readonly LoadedPack[];
    readonly refusals: readonly PackRefusal[];
}
/** Enumerate sealed pack files in the store, sorted. Absent store → none. */
export declare function listPackIds(workspaceRoot: string): readonly string[];
/**
 * Load every sealed pack in the store. Total over arbitrary on-disk input:
 * every failure is a typed, per-pack refusal; containment violations throw
 * PackRefusalError (exit-3 class). Advances the per-pack accepted floor only
 * after the ENTIRE chain (envelope → key → signature → version → block →
 * id → config) succeeds, and only when it actually moved.
 */
export declare function loadPacks(workspaceRoot: string): PackLayerLoad;
/**
 * Install helper for hosts and tests: write the sealed pack, the trust pin
 * and (optionally) the config into a workspace store. Plain contained writes;
 * the loader re-verifies everything on the next decision — installing never
 * pre-trusts.
 */
export declare function installPack(workspaceRoot: string, packId: string, sealed: unknown, trust: {
    readonly keyId: string;
    readonly publicKey: string;
    readonly minBundleVersion?: number;
}, config?: PackConfig): void;
