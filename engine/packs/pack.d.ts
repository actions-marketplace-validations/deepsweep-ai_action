/**
 * Rule packs (TEAM-ADR-041) — content on existing rails.
 *
 * A pack is a SIGNED, versioned bundle of: a manifest, a taxonomy, rules
 * authored against taxonomy classes, and vendor bindings. `compilePackPolicy`
 * turns the class rules into an ordinary ADR-009 policy (action
 * `tool.invoke`, resource `class/<id>` for allow, `class/<id>*` for
 * narrowing) — the engine's grammar, validator, evaluator, enforcement
 * mapping and ledger are reused verbatim. `sealPack` wraps compiled policy +
 * pack block in the ADR-016 envelope so `verifyBundle` covers ALL of it:
 * a tampered binding breaks the same signature as a tampered rule.
 *
 * Nothing here evaluates, enforces, or reads a workspace. Pure functions
 * over parsed JSON, node:crypto only.
 */
import type { KeyObject } from "node:crypto";
import { type PolicyBundle, type SealedBundle } from "../review/bundle.js";
import type { PolicyDefaultEffect, PolicyMode, PolicySet } from "../review/policy.js";
import { CLASS_ALIAS_PREFIX, type TaxonomyBinding } from "./bindings.js";
import { type Taxonomy, type ThreatRef } from "./taxonomy.js";
export declare const PACK_SCHEMA_VERSION: 1;
export declare const SEMVER_RE: RegExp;
export declare const RULE_NAME_RE: RegExp;
export interface PackThreatRef {
    readonly id: ThreatRef;
    readonly title: string;
    readonly mechanism: string;
}
export interface PackManifest {
    readonly schemaVersion: typeof PACK_SCHEMA_VERSION;
    readonly packId: string;
    readonly version: string;
    readonly title: string;
    readonly description: string;
    readonly taxonomyVersion: string;
    readonly engine: {
        readonly policySchemaVersion: 1;
        readonly action: "tool.invoke";
        readonly resourcePrefix: typeof CLASS_ALIAS_PREFIX;
    };
    readonly defaults: {
        readonly mode: PolicyMode;
        readonly defaultEffect: Exclude<PolicyDefaultEffect, "observe">;
    };
    readonly threatRefs: readonly PackThreatRef[];
    readonly standing: string;
    readonly wording?: Record<string, unknown>;
    readonly note?: string;
}
export type PackRuleRole = "narrow" | "allow-counterpart";
export type PackRuleEffect = "allow" | "deny" | "require-approval";
export interface PackRule {
    readonly name: string;
    readonly threatRef: ThreatRef;
    readonly role: PackRuleRole;
    readonly effect: PackRuleEffect;
    readonly class: string;
    readonly rationale: string;
}
export interface PackRules {
    readonly schemaVersion: typeof PACK_SCHEMA_VERSION;
    readonly packId: string;
    readonly note?: string;
    readonly rules: readonly PackRule[];
}
/** The signed pack block that travels INSIDE the ADR-016 bundle next to the compiled policy. */
export interface PackBlock {
    readonly schemaVersion: typeof PACK_SCHEMA_VERSION;
    readonly manifest: PackManifest;
    readonly taxonomy: Taxonomy;
    readonly rules: PackRules;
    readonly bindings: readonly TaxonomyBinding[];
}
/** ADR-016 PolicyBundle + the pack block; `sealBundle` signs the whole object. */
export interface PackBundle extends PolicyBundle {
    readonly pack: PackBlock;
}
export declare const MAX_PACK_REASONS = 20;
export type PackValidation = {
    readonly ok: true;
    readonly pack: PackBlock;
} | {
    readonly ok: false;
    readonly reasons: readonly string[];
};
/**
 * Strict, whole-block validation of a pack block (manifest + taxonomy +
 * rules + bindings), cross-checking ids and classes. Reasons bounded and
 * sanitized; nothing partial is ever returned.
 */
export declare function validatePackBlock(parsed: unknown): PackValidation;
/** Resource matcher a compiled rule carries for a class: exact for allow, trailing-wildcard for narrowing. */
export declare function classResourceMatcher(cls: string, effect: PackRuleEffect): string;
/**
 * Compile a VALIDATED pack block into an ADR-009 PolicySet. Deterministic:
 * rules sorted by name; the policy `name` is `<packId>@<version>`; mode and
 * defaultEffect come from the manifest defaults. The result is validated by
 * the loader through the ONE policy validator (never here — no cycle).
 */
export declare function compilePackPolicy(pack: PackBlock): PolicySet;
/** SHA-256 over the canonical bytes of the signed bundle — the pack's content identity. */
export declare function packBundleHash(bundle: PackBundle): string;
/**
 * Seal a validated pack: compile, wrap with the pack block in the ADR-016
 * envelope, sign. `bundleVersion` is the strictly-monotonic replay counter
 * (distinct from the manifest's semver, which is the human release label).
 */
export declare function sealPack(pack: PackBlock, privateKey: KeyObject, bundleVersion: number): {
    readonly sealed: SealedBundle;
    readonly bundle: PackBundle;
    readonly bundleHash: string;
};
/** Assemble a pack block from its source documents (as read from packs/<id>/). Validates. */
export declare function assemblePack(source: {
    readonly manifest: unknown;
    readonly taxonomy: unknown;
    readonly rules: unknown;
    readonly bindings: readonly unknown[];
}): PackValidation;
