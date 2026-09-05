export declare const TAXONOMY_SCHEMA_VERSION: 1;
/** The threat-pattern references a pack may cite (closed; §4 of the EXEC-1 spec). */
export declare const THREAT_REFS: readonly ["P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9"];
export type ThreatRef = (typeof THREAT_REFS)[number];
export interface TaxonomyClass {
    readonly id: string;
    readonly summary: string;
    /** True when acting through this class moves data or authority OUTSIDE the organisation. */
    readonly external: boolean;
    readonly threatRefs: readonly ThreatRef[];
}
export interface Taxonomy {
    readonly schemaVersion: typeof TAXONOMY_SCHEMA_VERSION;
    readonly taxonomyId: string;
    readonly version: string;
    readonly note?: string;
    readonly classes: readonly TaxonomyClass[];
}
/** Class ids are lower-case dot paths of at least two segments (`mail.send.external`). */
export declare const CLASS_ID_RE: RegExp;
/** Pack / taxonomy / binding ids: lower-case, digits, hyphens; no dots (they name store files). */
export declare const PACK_ID_RE: RegExp;
export declare const MAX_TAXONOMY_REASONS = 20;
export type TaxonomyValidation = {
    readonly ok: true;
    readonly taxonomy: Taxonomy;
} | {
    readonly ok: false;
    readonly reasons: readonly string[];
};
export declare function isPlainObject(v: unknown): v is Record<string, unknown>;
export declare function isThreatRef(v: unknown): v is ThreatRef;
/**
 * Strict, deterministic validation of a taxonomy document. Whole-document
 * refusal on any problem; reasons are bounded and sanitized.
 */
export declare function validateTaxonomy(parsed: unknown): TaxonomyValidation;
/** The set of class ids a validated taxonomy defines. */
export declare function taxonomyClassIds(t: Taxonomy): ReadonlySet<string>;
