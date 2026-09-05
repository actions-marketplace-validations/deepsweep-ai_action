export declare const BINDING_SCHEMA_VERSION: 1;
/** Alias namespace pack rules are written against. */
export declare const CLASS_ALIAS_PREFIX = "class/";
/** Suffix that marks a heuristic (name-pattern) classification. */
export declare const HEURISTIC_ALIAS_SUFFIX = "#heuristic";
export type BindingConfidence = "vendor" | "heuristic";
/** Confidence of ONE resolved classification, best-of across contributing bindings. */
export type ClassificationConfidence = "pinned" | "vendor" | "heuristic";
export interface BindingSource {
    readonly server: string;
    readonly url: string;
    readonly checkedAt: string;
    readonly method: string;
}
export interface BindingTool {
    readonly name: string;
    readonly classes: readonly string[];
    readonly source?: string;
    /** SHA-256 over canonical {name, description, inputSchema} (TEAM-ADR-039) when DeepSweep has pinned this exact tool. */
    readonly descriptionHash?: string;
    readonly note?: string;
}
export interface BindingPattern {
    /** Case-insensitive glob over the tool name; `*` is the only wildcard. */
    readonly pattern: string;
    readonly classes: readonly string[];
    readonly note?: string;
}
export interface TaxonomyBinding {
    readonly schemaVersion: typeof BINDING_SCHEMA_VERSION;
    readonly bindingId: string;
    readonly vendorClass: string;
    readonly title: string;
    readonly taxonomyId: string;
    readonly taxonomyVersion: string;
    readonly confidence: BindingConfidence;
    readonly note?: string;
    readonly sources: readonly BindingSource[];
    readonly tools: readonly BindingTool[];
    readonly patterns?: readonly BindingPattern[];
}
export declare const MAX_BINDING_REASONS = 20;
export type BindingValidation = {
    readonly ok: true;
    readonly binding: TaxonomyBinding;
} | {
    readonly ok: false;
    readonly reasons: readonly string[];
};
/**
 * Strict validation of ONE binding document against a taxonomy's class set.
 * Whole-document refusal on any problem; reasons bounded and sanitized.
 */
export declare function validateBinding(parsed: unknown, knownClasses: ReadonlySet<string>): BindingValidation;
/** Case-insensitive glob (`*` only) → anchored RegExp. Everything else is literal. */
export declare function globToRegExp(glob: string): RegExp;
export interface Classification {
    /** Sorted, unique taxonomy class ids. */
    readonly classes: readonly string[];
    readonly confidence: ClassificationConfidence;
    /** Sorted ids of the bindings that contributed. */
    readonly bindings: readonly string[];
    /** Resource aliases for the evaluator: `class/<id>` (vendor/pinned) or `class/<id>#heuristic`. Sorted. */
    readonly aliases: readonly string[];
}
/**
 * Resolve the classes a tool NAME belongs to. Vendor name-matches take the
 * union across all bindings that name the tool; heuristics run only when no
 * binding named it. Returns null when nothing matched — the caller then
 * evaluates the raw `mcp/<server>/<tool>` resource alone and the pack's
 * default decides (default-deny-unknown).
 */
export declare function resolveClasses(bindings: readonly TaxonomyBinding[], toolName: string, descriptionHash?: string): Classification | null;
