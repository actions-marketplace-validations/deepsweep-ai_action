/** Environment variable carrying an explicit label for every surface. */
export declare const WORKSPACE_LABEL_ENV = "DEEPSWEEP_WORKSPACE_LABEL";
/** Prefix that marks a DERIVED label, so a reader never mistakes it for a name. */
export declare const WORKSPACE_LABEL_PREFIX = "ws_";
/** Hex characters kept from the HMAC (64 bits — a label, not a digest). */
export declare const WORKSPACE_LABEL_HEX_LENGTH = 16;
/** Maximum accepted length of a client-supplied label. */
export declare const WORKSPACE_LABEL_MAX_LENGTH = 64;
/**
 * Accepted shape for a client-supplied label: letters, digits, dot, dash,
 * underscore, first character alphanumeric. Deliberately excludes `/`, `\`,
 * `:` and whitespace, so a supplied label can never be a path, a URL
 * authority, or a value that changes how any renderer frames it.
 */
export declare const WORKSPACE_LABEL_SHAPE: RegExp;
/** Raised only for a supplied label that cannot be used as given. */
export declare class WorkspaceLabelError extends Error {
    constructor(message: string);
}
/**
 * Validate a client-supplied label, or REFUSE. Never falls back to the
 * derived value: an operator who typed a label wrong must find out, not
 * discover later that the artifact carries a hash they did not expect.
 */
export declare function checkWorkspaceLabel(supplied: string): string;
/**
 * The salted-hash default. Exported so a test can assert the artifact's value
 * IS this function's output and nothing else.
 */
export declare function derivedWorkspaceLabel(workspaceRoot: string): string;
/**
 * THE derivation. Every surface that needs to name a workspace calls this and
 * nothing else — the count of `basename(` calls outside this module is the
 * regression guard (tests/workspace-label-gate.test.ts).
 *
 * @param workspaceRoot absolute or relative workspace root.
 * @param supplied optional client label; falls back to
 *   `DEEPSWEEP_WORKSPACE_LABEL`, then to the salted hash.
 */
export declare function workspaceLabel(workspaceRoot: string, supplied?: string): string;
