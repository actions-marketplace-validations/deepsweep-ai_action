/**
 * Pinned-entity extraction for MCP tool-description pinning (S1.4 AC3,
 * detection-only). ADR-003:
 *  - Pinned-entity key is the tuple (entityType, logicalName) — deliberately
 *    excluding `source`, so identity survives moves between allowlisted files.
 *  - `contentHash` is a canonical per-entity digest (RFC 8785-style
 *    canonicalization) so formatting-only edits raise no false drift, while
 *    any code-point change in a description does.
 *  - Secret redaction BEFORE hashing: env.* / headers.* VALUES are replaced
 *    with "<redacted>"; key NAMES are preserved and remain part of the pinned
 *    identity. Consequence: rotating a secret does not raise drift.
 *  - Endpoint-shaped env/header key NAMES raise a pin-time warning: changes
 *    to their values will not raise drift. Key-name matching only.
 *
 * TEAM-ADR-047 (the confirmation-oracle close-out) changed two things here.
 *
 * (1) REDACTION REACHES url/serverUrl AND args. It previously did not, and
 *     the file said so: "args are NOT redacted", "URLs are hashed UNREDACTED
 *     by design". A token passed as a CLI argument, and the userinfo/query of
 *     a private endpoint, therefore landed in a hash PREIMAGE — which leaks
 *     even when every rendered field is clean. Now: URL fields keep
 *     scheme+host+path (via the one audited redactUrl) and drop userinfo,
 *     query and fragment; args are redacted element-wise, preserving flag
 *     NAMES, public package specifiers and transport words (the attack-
 *     relevant semantics) while replacing secret-shaped VALUES. Same
 *     consequence as env: rotating a redacted value raises no drift.
 *
 * (2) THE DIGEST IS KEYED. Redaction alone cannot close a confirmation
 *     oracle, because the highest-value preimages have nothing to redact — a
 *     hostname, a repo basename, `@modelcontextprotocol/server-github`, a
 *     tool description naming a customer's systems. Those are all guessable,
 *     and an unkeyed SHA-256 lets any holder of the digest confirm a guess.
 *     `contentHash` is now HMAC-SHA256 under an out-of-workspace key
 *     (pinkey.ts): byte-stable within an installation, so drift detection is
 *     untouched, and useless to anyone who does not hold the key.
 *
 * Reads local files only via safeRead (ADR-002 containment); no execution,
 * no network.
 */
import type { ReviewWarning } from "./types.js";
import { type PinKey } from "./pinkey.js";
/** Fixed allowlist of MCP config sources pinned into the baseline (ADR-002). */
export declare const PIN_SOURCES: readonly [".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".windsurf/mcp_config.json"];
/** Fixed placeholder substituted for secret-bearing values before hashing. */
export declare const REDACTED_PLACEHOLDER = "<redacted>";
export type PinnedEntityType = "mcpServer" | "toolDescription";
export interface PinnedEntity {
    entityType: PinnedEntityType;
    /** e.g. "github" (mcpServer) or "github/create_pr" (toolDescription). */
    logicalName: string;
    /** Workspace-relative config path the entity was found in. */
    source: string;
    /** Keyed digest of the REDACTED, canonicalized entity definition. */
    contentHash: string;
}
export interface PinExtraction {
    /** Sorted by (entityType, logicalName, source) for determinism. */
    entities: PinnedEntity[];
    /** Pin-time warnings: endpoint-shaped keys, secret-shaped args, duplicate keys. */
    warnings: ReviewWarning[];
    /** MCP config sources found (workspace-relative). */
    sources: string[];
    /** Non-secret id of the key these contentHashes were computed under. */
    pinKeyId: string;
}
/**
 * Redact ONE command-line argument before it reaches a hash preimage
 * (TEAM-ADR-047). The rule is deliberately value-shaped rather than
 * blanket, because args carry the drift signal that matters most — which
 * package a server runs, which transport, which flag:
 *
 *  - URL-shaped anywhere in the arg  → redactUrl (scheme+host+path survive;
 *    userinfo, query and fragment never enter the preimage);
 *  - `NAME=VALUE` / `--flag=VALUE`   → NAME kept verbatim, VALUE redacted
 *    when secret-shaped (a flag name is itself a strong drift signal);
 *  - a bare flag (`-y`, `--transport`) → kept verbatim, never a secret;
 *  - any other positional value      → redacted when secret-shaped, else
 *    kept (package specifiers, paths, transport words).
 *
 * RESIDUAL, stated rather than papered over: a positional secret with no
 * secret shape and no recognisable prefix (`hunter2`) is not detected by the
 * heuristic and stays in the preimage. That is why the digest is ALSO keyed —
 * the two defences are independent, and neither is claimed to be sufficient
 * alone.
 */
export declare function redactArg(arg: unknown): unknown;
/**
 * A hook COMMAND LINE, redacted token-wise for a rendered surface.
 *
 * WHY THIS EXISTS. `claude.ts` carried the comment "the command string is
 * config the operator wrote, not a secret (sanitized at every render choke
 * point anyway)". It was not sanitized anywhere. Measured 2026-08-23 with a
 * planted bearer token on a `.claude/settings.json` PreToolUse hook: the
 * command reached `review.md` once, `review.json` four times and
 * `studio.html` three times, verbatim. `review.md` is the artifact a founder
 * hand-delivers to a client during a paid engagement.
 *
 * The delivery runbook's answer was "hand-edit review.md and replace every
 * hook command line" — a manual step, on a deliverable, protecting someone
 * else's credential, performed under time pressure. This makes it automatic.
 *
 * The finding must stay ACTIONABLE. "A pre-tool hook pipes a bearer token to
 * an internal host" is the finding; the token itself is never the finding. So
 * this redacts token-wise via the already-audited `redactArg` rather than
 * masking the whole string — the reader still sees the binary, the flags and
 * the destination.
 *
 * Deliberately NOT a secret scanner. It reuses one predicate so there is one
 * place to improve, and it over-redacts rather than under-redacts: the literal
 * word "Bearer" is masked because `looksSecretShaped` matches it, which is
 * noise, not exposure.
 */
export declare function redactCommandLine(command: string): string;
/**
 * Redaction-before-hashing for a pinned definition (the ONE seam; extended
 * by TEAM-ADR-047, never rewritten):
 *  - env.* / headers.* VALUES → fixed placeholder, key NAMES preserved
 *    (presence-and-key-names-only invariant, ADR-002/ADR-003) — unchanged;
 *  - url / serverUrl → scheme + host + path only, via the one audited
 *    redactUrl already applied to every report surface;
 *  - args → element-wise per redactArg above.
 * `command` is preserved verbatim: it is the strongest drift signal a stdio
 * server has, it is not a credential field, and its guessability is answered
 * by the key rather than by redaction.
 * Applied to tool records as well as server definitions — the per-tool
 * digests previously canonicalized with NO redaction pass at all.
 */
export declare function redactServerDefinition(def: Record<string, unknown>): Record<string, unknown>;
/**
 * Extract pinned entities from the fixed MCP config allowlist.
 * Pure function of workspace file contents; deterministic ordering.
 */
export declare function extractPins(workspaceRoot: string, key?: PinKey): PinExtraction;
