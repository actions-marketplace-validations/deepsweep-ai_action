import type { ArgCredentialHit } from "./credentials.js";
import type { UnreadableReason } from "../read.js";
import type { ReviewWarning, SourceInspectionStatus } from "../types.js";
import type { DetectorResult } from "./detector.js";
export declare function asRecord(v: unknown): Record<string, unknown> | undefined;
export declare function asString(v: unknown): string | undefined;
/**
 * An EMPTY config document is "nothing configured", NOT "malformed".
 *
 * FOUND 2026-08-15 on a real Antigravity install: it ships
 * `~/.gemini/config/mcp_config.json` as a ZERO-BYTE file on first run. Every
 * detector here fed that straight into `parseTolerantJson`, got `undefined`,
 * and raised "Configuration is malformed" — so every Antigravity user's very
 * first review would have opened with a false alarm about a file they had
 * never touched.
 *
 * NONE of the seven detector families guarded this, so the defect was latent
 * across the whole engine and Antigravity merely made it reachable: it is the
 * only assistant we cover that creates the file eagerly rather than on first
 * use.
 *
 * This matters more than one spurious line. A warning channel that cries wolf
 * on a clean machine is a warning channel operators learn to skip, and the
 * S1.14 absent-evidence guarantee depends on those warnings being believed.
 * Fix the false alarms first — a muted guard is worse than no guard.
 *
 * A blank document is reported as REVIEWED with no capabilities, which is the
 * truth: we read it, and it grants nothing.
 */
export declare function isBlankDocument(text: string): boolean;
export declare function malformedWarning(source: string): ReviewWarning;
/**
 * S1.14 absent-evidence observability: an agent-config file that is present
 * but UNREADABLE must never degrade to silence — its capabilities are simply
 * missing from the review, with nothing telling the operator so. This
 * warning carries METADATA ONLY: the allowlisted path plus a reason class.
 * Never file content, and never a guess at what the capabilities might be.
 */
export declare function unreadableWarning(source: string, reason: UnreadableReason): ReviewWarning;
/** The same warning for a DIRECTORY that could not be enumerated (TEAM-ADR-072 code). */
export declare function directoryUnreadableWarning(source: string, reason: UnreadableReason): ReviewWarning;
export type InspectionScope = "workspace" | "user";
/**
 * Stamp how far one source was inspected, at the read itself (TEAM-ADR-072).
 * Metadata only: it never changes what the detector reports, and the engine
 * keeps the strongest limitation when a source is observed more than once.
 */
export declare function inspect(out: DetectorResult, source: string, status: SourceInspectionStatus, scope?: InspectionScope, reason?: UnreadableReason): void;
/**
 * A presence-only check that records what it saw (TEAM-ADR-072, X-583): present
 * is "presence_only", a refusal is "unreadable" with its reason, and absence
 * (or the wrong inode type) records nothing. Returns what `exists` returned.
 */
export declare function presentOrRecord(out: DetectorResult, root: string, rel: string, expect?: "file" | "directory"): boolean;
/**
 * A structured JSON reader's verdict: "parsed" only when the document parsed
 * to the object it expects; a blank document is "blank" (nothing configured);
 * anything else is "parse_failed", whether or not the detector warns about it.
 */
export declare function jsonInspection(text: string, parsedAsObject: boolean): SourceInspectionStatus;
/** A text pattern reader's verdict: read, but never structurally parsed. */
export declare function textInspection(text: string): SourceInspectionStatus;
/**
 * Directory listing that cannot silently lose evidence.
 *
 * Extends the S1.14 warning contract from files to directories: an
 * ENUMERABLE directory yields its names, an ABSENT one yields none, and a
 * PRESENT-BUT-UNREADABLE one yields none *plus a warning*. Collapsing the
 * last two — which `listDirNames` alone does — is what let `chmod 000` on a
 * rules directory delete a capability from the review and raise the score.
 *
 * Warnings are deduplicated by source so a nested walk cannot emit the same
 * path twice.
 */
export declare function dirNamesOrWarn(workspaceRoot: string, relPath: string, out: DetectorResult, opts?: {
    readonly fileIsAnEntry?: boolean;
}): string[];
export interface McpServerEntry {
    /** Number of launch args (shape only — arg contents never leave util). */
    argCount?: number;
    /** ADR-013 credential-shape hits over the args (pattern + index only). */
    credentialHits?: ArgCredentialHit[];
    /** Cleartext non-loopback http transport, and where it was declared. */
    cleartextHttp?: "url" | "args";
    name: string;
    command?: string;
    url?: string;
}
/**
 * The ADR-013 credential/transport fragment for one MCP server, flattened into
 * the primitive record a `Capability.detail` must be.
 *
 * THIS EXISTS BECAUSE FOUR OF SIX READERS FORGOT IT. `mcpServersFrom` computed
 * `credentialHits` for every family, and only `mcp.ts` and the windsurf
 * USER-scope loop ever read them back — so a plaintext database URL in an MCP
 * server's args was reported in `.mcp.json`, `.cursor/mcp.json` and
 * `.vscode/mcp.json`, and silently dropped in `.trae/mcp.json`,
 * `.agents/mcp_config.json` and `.windsurf/mcp_config.json` (measured
 * 2026-08-16, TEAM-ADR-035). Those last three are the editors most of our
 * users actually run.
 *
 * One owner, so a family added tomorrow cannot quietly omit it: spread this
 * into `detail` instead of hand-assembling the fields.
 *
 * Emits pattern NAMES, indexes and counts only — never an argument's content.
 */
export declare function mcpCredentialDetail(server: McpServerEntry): Record<string, string | number | boolean>;
/**
 * Redact a server URL before it can reach any report surface (text, --json,
 * future cloud payloads): keep scheme + host + path ONLY. Userinfo
 * credentials, query strings (tokens), and fragments are dropped.
 */
export declare function redactUrl(raw: string): string;
/**
 * Extract MCP server entries from the common `mcpServers`/`servers` map shape
 * shared by Cursor, VS Code, Claude Code, and Windsurf MCP configs.
 * Env blocks are never surfaced. Args are reviewed IN-MODULE for credential
 * SHAPE and transport (ADR-013) — pattern kinds, indexes, and counts leave;
 * arg contents never do. URLs are redacted (scheme + host + path) before
 * leaving this module.
 */
export declare function mcpServersFrom(json: unknown): McpServerEntry[];
/** Cap + join a list of names for a detail field (first `max`, sorted input). */
export declare function nameList(names: string[], max?: number): string;
/** Visible (non-dot) entry names — used for rule/instruction directories. */
export declare function visibleNames(names: string[]): string[];
