/**
 * Shared building blocks for the tool-family detectors added on 2026-08-19
 * (Kiro, Cline, Roo Code, Continue, Gemini, Amazon Q Developer, Codex, Aider —
 * the complete list of tools our users are measured in, per the founder).
 *
 * Every existing family (antigravity/trae/windsurf/…) re-implements the same
 * three reads: a JSON `mcpServers` document (workspace and user scope), a
 * rules DIRECTORY read as names only, and an instruction FILE read for
 * presence. Four of six of those copies forgot the ADR-013 credential detail
 * (TEAM-ADR-035). So the eight new families share ONE implementation of each
 * read here — same contained reader (ADR-002/ADR-014), same degrade-to-warning
 * rules, same names-only discipline — and a family added tomorrow cannot
 * quietly omit a step. Existing detectors are deliberately left as they are.
 */
import { type ProbeResult } from "../read.js";
import type { DetectorResult } from "./detector.js";
import type { Capability, CapabilityKind } from "../types.js";
export type Scope = "workspace" | "user";
export interface McpEmitOptions {
    /** Product name as it appears in summaries ("Kiro", "Roo Code", …). */
    readonly tool: string;
    readonly scope: Scope;
    /** User-scope reach clause, e.g. " in EVERY workspace". */
    readonly reach?: string;
}
/** Emit mcpToolAccess (+ shellExecution for local launchers) for a standard mcpServers map. */
export declare function emitMcpServers(json: unknown, source: string, out: DetectorResult, opts: McpEmitOptions): void;
/**
 * Review one JSON document that may carry an mcpServers map. `probe` is the
 * already-executed contained read (workspace or user root); `source` is the
 * label recorded in reviewedSources/warnings ("~/"-prefixed for user scope).
 * Returns the parsed document (or undefined) so a family can read extra keys.
 */
export declare function reviewJsonMcpSource(probe: ProbeResult, source: string, out: DetectorResult, opts: McpEmitOptions): unknown;
export declare function reviewWorkspaceMcpJson(workspaceRoot: string, rel: string, out: DetectorResult, tool: string): unknown;
export declare function reviewUserMcpJson(userConfigRoot: string | undefined, rel: string, label: string, out: DetectorResult, tool: string, reach?: string): unknown;
export interface RulesDirOptions {
    readonly tool: string;
    /** Verb phrase pair for countNoun: ["rule file auto-applies", "rule files auto-apply"]. */
    readonly noun: readonly [string, string];
    /** What the rules do, appended after the noun: "workspace instructions to agent sessions". */
    readonly effect: string;
    readonly kind?: CapabilityKind;
    readonly scope?: Scope;
}
/** Names-only review of a rules/config directory → one agentInstructions capability. */
export declare function reviewRulesDir(root: string, rel: string, label: string, out: DetectorResult, opts: RulesDirOptions): string[];
/** Presence-only review of an instruction/config FILE → one capability (content never summarised). */
export declare function reviewPresence(workspaceRoot: string, rel: string, out: DetectorResult, capability: Omit<Capability, "resource" | "source"> & Partial<Pick<Capability, "resource">>): boolean;
/**
 * Minimal TOML table-header scan — NAMES only. Returns the `<id>` of every
 * `[mcp_servers.<id>]` table (Codex). No TOML parser ships in the engine
 * (zero runtime deps, ADR-002); names are all the review needs (ADR-002).
 */
export declare function tomlMcpServerNames(text: string): string[];
/** Top-level `key = "value"` (string) from a TOML document, before the first table header. */
export declare function tomlTopLevelString(text: string, key: string): string | undefined;
/** `key: true` at the top level of a simple YAML document (aider's flat config). */
export declare function yamlTopLevelTrue(text: string, key: string): boolean;
