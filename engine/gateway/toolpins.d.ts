import { type LedgerEntry } from "../review/ledger.js";
import { type LedgerSigningKey } from "../review/ledger-sign.js";
export declare const TOOL_PINS_FILE = "tool-pins.json";
export interface ToolPin {
    readonly hash: string;
    readonly pinnedAt: string;
    readonly status: "pinned" | "drifted";
    /** The hash most recently observed when status is "drifted". */
    readonly seenHash?: string;
}
export interface ToolPinsFile {
    readonly schemaVersion: 1;
    readonly servers: Record<string, Record<string, ToolPin>>;
}
/** Read the pin store. Malformed → undefined (caller fails closed by treating every tool as unpinnable). */
export declare function readToolPins(workspaceRoot: string): ToolPinsFile | undefined;
/** Canonical identity of what a tool CLAIMS to be. Byte-preserving (ADR-003): any code-point change is drift. */
export declare function toolDescriptionHash(tool: Record<string, unknown>): string;
export interface ObserveResult {
    readonly pinned: readonly string[];
    readonly unchanged: readonly string[];
    readonly drifted: readonly string[];
    readonly entries: readonly LedgerEntry[];
}
/**
 * Observe one `tools/list` result. First sight pins (TOFU); a changed hash
 * marks the tool drifted (breaker tripped) and records `gateway.tool_drift`;
 * an already-drifted tool that changes AGAIN updates seenHash silently
 * (still tripped). Returns which tools fell into which bucket.
 */
export declare function observeToolList(workspaceRoot: string, serverName: string, tools: readonly unknown[], nowIso: string, key?: LedgerSigningKey): ObserveResult;
/** Is the breaker tripped for this tool? Unpinned tools are NOT tripped (a call before any tools/list is governed by policy alone). Unreadable store → tripped (fail closed). */
export declare function isToolTripped(workspaceRoot: string, serverName: string, toolName: string): boolean;
/** Human re-pins a drifted tool to what the server currently claims (its last seen hash). Ledger event `gateway.tool_repinned`. */
export declare function repinTool(workspaceRoot: string, serverName: string, toolName: string, approver: string, nowIso: string, key?: LedgerSigningKey): {
    readonly ok: boolean;
    readonly reason?: "unreadable" | "unknown-tool" | "not-drifted";
};
