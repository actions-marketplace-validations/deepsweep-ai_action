/**
 * The intercept–evaluate–record loop (TEAM-ADR-036) — the gateway's one
 * behavioural decision, kept pure of transport so stdio and HTTP share it and
 * so it is unit-tested without spawning anything.
 *
 * For every `tools/call`:
 *   1. `authorizeAction` (ADR-009/010) decides allow / deny / require-approval
 *      and appends its own `policy.decision` ledger entry (hashes only).
 *   2. a `gateway.tool_call` entry binds that decision to the call: server /
 *      tool / args as SHA-256 digests, the decision, and how the gateway ACTED
 *      (forwarded · blocked · held · approved). Content is never stored — the
 *      customer's own vault holds it; the compiler verifies disclosures
 *      against these hashes at packet time (selective disclosure).
 *   3. `require-approval` → deny-with-resumable-token (approval.ts). A retry
 *      carrying an approved token for the SAME tuple is forwarded.
 *   4. When the upstream answers, `gateway.tool_result` records resultHash,
 *      latency and isError, chained to the call entry.
 * Every entry is signed per TEAM-ADR-028 when a host-injected key is present.
 */
import { type AuthorizeResult } from "../api/authorize.js";
import { type LedgerEntry } from "../review/ledger.js";
import { type LedgerSigningKey } from "../review/ledger-sign.js";
import { type ApprovalBinding } from "./approval.js";
export type GatewayAction = "forwarded" | "blocked" | "held" | "approved";
export interface InterceptParams {
    readonly workspaceRoot: string;
    /** Neutral agent identifier (ADR-005); null = unattributed. */
    readonly principal: string | null;
    readonly serverName: string;
    readonly toolName: string;
    readonly args: unknown;
    readonly approvalToken?: string | undefined;
    readonly userConfigRoot?: string | undefined;
    readonly nowIso: string;
    readonly key?: LedgerSigningKey | undefined;
}
export interface InterceptResult {
    readonly authorize: AuthorizeResult;
    readonly action: GatewayAction;
    /** Present only when action === "held": the plaintext token, returned to the agent ONCE. */
    readonly approvalToken?: string;
    readonly binding: ApprovalBinding;
    readonly callEntry: LedgerEntry | "corrupt";
}
export declare function resourceFor(serverName: string, toolName: string): string;
/** Decide + record ONE tool call. Never throws on policy grounds; store-containment errors propagate (exit-3 class). */
export declare function interceptToolCall(p: InterceptParams): InterceptResult;
export interface ResultParams {
    readonly workspaceRoot: string;
    readonly callEntryHash: string;
    readonly result: unknown;
    readonly isError: boolean;
    readonly latencyMs: number;
    readonly nowIso: string;
    readonly key?: LedgerSigningKey | undefined;
}
/** Record the upstream's answer, chained to the call entry. Content → hash only. */
export declare function recordToolResult(p: ResultParams): LedgerEntry | "corrupt";
