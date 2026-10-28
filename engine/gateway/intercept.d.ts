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
 * A call the gateway refuses BEFORE policy (kill switch, tool drift) is
 * recorded by `recordToolRefusal` as `gateway.tool_refused` (TEAM-ADR-069).
 * Every entry is signed per TEAM-ADR-028 when a host-injected key is present.
 */
import { type AuthorizeResult } from "../api/authorize.js";
import { type LedgerEntry } from "../review/ledger.js";
import { type LedgerSigningKey } from "../review/ledger-sign.js";
import { type ApprovalBinding } from "./approval.js";
import { type Recorded } from "./record.js";
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
    /** When callEntry is "corrupt": why the call entry was not written (path and cause), for the operator. The caller says which of this decision's other entries are on the ledger. */
    readonly unrecorded?: string;
    /**
     * The call entry IS on the ledger, and something after it failed: its
     * signature, the approval.consumed signature, or storing the approval
     * token. The entry is the record and the gateway does what it says
     * (TEAM-ADR-069 fix pass 1, M2); this says what is missing.
     */
    readonly note?: string;
}
export declare function resourceFor(serverName: string, toolName: string): string;
/**
 * Decide + record ONE tool call. Never throws on policy grounds, nor for a
 * record that cannot be written (TEAM-ADR-069 fix pass 2, m-a): that is
 * reported in `callEntry: "corrupt"` with `unrecorded`, and the action the
 * policy decided is kept, so a denial is still answered as a denial.
 * Containment errors and anything that is not a store failure propagate.
 */
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
/**
 * Record the upstream's answer, chained to the call entry. Content → hash
 * only. The transports use this form: a refusal or a missing signature is
 * reported, never thrown, because the call already ran and its answer must
 * still reach the agent (TEAM-ADR-069 fix pass 1).
 */
export declare function recordToolResultEntry(p: ResultParams): Recorded;
/** Record the upstream's answer, chained to the call entry. Content → hash only. A refusal is "corrupt"; a signature failure throws. */
export declare function recordToolResult(p: ResultParams): LedgerEntry | "corrupt";
/** Why the gateway refused a call before asking the policy (TEAM-ADR-069 Decision 2). A closed vocabulary. */
export type RefusalReason = "killed" | "drifted";
/** The call a refusal is about, plus why. `switchSource` travels with "killed" and only with it. */
export type RefusalParams = {
    readonly workspaceRoot: string;
    readonly principal: string | null;
    readonly serverName: string;
    readonly toolName: string;
    readonly args: unknown;
    readonly nowIso: string;
    readonly key?: LedgerSigningKey | undefined;
} & ({
    readonly reason: "killed";
    readonly switchSource: "workspace" | "user" | "unreadable";
} | {
    readonly reason: "drifted";
});
/**
 * Record a refusal the gateway made before policy: the kill switch, or a
 * drifted tool (TEAM-ADR-069 Decision 2). `gateway.tool_refused` carries the
 * same digests as `gateway.tool_call` (so a selective disclosure of the
 * server, tool, principal or arguments verifies against it) plus the closed
 * reason code, and for the kill switch which file refused. No
 * `policy.decision` precedes it: the policy was never asked. Frozen by
 * contracts/schemas/tool-refusal-record.v1.json.
 */
export declare function recordToolRefusal(p: RefusalParams): Recorded;
