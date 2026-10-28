/**
 * Transport-independent governance decision for ONE inbound MCP frame
 * (TEAM-ADR-040). Both the stdio gateway and the Streamable-HTTP gateway call
 * this so the two transports cannot drift in what they allow, deny, hold or
 * pin — the decision is defined once, tested once.
 *
 * A frame is classified into exactly one disposition:
 *   - "pass"     not a governed verb (or tools/list): forward untouched. If it
 *                is a tools/list REQUEST, `pinOnResponse` is true so the caller
 *                pins the response.
 *   - "forward"  a tools/call the policy permits, ALREADY RECORDED: forward it
 *                (the caller must remember callEntryHash to attribute the result).
 *                There is no forward without a call entry (TEAM-ADR-069).
 *   - "reject"   deny / hold / rug-pull-drift / kill switch, a tools/call the
 *                gateway cannot decide (TEAM-ADR-068), or one it cannot record
 *                (TEAM-ADR-069): DO NOT forward; the caller writes `errorFrame`
 *                back to the agent verbatim.
 *
 * Every decision about a named tools/call is on the ledger (TEAM-ADR-069): a
 * kill-switch state the ledger did not record is recorded first, as observed;
 * kill-switch and drift refusals are recorded as `gateway.tool_refused`; a
 * policy decision is recorded by the intercept loop. When the ledger cannot be
 * read or appended, nothing is forwarded or spent, in every mode; the refusal
 * says why in `unrecorded`, which the transports print as a diagnostic.
 *
 * A JSON-RPC BATCH never reaches decideFrame: `refuseBatch` answers it whole
 * (TEAM-ADR-068), so "every call is a policy decision" (TEAM-ADR-036
 * Decision 3) cannot be bypassed by wrapping a call in an array. Nor do bytes
 * the gateway cannot parse, or a message over the size cap: the transports
 * answer those with PARSE_ERROR_ANSWER and OVERSIZE_ANSWER (Addendum 1).
 */
import { type McpFrame } from "./frames.js";
import { type InterceptResult } from "./intercept.js";
import type { LedgerSigningKey } from "../review/ledger-sign.js";
export interface DecideContext {
    readonly workspaceRoot: string;
    readonly serverName: string;
    readonly principal: string | null;
    readonly userConfigRoot?: string | undefined;
    readonly nowIso: string;
    readonly key?: LedgerSigningKey | undefined;
}
export type Disposition = {
    readonly kind: "pass";
    readonly pinOnResponse: boolean;
} | {
    readonly kind: "forward";
    readonly callEntryHash: string;
    readonly intercept: InterceptResult;
    readonly tool: string;
    /** The call entry is on the ledger, and something else is missing (a signature); for the operator's diagnostic (TEAM-ADR-069 fix pass 1, M2). */
    readonly note?: string;
} | {
    readonly kind: "reject";
    readonly reason: "drifted" | "blocked" | "held" | "killed" | "undecidable" | "unrecordable";
    readonly errorFrame: string;
    readonly tool: string;
    readonly rule?: string;
    /** Why this decision is NOT on the ledger, for the operator's diagnostic line (TEAM-ADR-069). Absent when it is recorded, or needs no record (undecidable). */
    readonly unrecorded?: string;
    /** The decision IS on the ledger, and something else is missing (a signature, an approval token). */
    readonly note?: string;
};
/** The gateway's answer to agent bytes it cannot parse as UTF-8 JSON: JSON-RPC's own parse error, id null (TEAM-ADR-068 Addendum 1). */
export declare const PARSE_ERROR_ANSWER: string;
/** The gateway's answer to an agent message larger than its size cap, id null (TEAM-ADR-068 Addendum 1). */
export declare const OVERSIZE_ANSWER: string;
/** The gateway's answer to an HTTP body that declares a charset other than UTF-8, id null (TEAM-ADR-068 Addendum 1). */
export declare const CHARSET_ANSWER: string;
/**
 * Room a decision needs on the ledger before it starts (TEAM-ADR-069 fix pass
 * 1, M1): the observed-switch, decision, call and approval entries, and the
 * result entry of a call that is forwarded, with margin. A call is not
 * forwarded unless its result can still be recorded; appendLedgerEntry
 * refuses anything past the cap itself, so the file never passes it.
 */
export declare const LEDGER_DECISION_HEADROOM_BYTES: number;
/** Decide one already-parsed frame. Pure w.r.t. transport; performs the ledger side effects of a governed call. */
export declare function decideFrame(frame: McpFrame, ctx: DecideContext): Disposition;
/**
 * The operator's diagnostic line for a refusal, shared by both transports so
 * they cannot word it differently (TEAM-ADR-040 Decision 1): the reason, the
 * server and tool, the deciding rule, and, when the refusal is not on the
 * ledger, why (TEAM-ADR-069).
 */
export declare function rejectDiagnostic(d: Extract<Disposition, {
    kind: "reject";
}>, serverName: string): string;
/** The operator's diagnostic line for a forwarded call, when something about its record is missing (fix pass 1, M2); otherwise undefined. */
export declare function forwardDiagnostic(d: Extract<Disposition, {
    kind: "forward";
}>, serverName: string): string | undefined;
/** The gateway's whole answer to a JSON-RPC batch (TEAM-ADR-068). */
export interface BatchRefusal {
    /** Written back verbatim over stdio: a batch reply with one -32044 error per request id, or ONE id-null error. */
    readonly errorFrame: string;
    /** How many messages were refused (the transports add it to `blocked`): the request count, or 1 for a batch with no request. */
    readonly refused: number;
    /**
     * "per-id": `errorFrame` answers each request. "no-request": the batch holds
     * only notifications or responses, or nothing; Streamable HTTP answers such
     * input 202 with no body. "too-large": one error per id would outgrow the
     * size cap, so ONE id-null error answers the batch (Addendum 1).
     */
    readonly answer: "per-id" | "no-request" | "too-large";
}
/**
 * Refuse a JSON-RPC batch WHOLE, in every mode (TEAM-ADR-068). Nothing in it
 * is relayed. Deciding each element and relaying only the permitted ones
 * would rewrite the frame the agent sent (TEAM-ADR-036 Decision 2), and MCP
 * 2025-06-18 removed batching, so current clients send one message at a
 * time. Each request gets its own error, as JSON-RPC 2.0 answers a batch; a
 * notification gets none. A batch with no request still gets one id-null
 * error, so a refusal is never silent. The answer never outgrows `maxBytes`
 * (Addendum 1): a small request can carry a long answer, so a batch whose
 * per-id answer would exceed the cap gets ONE id-null error instead.
 */
export declare function refuseBatch(elements: readonly unknown[], maxBytes?: number): BatchRefusal;
