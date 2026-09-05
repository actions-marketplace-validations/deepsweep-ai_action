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
 *   - "forward"  a tools/call the policy permits: forward, and record the call
 *                (the caller must remember callEntryHash to attribute the result).
 *   - "reject"   deny / hold / rug-pull-drift: DO NOT forward; the caller writes
 *                `errorFrame` back to the agent verbatim.
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
    readonly callEntryHash: string | null;
    readonly intercept: InterceptResult;
} | {
    readonly kind: "reject";
    readonly reason: "drifted" | "blocked" | "held";
    readonly errorFrame: string;
    readonly tool: string;
    readonly rule?: string;
};
/** Decide one already-parsed frame. Pure w.r.t. transport; performs the ledger side effects of a governed call. */
export declare function decideFrame(frame: McpFrame, ctx: DecideContext): Disposition;
