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
import { GATEWAY_ERROR_APPROVAL_REQUIRED, GATEWAY_ERROR_DENIED, GATEWAY_ERROR_TOOL_DRIFTED, gatewayError, toolCallOf } from "./frames.js";
import { interceptToolCall } from "./intercept.js";
import { isToolTripped } from "./toolpins.js";
/** Decide one already-parsed frame. Pure w.r.t. transport; performs the ledger side effects of a governed call. */
export function decideFrame(frame, ctx) {
    const call = toolCallOf(frame);
    if (call === undefined)
        return { kind: "pass", pinOnResponse: frame.method === "tools/list" };
    if (isToolTripped(ctx.workspaceRoot, ctx.serverName, call.name)) {
        return { kind: "reject", reason: "drifted", tool: call.name, errorFrame: gatewayError(call.id, GATEWAY_ERROR_TOOL_DRIFTED, "deepsweep: tool description drifted since it was pinned — refused until a human re-pins (deepsweep-gateway repin)", { tool: call.name }) };
    }
    const r = interceptToolCall({
        workspaceRoot: ctx.workspaceRoot,
        principal: ctx.principal,
        serverName: ctx.serverName,
        toolName: call.name,
        args: call.args,
        approvalToken: call.approvalToken,
        userConfigRoot: ctx.userConfigRoot,
        nowIso: ctx.nowIso,
        key: ctx.key,
    });
    if (r.action === "blocked") {
        return { kind: "reject", reason: "blocked", tool: call.name, rule: r.authorize.ruleLabel, errorFrame: gatewayError(call.id, GATEWAY_ERROR_DENIED, "deepsweep: tools/call denied by policy", { rule: r.authorize.ruleLabel }) };
    }
    if (r.action === "held") {
        const data = { rule: r.authorize.ruleLabel };
        if (r.approvalToken !== undefined)
            data["approvalToken"] = r.approvalToken;
        return { kind: "reject", reason: "held", tool: call.name, rule: r.authorize.ruleLabel, errorFrame: gatewayError(call.id, GATEWAY_ERROR_APPROVAL_REQUIRED, "deepsweep: human approval required — retry with the approval token in params._meta[\"deepsweep/approval\"] once granted", data) };
    }
    return { kind: "forward", callEntryHash: r.callEntry === "corrupt" ? null : r.callEntry.entryHash, intercept: r };
}
