/**
 * MCP JSON-RPC 2.0 frame codec for the evidence gateway (TEAM-ADR-036).
 *
 * The gateway sits transparently between an agent and an MCP server. It
 * NEVER rewrites a frame it forwards — observe / enforce / record only. That
 * is a legal posture, not just a design one: a layer that mutates model or
 * tool behaviour risks "provider" reclassification under the AI Act; a layer
 * that only executes customer-authored policy and records what happened does
 * not. So this module parses just enough to recognise `tools/call` (the
 * governed verb) and to mint the JSON-RPC error the gateway itself answers
 * with when a call is blocked. Everything else is opaque bytes.
 *
 * Zero dependencies (node builtins only), pure, deterministic.
 */
/** JSON-RPC error codes the GATEWAY answers with (server-defined range). */
export const GATEWAY_ERROR_DENIED = -32040;
export const GATEWAY_ERROR_APPROVAL_REQUIRED = -32041;
export const GATEWAY_ERROR_TOOL_DRIFTED = -32042;
export const APPROVAL_META_KEY = "deepsweep/approval";
/** Parse one newline-delimited frame. Non-JSON / non-object → undefined (forwarded opaquely). */
export function parseFrame(line) {
    const text = line.trim();
    if (text.length === 0)
        return undefined;
    try {
        const v = JSON.parse(text);
        if (typeof v !== "object" || v === null || Array.isArray(v))
            return undefined;
        return v;
    }
    catch {
        return undefined;
    }
}
/** The governed verb. Returns the call tuple or undefined when the frame is anything else. */
export function toolCallOf(frame) {
    if (frame.method !== "tools/call")
        return undefined;
    const p = frame.params;
    if (typeof p !== "object" || p === null || Array.isArray(p))
        return undefined;
    const rec = p;
    const name = rec["name"];
    if (typeof name !== "string" || name.length === 0)
        return undefined;
    const meta = rec["_meta"];
    let approvalToken;
    if (typeof meta === "object" && meta !== null && !Array.isArray(meta)) {
        const t = meta[APPROVAL_META_KEY];
        if (typeof t === "string" && t.length > 0)
            approvalToken = t;
    }
    return {
        id: frame.id === undefined ? null : frame.id,
        name,
        args: rec["arguments"] === undefined ? {} : rec["arguments"],
        approvalToken,
    };
}
/** True when this frame is a response (result or error) — pairs with a forwarded request id. */
export function isResponse(frame) {
    return frame.method === undefined && (frame.result !== undefined || frame.error !== undefined);
}
/** The gateway's own refusal. `data` carries SHAPE only (rule name, token) — never args. */
export function gatewayError(id, code, message, data) {
    const error = { code, message };
    if (data !== undefined)
        error["data"] = data;
    return JSON.stringify({ jsonrpc: "2.0", id, error });
}
