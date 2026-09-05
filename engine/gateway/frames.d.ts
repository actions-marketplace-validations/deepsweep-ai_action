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
export interface McpFrame {
    readonly jsonrpc?: unknown;
    readonly id?: string | number | null;
    readonly method?: string;
    readonly params?: unknown;
    readonly result?: unknown;
    readonly error?: unknown;
}
export interface ToolCall {
    readonly id: string | number | null;
    readonly name: string;
    readonly args: unknown;
    /** Resumable approval token carried in `params._meta["deepsweep/approval"]`. */
    readonly approvalToken: string | undefined;
}
/** JSON-RPC error codes the GATEWAY answers with (server-defined range). */
export declare const GATEWAY_ERROR_DENIED = -32040;
export declare const GATEWAY_ERROR_APPROVAL_REQUIRED = -32041;
export declare const GATEWAY_ERROR_TOOL_DRIFTED = -32042;
export declare const APPROVAL_META_KEY = "deepsweep/approval";
/** Parse one newline-delimited frame. Non-JSON / non-object → undefined (forwarded opaquely). */
export declare function parseFrame(line: string): McpFrame | undefined;
/** The governed verb. Returns the call tuple or undefined when the frame is anything else. */
export declare function toolCallOf(frame: McpFrame): ToolCall | undefined;
/** True when this frame is a response (result or error) — pairs with a forwarded request id. */
export declare function isResponse(frame: McpFrame): boolean;
/** The gateway's own refusal. `data` carries SHAPE only (rule name, token) — never args. */
export declare function gatewayError(id: string | number | null, code: number, message: string, data?: Record<string, string>): string;
