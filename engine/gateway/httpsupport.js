/**
 * HTTP-transport helpers (TEAM-ADR-040): parse a JSON or SSE response body far
 * enough to (a) pin a tools/list result and (b) hash a tools/call result. Kept
 * out of http.ts so the transport file stays about sockets and this stays about
 * MCP semantics — and so both are unit-tested directly.
 */
import { parseFrame } from "./frames.js";
import { observeToolList as observe } from "./toolpins.js";
import { recordToolResult } from "./intercept.js";
import { sha256Hex } from "../review/canonical.js";
/** Extract the JSON-RPC result object from a Streamable-HTTP body: a bare JSON frame, or the last `data:` line of an SSE stream. */
export function frameFromBody(body) {
    const text = body.toString("utf8").trim();
    if (text.length === 0)
        return undefined;
    const direct = parseFrame(text);
    if (direct !== undefined)
        return { result: direct.result, error: direct.error, streamed: false };
    // SSE: find the last non-empty `data:` payload that parses as a JSON-RPC frame.
    let found;
    for (const line of text.split(/\r?\n/)) {
        const m = /^data:\s?(.*)$/.exec(line);
        if (m === null || m[1] === undefined || m[1].length === 0)
            continue;
        const f = parseFrame(m[1]);
        if (f !== undefined && (f.result !== undefined || f.error !== undefined))
            found = { result: f.result, error: f.error };
    }
    return found === undefined ? undefined : { ...found, streamed: true };
}
/** Pin a tools/list response body (TEAM-ADR-039) over HTTP. */
export function observeToolList(workspaceRoot, serverName, body, nowIso, key, diag) {
    const f = frameFromBody(body);
    const tools = f?.result !== undefined ? f.result.tools : undefined;
    if (Array.isArray(tools)) {
        const r = observe(workspaceRoot, serverName, tools, nowIso, key);
        for (const t of r.drifted)
            diag(`tool drift ${serverName}/${t}`);
    }
}
/** Record a tools/call result from an HTTP response body. A stream is hashed over its raw bytes with a `streamed` marker. */
export function recordToolResultOverBody(workspaceRoot, callEntryHash, body, now, t0, key) {
    const f = frameFromBody(body);
    if (f !== undefined && !f.streamed) {
        recordToolResult({ workspaceRoot, callEntryHash, result: f.error !== undefined ? f.error : f.result, isError: f.error !== undefined, latencyMs: now.getTime() - t0, nowIso: now.toISOString(), key });
        return;
    }
    // SSE or unparseable body: hash the raw bytes so the result is still committed, marked streamed.
    recordToolResult({ workspaceRoot, callEntryHash, result: { streamedBodyHash: sha256Hex(body.toString("utf8")) }, isError: false, latencyMs: now.getTime() - t0, nowIso: now.toISOString(), key });
}
