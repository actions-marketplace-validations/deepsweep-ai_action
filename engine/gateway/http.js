/**
 * Streamable-HTTP evidence gateway (TEAM-ADR-040) — the same intercept core as
 * the stdio gateway, for REMOTE MCP servers that never touch a developer's
 * machine (the enterprise case ADR-RGOV-006 §6b anticipated).
 *
 * Shape: the gateway is an MCP server to the agent and an MCP client to the
 * upstream. The agent POSTs a JSON-RPC request to the gateway; the gateway
 * runs `decideFrame` (shared with stdio, so the two transports cannot drift);
 * a permitted call is forwarded to the upstream over HTTP and the upstream's
 * response is recorded and relayed back; a denied/held/drifted call is
 * answered by the gateway itself and never leaves the boundary.
 *
 * Zero-egress note: the gateway opens exactly one outbound connection — to the
 * customer-configured upstream URL. It phones no home. Bind 127.0.0.1 by
 * default; the operator opts into a wider bind explicitly.
 *
 * v1 scope: JSON request → JSON response (the common Streamable-HTTP case). An
 * upstream that answers a tools/call with an SSE stream is relayed opaquely
 * but not parsed for the result hash — recorded honestly as `resultHash` over
 * the raw body with `isError:false` and a `streamed:true` marker. GET/SSE
 * session-open requests are proxied untouched (they carry no tools/call).
 */
import { createServer, request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { URL } from "node:url";
import { parseFrame } from "./frames.js";
import { relayChunk } from "./relay.js";
import { decideFrame } from "./decide.js";
import { observeToolList, recordToolResultOverBody } from "./httpsupport.js";
const DEFAULT_MAX_BODY = 8 * 1024 * 1024;
function readBody(req, max) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let size = 0;
        let over = false;
        req.on("data", (c) => { size += c.length; if (size > max) {
            over = true;
            return;
        } chunks.push(c); });
        req.on("end", () => resolve(over ? "too-large" : Buffer.concat(chunks)));
        req.on("error", reject);
    });
}
function forwardUpstream(upstreamUrl, reqUrl, method, headers, body, max) {
    const u = new URL(upstreamUrl);
    // Carry the agent request's query string onto the upstream endpoint (the MCP
    // path is the upstream URL's; the query is the agent's, e.g. session ids).
    const incoming = new URL(reqUrl, "http://local");
    if (incoming.search.length > 0)
        u.search = incoming.search;
    const doRequest = u.protocol === "https:" ? httpsRequest : httpRequest;
    const outHeaders = {};
    for (const [k, v] of Object.entries(headers))
        if (v !== undefined && k.toLowerCase() !== "host" && k.toLowerCase() !== "content-length")
            outHeaders[k] = v;
    if (body !== undefined)
        outHeaders["content-length"] = String(body.length);
    return new Promise((resolve, reject) => {
        const r = doRequest({ hostname: u.hostname, port: u.port, path: u.pathname + u.search, method, headers: outHeaders }, (res) => {
            const chunks = [];
            let size = 0;
            res.on("data", (c) => { size += c.length; if (size > max) {
                res.destroy();
                return;
            } chunks.push(c); });
            res.on("end", () => resolve({ status: res.statusCode ?? 502, headers: res.headers, body: Buffer.concat(chunks) }));
            res.on("error", reject);
        });
        r.on("error", reject);
        if (body !== undefined)
            relayChunk(r, body);
        r.end();
    });
}
export function startHttpGateway(o) {
    const diag = o.diag ?? (() => undefined);
    const max = o.maxBodyBytes ?? DEFAULT_MAX_BODY;
    const stats = { forwarded: 0, blocked: 0, held: 0 };
    const server = createServer((req, res) => {
        void (async () => {
            // Only POST carries JSON-RPC (tools/call). GET/DELETE (SSE open, session close) are proxied untouched.
            const raw = req.method === "POST" ? await readBody(req, max) : undefined;
            if (raw === "too-large") {
                res.writeHead(413).end("request too large");
                return;
            }
            const bodyText = raw !== undefined ? raw.toString("utf8") : undefined;
            const frame = bodyText !== undefined ? parseFrame(bodyText) : undefined;
            const ctxNow = o.now().toISOString();
            const d = frame !== undefined
                ? decideFrame(frame, { workspaceRoot: o.workspaceRoot, serverName: o.serverName, principal: o.principal, userConfigRoot: o.userConfigRoot, nowIso: ctxNow, key: o.key })
                : { kind: "pass", pinOnResponse: false };
            if (d.kind === "reject") {
                stats[d.reason === "held" ? "held" : "blocked"] += 1;
                diag(`${d.reason} ${o.serverName}/${d.tool}${d.rule ? ` rule=${d.rule}` : ""}`);
                res.writeHead(200, { "content-type": "application/json" }).end(d.errorFrame.trimEnd());
                return;
            }
            // Forward (a permitted tools/call) or pass (anything else) to the upstream.
            const t0 = o.now().getTime();
            let reply;
            try {
                reply = await forwardUpstream(o.upstreamUrl, req.url ?? "/", req.method ?? "POST", req.headers, raw ?? undefined, max);
            }
            catch (e) {
                res.writeHead(502, { "content-type": "application/json" }).end(JSON.stringify({ jsonrpc: "2.0", id: frame?.id ?? null, error: { code: -32050, message: "deepsweep: upstream unreachable" } }));
                return;
            }
            // Record the result of a forwarded tools/call; pin a tools/list response.
            if (d.kind === "forward") {
                stats.forwarded += 1;
                if (d.callEntryHash !== null)
                    recordToolResultOverBody(o.workspaceRoot, d.callEntryHash, reply.body, o.now(), t0, o.key);
            }
            else if (d.pinOnResponse) {
                observeToolList(o.workspaceRoot, o.serverName, reply.body, o.now().toISOString(), o.key, diag);
            }
            const outHeaders = {};
            for (const [k, v] of Object.entries(reply.headers))
                if (v !== undefined)
                    outHeaders[k] = v;
            res.writeHead(reply.status, outHeaders).end(reply.body);
        })().catch(() => { if (!res.headersSent)
            res.writeHead(500).end("gateway error"); });
    });
    const host = o.host ?? "127.0.0.1";
    const port = o.port ?? 0;
    return new Promise((resolve) => {
        server.listen(port, host, () => {
            const addr = server.address();
            const boundPort = typeof addr === "object" && addr !== null ? addr.port : port;
            resolve({
                server,
                url: `http://${host}:${boundPort}/`,
                stats,
                close: () => new Promise((r) => server.close(() => r())),
            });
        });
    });
}
