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
 *
 * A POST body the gateway cannot decide as one call — a JSON-RPC batch, or a
 * tools/call that does not name its tool — is answered by the gateway and
 * never forwarded (TEAM-ADR-068). Since its Addendum 1, so is a body it cannot
 * parse as UTF-8 JSON (400, -32700), one declared in another charset (415),
 * and a look-alike of a governed method or key (-32044).
 */
import { createServer, request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { URL } from "node:url";
import { answersRequest, CALL_ANSWER_WITHHELD_MESSAGE, GATEWAY_ERROR_CALL_ANSWER_WITHHELD, GATEWAY_ERROR_UNRECORDABLE, GATEWAY_ERROR_UPSTREAM_FAILED, gatewayError, MAX_MESSAGE_BYTES, parseInbound } from "./frames.js";
import { relayChunk } from "./relay.js";
import { CHARSET_ANSWER, decideFrame, forwardDiagnostic, PARSE_ERROR_ANSWER, refuseBatch, rejectDiagnostic } from "./decide.js";
import { pinFailure, resultDiagnostic, unpinnedListAnswer } from "./stdio.js";
import { declaresOnlyUtf8, MAX_DECODED_BYTES, messagesInBody, observeBodyTools, recordToolResultOverBody } from "./httpsupport.js";
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
class UpstreamTooLarge extends Error {
    constructor(max) { super(`upstream response exceeds ${max} bytes`); }
}
/**
 * Headers that describe THIS connection, never the message (RFC 7230 §6.1),
 * plus the ones a `Connection:` header names. A relay that copies them tells
 * the next hop a lie about its own transport: the gateway buffers every body
 * (it must, to read it), so an upstream's `transfer-encoding: chunked` and
 * `keep-alive` describe the upstream's connection, not ours. Node tolerates the
 * lie; Bun, the runtime the shipped gateway binary embeds, answers an EMPTY
 * body when a buffered reply carries `transfer-encoding: chunked` (backlog row
 * 55, "every chunked MCP answer reaches the client empty"). `host` is the
 * upstream's to set and `content-length` is recomputed from the buffered body.
 * Applied on BOTH sides: what the agent sent us and what the upstream sent back.
 */
// `proxy-authorization` / `proxy-authenticate` are in RFC 7230's list and are
// deliberately NOT here: the gateway decides tool calls, never authentication,
// and relays the agent's credentials to the upstream untouched (TEAM-ADR-040
// counterexample b2, pinned by tests/gateway/threat-counterexamples.test.ts).
const HOP_BY_HOP = new Set(["connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length"]);
// On the REQUEST side the agent's `connection` / `keep-alive` are forwarded as
// they always were: the Node client manages that connection and the in-process
// network harness (tests/gateway/*fault-injection*) keys its sockets on them;
// stripping them made a later request in the same process wait forever. The
// headers that describe the agent's MESSAGE framing (`te`, `trailer`,
// `transfer-encoding`, `upgrade`) are the ones a buffering relay must not repeat.
const REQUEST_KEEPS = new Set(["connection", "keep-alive"]);
export function relayableHeaders(headers, bodyLength, side = "response") {
    const named = new Set();
    for (const [k, v] of Object.entries(headers)) {
        if (k.toLowerCase() !== "connection" || v === undefined)
            continue;
        for (const token of (Array.isArray(v) ? v.join(",") : v).split(",")) {
            const t = token.trim().toLowerCase();
            if (t)
                named.add(t);
        }
    }
    const out = {};
    for (const [k, v] of Object.entries(headers)) {
        const key = k.toLowerCase();
        if (v === undefined)
            continue;
        if (side === "request" && REQUEST_KEEPS.has(key)) {
            out[key] = v;
            continue;
        }
        if (HOP_BY_HOP.has(key) || named.has(key))
            continue;
        out[key] = v;
    }
    if (bodyLength !== undefined)
        out["content-length"] = String(bodyLength);
    return out;
}
function forwardUpstream(upstreamUrl, reqUrl, method, headers, body, max) {
    const u = new URL(upstreamUrl);
    // Carry the agent request's query string onto the upstream endpoint (the MCP
    // path is the upstream URL's; the query is the agent's, e.g. session ids).
    const incoming = new URL(reqUrl, "http://local");
    if (incoming.search.length > 0)
        u.search = incoming.search;
    const doRequest = u.protocol === "https:" ? httpsRequest : httpRequest;
    const outHeaders = relayableHeaders(headers, body?.length, "request");
    return new Promise((resolve, reject) => {
        const r = doRequest({ hostname: u.hostname, port: u.port, path: u.pathname + u.search, method, headers: outHeaders }, (res) => {
            const chunks = [];
            let size = 0;
            // Over the cap: refuse, never relay. Destroying the stream still lets "end"
            // fire on current Node, which used to answer 200 with an empty body.
            res.on("data", (c) => { size += c.length; if (size > max) {
                reject(new UpstreamTooLarge(max));
                res.destroy();
                return;
            } chunks.push(c); });
            res.on("end", () => { if (size > max)
                return; resolve({ status: res.statusCode ?? 502, headers: res.headers, body: Buffer.concat(chunks) }); });
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
    const max = o.maxBodyBytes ?? MAX_MESSAGE_BYTES;
    const stats = { forwarded: 0, blocked: 0, held: 0 };
    const server = createServer((req, res) => {
        void (async () => {
            // Only POST carries JSON-RPC (tools/call). GET/DELETE (SSE open, session close) are proxied untouched.
            const raw = req.method === "POST" ? await readBody(req, max) : undefined;
            if (raw === "too-large") {
                res.writeHead(413).end("request too large");
                return;
            }
            /** Answer the agent from the gateway itself; nothing is forwarded. */
            const refuse = (status, body, refused, diagLine) => {
                stats.blocked += refused;
                diag(diagLine);
                if (body === undefined)
                    res.writeHead(status).end();
                else
                    res.writeHead(status, { "content-type": "application/json" }).end(body);
            };
            // TEAM-ADR-068 Addendum 1: the gateway reads a body as UTF-8 only.
            if (raw !== undefined && !declaresOnlyUtf8(req.headers["content-type"])) {
                refuse(415, CHARSET_ANSWER, 1, `charset ${o.serverName}`);
                return;
            }
            const inbound = raw !== undefined ? parseInbound(raw) : undefined;
            // TEAM-ADR-068 Addendum 1: a POST body is exactly one JSON-RPC message; one
            // the gateway cannot parse (blank included) is never forwarded as opaque bytes.
            if (inbound?.kind === "unparseable" || inbound?.kind === "blank") {
                refuse(400, PARSE_ERROR_ANSWER, 1, `unparseable ${o.serverName}`);
                return;
            }
            if (inbound?.kind === "batch") {
                // TEAM-ADR-068: a batch is refused whole and never leaves the boundary.
                // Streamable HTTP answers requests with 200 + JSON, and accepts input
                // that holds no request with 202 and no body (Addendum 1: nothing is
                // forwarded all the same). An answer that would outgrow the cap is one
                // id-null error with 413.
                const r = refuseBatch(inbound.elements, max);
                const batchDiag = `undecidable ${o.serverName} batch of ${inbound.elements.length}`;
                if (r.answer === "per-id")
                    refuse(200, r.errorFrame, r.refused, batchDiag);
                else if (r.answer === "no-request")
                    refuse(202, undefined, r.refused, batchDiag);
                else
                    refuse(413, r.errorFrame, r.refused, batchDiag);
                return;
            }
            const frame = inbound?.kind === "frame" ? inbound.frame : undefined;
            const ctxNow = o.now().toISOString();
            const d = frame !== undefined
                ? decideFrame(frame, { workspaceRoot: o.workspaceRoot, serverName: o.serverName, principal: o.principal, userConfigRoot: o.userConfigRoot, nowIso: ctxNow, key: o.key })
                : { kind: "pass", pinOnResponse: false };
            if (d.kind === "reject") {
                stats[d.reason === "held" ? "held" : "blocked"] += 1;
                diag(rejectDiagnostic(d, o.serverName));
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
                const message = e instanceof UpstreamTooLarge ? "deepsweep: upstream response exceeds the gateway's size cap" : "deepsweep: upstream unreachable";
                res.writeHead(502, { "content-type": "application/json" }).end(JSON.stringify({ jsonrpc: "2.0", id: frame?.id ?? null, error: { code: GATEWAY_ERROR_UPSTREAM_FAILED, message } }));
                return;
            }
            // The answer's arrival: a call's latency ends here, before the gateway
            // decodes or parses anything (fix pass 9, R9-4).
            const received = o.now();
            const calls = d.kind === "forward";
            const pinOnResponse = d.kind === "pass" && d.pinOnResponse;
            // The body is parsed once, here (fix pass 8): the call's result record
            // and the pin check below both read this one parse. An answer to any
            // other request is read only for the tools results in it.
            const read = messagesInBody(reply.body, reply.headers["content-encoding"], !calls && !pinOnResponse);
            // Record the result of a forwarded tools/call.
            if (d.kind === "forward") {
                stats.forwarded += 1;
                const fwdNote = forwardDiagnostic(d, o.serverName);
                if (fwdNote !== undefined)
                    diag(fwdNote);
                // The call already ran: its answer is recorded whatever happens to it
                // next (TEAM-ADR-069 fix pass 1).
                const line = resultDiagnostic(o.serverName, () => recordToolResultOverBody(o.workspaceRoot, d.callEntryHash, reply.body, read, received, t0, o.key));
                if (line !== undefined)
                    diag(line);
            }
            // Fix pass 6 (R6-2): every body the server sends, on any request, is read
            // as a client reads it (encoding undone; one JSON value, a batch, or every
            // event of a stream), and every tools result in it is pinned. A client
            // reads a 2xx body other than 202; that body is withheld when the gateway
            // cannot decode it, when it answers a tools/list and does not read
            // completely into messages, or when its tools cannot be pinned. The agent
            // then gets -32045 under the request's id (fix pass 2, M-2), or a bare 502
            // for a request without one. A forwarded tools/call RAN (fix pass 7,
            // R7-2): its result is recorded above, its answer is relayed as the server
            // sent it, and the tools result in the call's own answer is the tool's
            // data, not the server's tools, so it is not pinned. Only when its answer
            // cannot be decoded, or carries another request's tools result that
            // cannot be pinned, is it withheld, with -32051, which says the call ran.
            const clientReads = reply.status >= 200 && reply.status < 300 && reply.status !== 202 && reply.body.length > 0;
            const withhold = (why, answer) => {
                diag(why);
                if (frame?.id === undefined) {
                    res.writeHead(502).end();
                    return;
                }
                res.writeHead(200, { "content-type": "application/json" }).end(calls ? gatewayError(frame.id, GATEWAY_ERROR_CALL_ANSWER_WITHHELD, CALL_ANSWER_WITHHELD_MESSAGE)
                    : answer ?? gatewayError(frame.id, GATEWAY_ERROR_UNRECORDABLE, "deepsweep: the server's answer was withheld -- the gateway could not read it, so it did not relay it"));
            };
            if (clientReads && !read.readable) {
                withhold(`unread ${o.serverName} -- not relayed: the answer's content-encoding (${String(reply.headers["content-encoding"])}) could not be decoded within ${MAX_DECODED_BYTES} bytes${calls ? "; the call ran" : ""}`, pinOnResponse ? unpinnedListAnswer(frame.id) : undefined);
                return;
            }
            if (clientReads && pinOnResponse && !read.complete) {
                withhold(`unpinned ${o.serverName} tools/list -- not relayed: the answer could not be read completely into messages`, unpinnedListAnswer(frame.id));
                return;
            }
            // Only the ONE message a client takes as the call's answer (the first
            // whose id matches) is the tool's data and skips the pin check; any
            // later message under the same id is checked like any other (fix pass 9,
            // R9-2: filtering by id alone let a second same-id message carry
            // unchecked tools).
            const own = calls ? read.messages.findIndex((m) => answersRequest(m, frame.id)) : -1;
            const toCheck = own < 0 ? read.messages : read.messages.filter((_m, i) => i !== own);
            const failed = pinFailure(o.serverName, () => observeBodyTools(o.workspaceRoot, o.serverName, toCheck, o.now().toISOString(), o.key, diag));
            if (failed !== undefined) {
                withhold(calls ? `${failed}; the call ran, and its answer was withheld with it` : failed, frame?.id !== undefined ? unpinnedListAnswer(frame.id) : undefined);
                return;
            }
            res.writeHead(reply.status, relayableHeaders(reply.headers, reply.body.length)).end(reply.body);
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
