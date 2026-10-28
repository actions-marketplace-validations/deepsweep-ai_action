/**
 * HTTP-transport helpers (TEAM-ADR-040): parse a JSON or SSE response body far
 * enough to (a) pin a tools/list result and (b) hash a tools/call result. Kept
 * out of http.ts so the transport file stays about sockets and this stays about
 * MCP semantics — and so both are unit-tested directly. Since fix pass 8 one
 * parse (messagesInBody) feeds both.
 */
import { brotliDecompressSync, gunzipSync, inflateRawSync, inflateSync } from "node:zlib";
import * as zlib from "node:zlib";
import { MAX_MESSAGE_BYTES, toolsInResult } from "./frames.js";
import { observeDiagnostics, observeToolList as observe } from "./toolpins.js";
import { recordToolResultEntry } from "./intercept.js";
import { sha256Hex } from "../review/canonical.js";
/**
 * True when a Content-Type declares no charset, or declares UTF-8 (TEAM-ADR-068
 * Addendum 1). The gateway reads a body as UTF-8 (RFC 8259 section 8.1), so a
 * body declared in another charset could be read differently by a server that
 * honours the header, and the gateway would have decided a message the server
 * never sees. Every charset parameter must say UTF-8; one it cannot read
 * (empty, half-quoted, or the extended `charset*` form) counts as not UTF-8.
 */
export function declaresOnlyUtf8(contentType) {
    if (contentType === undefined)
        return true;
    for (const param of contentType.split(";").slice(1)) {
        const eq = param.indexOf("=");
        const name = (eq < 0 ? param : param.slice(0, eq)).trim().toLowerCase();
        if (name !== "charset" && name !== "charset*")
            continue;
        let value = eq < 0 ? "" : param.slice(eq + 1).trim();
        if (value.length >= 2 && value.startsWith('"') && value.endsWith('"'))
            value = value.slice(1, -1);
        if (name !== "charset" || !["utf-8", "utf8"].includes(value.toLowerCase()))
            return false;
    }
    return true;
}
/**
 * The most a body may decode to, in bytes, across all of its encodings
 * together: 16 MiB, twice MAX_MESSAGE_BYTES (TEAM-ADR-069 fix pass 7, R7-1).
 * The gateway already refuses a body over 8 MiB as sent; a compressed body
 * may decode to more than that, and JSON rarely compresses by more than ten
 * times, so twice the plain limit leaves room for any answer a server would
 * send plainly while keeping memory bounded. Fix pass 6 decoded without a
 * limit: a 1.2 MB gzip body of 1,200 MB took the gateway to 3.7 GB.
 */
export const MAX_DECODED_BYTES = 2 * MAX_MESSAGE_BYTES;
/** The codings fetch (undici) undoes. zstd only where this runtime has a decoder for it. */
const hasZstd = typeof zlib.zstdDecompressSync === "function";
/** Undo one coding, producing at most `limit` bytes (a larger output throws). */
function decodeOne(coding, input, limit) {
    const opts = { maxOutputLength: limit };
    if (coding === "gzip" || coding === "x-gzip")
        return gunzipSync(input, opts);
    if (coding === "br")
        return brotliDecompressSync(input, opts);
    if (coding === "deflate") {
        try {
            return inflateSync(input, opts);
        }
        catch {
            return inflateRawSync(input, opts);
        }
    }
    return zlib.zstdDecompressSync(input, opts);
}
/**
 * Undo a body's Content-Encoding the way fetch (undici) does before a client
 * reads it (TEAM-ADR-069 fix pass 6, R6-2; fix pass 7). The codings are undone
 * in reverse of the order they were applied (RFC 9110 section 8.4): gzip,
 * x-gzip, deflate (zlib or raw), br and, where this runtime has it, zstd. As in
 * fetch, a coding it does not know (identity, "none", "utf-8", anything else)
 * anywhere in the list stops all decoding, and the body is read as sent.
 * Undefined when a known coding does not decode, or when the output would pass
 * `budget` bytes in total, MAX_DECODED_BYTES unless a test passes a smaller
 * one (fix pass 7, R7-1: each decoder is stopped at the room the earlier ones
 * left, so stacked codings share one budget); the body is then unreadable and
 * is withheld.
 */
export function decodeBody(body, contentEncoding, budget = MAX_DECODED_BYTES) {
    const codings = (Array.isArray(contentEncoding) ? contentEncoding.join(",") : contentEncoding ?? "").split(",").map((c) => c.trim().toLowerCase()).filter((c) => c.length > 0);
    const known = (c) => c === "gzip" || c === "x-gzip" || c === "deflate" || c === "br" || (c === "zstd" && hasZstd);
    if (!codings.every(known))
        return body;
    let out = body;
    let room = budget;
    for (const coding of codings.reverse()) {
        // Spent: another coding cannot produce even one byte (zlib refuses a zero limit).
        if (room <= 0)
            return undefined;
        try {
            out = decodeOne(coding, out, room);
        }
        catch {
            return undefined;
        }
        room -= out.length;
    }
    return out;
}
/**
 * Split an event stream into events the way the WHATWG event-stream parser
 * does (fix pass 6, R6-2): lines end in CRLF, LF or CR; a line starting with
 * a colon is a comment; `data` lines are joined with "\n"; a blank line
 * dispatches. The event still pending at the end of the body is dispatched
 * too, which a client may not do: the gateway checks more, never less. A
 * leading byte-order mark is dropped.
 */
export function sseEvents(text) {
    const events = [];
    let data = [];
    let type = "";
    const dispatch = () => {
        const joined = data.join("\n");
        if (data.length > 0 && joined.length > 0)
            events.push({ event: type, data: joined });
        data = [];
        type = "";
    };
    for (const line of text.replace(/^\uFEFF/, "").split(/\r\n|\r|\n/)) {
        if (line.length === 0) {
            dispatch();
            continue;
        }
        if (line.startsWith(":"))
            continue;
        const colon = line.indexOf(":");
        const field = colon < 0 ? line : line.slice(0, colon);
        let value = colon < 0 ? "" : line.slice(colon + 1);
        if (value.startsWith(" "))
            value = value.slice(1);
        if (field === "data")
            data.push(value);
        else if (field === "event")
            type = value;
    }
    dispatch();
    return events;
}
const asMessages = (v) => (Array.isArray(v) ? v : typeof v === "object" && v !== null ? [v] : []);
/**
 * False only when `text` cannot hold a JSON member named "tools" (fix pass 8):
 * JSON spells a member name with literal characters or with \u escapes (no
 * other escape yields a letter), so a name "tools" appears as the text
 * `"tools"` or carries a `\u`. Sound, not exact: true means "parse to see".
 */
export function mayNameTools(text) {
    return text.includes('"tools"') || text.includes("\\u");
}
/**
 * Read a Streamable-HTTP response body as a client could (fix pass 6, R6-2):
 * undo its Content-Encoding; read it as one JSON value (an object or a batch
 * array) AND as an event stream, whatever its Content-Type says, and keep the
 * messages of both. Before, the gateway read one object, or only the last
 * single `data:` line of a stream, so a rug pull in the first of two events,
 * in data split over two lines, or in an array was relayed unchecked.
 */
export function messagesInBody(body, contentEncoding, toolsOnly = false) {
    const decoded = decodeBody(body, contentEncoding);
    if (decoded === undefined)
        return { messages: [], readable: false, complete: false };
    // One copy of the (at most MAX_DECODED_BYTES) body as text, and no more whole
    // copies (fix pass 7, R7-1), and one parse (fix pass 8): a body that parses
    // as JSON has no event stream to read. trim() drops surrounding whitespace
    // and a byte order mark, as the recorder's own parse did before.
    const text = decoded.toString("utf8");
    if (/^[\s\uFEFF]*$/.test(text))
        return { messages: [], readable: true, complete: true };
    // Fix pass 8: an answer read only for the tools results in it, whose text
    // cannot name a "tools" member, is not parsed at all.
    if (toolsOnly && !mayNameTools(text))
        return { messages: [], readable: true, complete: false };
    // Never spread a message list into a call (fix pass 8): past about 120,000
    // elements that throws, and the throw read a large array as no messages.
    let messages = [];
    try {
        const v = JSON.parse(text.trim());
        messages = asMessages(v);
        const single = decoded === body && messages.length === 1 && messages[0] === v ? { single: v } : {};
        if (messages.length > 0)
            return { messages, readable: true, complete: true, ...single };
    }
    catch {
        /* not one JSON value: read as an event stream below */
    }
    const events = sseEvents(text);
    let unread = false;
    let found = 0;
    for (const e of events) {
        try {
            const got = asMessages(JSON.parse(e.data));
            for (const m of got)
                messages.push(m);
            found += got.length;
        }
        catch {
            // A client dispatches only events of type "message" (or none) as JSON-RPC.
            if (e.event === "" || e.event === "message")
                unread = true;
        }
    }
    return { messages, readable: true, complete: found > 0 && !unread };
}
/**
 * Pin every tools result in a response body's messages (TEAM-ADR-039 over
 * HTTP; fix pass 6, R6-2: all of them, in every body, whatever request it
 * answers). Throws what observeToolList throws.
 */
export function observeBodyTools(workspaceRoot, serverName, messages, nowIso, key, diag) {
    for (const m of messages) {
        const tools = toolsInResult(m);
        if (tools === undefined)
            continue;
        const r = observe(workspaceRoot, serverName, tools, nowIso, key);
        for (const line of observeDiagnostics(serverName, r))
            diag(line);
    }
}
/** Pin a tools/list response body (TEAM-ADR-039) over HTTP: every tools result in it (fix pass 6). */
export function observeToolList(workspaceRoot, serverName, body, nowIso, key, diag) {
    observeBodyTools(workspaceRoot, serverName, messagesInBody(body).messages, nowIso, key, diag);
}
/**
 * Record a tools/call result from an HTTP response body, read once by
 * messagesInBody (fix pass 8: the same parse the pin check uses). A body that
 * is one JSON object sent with no coding to undo is recorded by its result or
 * error; anything else (a stream, a batch, a coded or unreadable body) is
 * hashed over its raw bytes with a `streamed` marker. The same bytes give the
 * same record as before fix pass 8, except a body whose declared coding does
 * not decode: it is now hashed as raw bytes too.
 */
export function recordToolResultOverBody(workspaceRoot, callEntryHash, body, read, now, t0, key) {
    const f = read.single;
    if (f !== undefined) {
        return recordToolResultEntry({ workspaceRoot, callEntryHash, result: f.error !== undefined ? f.error : f.result, isError: f.error !== undefined, latencyMs: now.getTime() - t0, nowIso: now.toISOString(), key });
    }
    // SSE or unparseable body: hash the raw bytes so the result is still committed, marked streamed.
    return recordToolResultEntry({ workspaceRoot, callEntryHash, result: { streamedBodyHash: sha256Hex(body.toString("utf8")) }, isError: false, latencyMs: now.getTime() - t0, nowIso: now.toISOString(), key });
}
