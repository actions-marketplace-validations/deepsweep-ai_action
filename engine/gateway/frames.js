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
 * with when a call is blocked. Everything else is relayed untouched, with
 * the exceptions TEAM-ADR-068 makes: a JSON-RPC batch is recognised so that
 * it can be REFUSED whole (the gateway decides one call per message, and
 * relaying only part of a batch would mean rewriting it), and, since its
 * Addendum 1, bytes the gateway cannot parse as UTF-8 JSON are refused too.
 * A server with a laxer reader could find a call in them that the gateway
 * never decided.
 *
 * Zero dependencies (node builtins only), pure, deterministic.
 */
import { isUtf8 } from "node:buffer";
/** JSON-RPC error codes the GATEWAY answers with (server-defined range). */
export const GATEWAY_ERROR_DENIED = -32040;
export const GATEWAY_ERROR_APPROVAL_REQUIRED = -32041;
export const GATEWAY_ERROR_TOOL_DRIFTED = -32042;
export const GATEWAY_ERROR_KILLED = -32043;
/** A message the gateway cannot decide as ONE call: a JSON-RPC batch, or a tools/call whose params do not name a tool (TEAM-ADR-068). */
export const GATEWAY_ERROR_UNDECIDABLE = -32044;
/**
 * A tools/call the gateway would have decided under policy, but cannot record:
 * its audit ledger cannot be read or appended (TEAM-ADR-069). Nothing was sent
 * to the server, so a retry after the ledger is repaired is safe. Since fix
 * pass 2 (M-2) it also answers a tools/list whose tool descriptions could not
 * be pinned, and since fix pass 6 a server answer the gateway cannot read or
 * check to any request other than a forwarded tools/call: the answer is
 * withheld, and since only a tools/call runs a tool, asking again runs no tool
 * twice. It never answers a tools/call that was forwarded (fix pass 7, R7-2):
 * that answer is relayed as the server sent it, or answered -32050 or -32051.
 */
export const GATEWAY_ERROR_UNRECORDABLE = -32045;
/** The HTTP upstream failed after the gateway sent it a request (unreachable, or an answer over the size cap); for a tools/call, the call may already have run. */
export const GATEWAY_ERROR_UPSTREAM_FAILED = -32050;
/**
 * A tools/call that was forwarded and RAN, whose answer the gateway withheld
 * because it could not check it (TEAM-ADR-069 fix pass 7, R7-2): the answer
 * could not be decoded within MAX_DECODED_BYTES, or it came with another
 * request's tools result that could not be pinned. Its result is recorded
 * first, as for every forwarded call (stderr says so when it cannot be).
 * Asking again runs the tool again.
 */
export const GATEWAY_ERROR_CALL_ANSWER_WITHHELD = -32051;
export const CALL_ANSWER_WITHHELD_MESSAGE = "deepsweep: the tool call ran, but the gateway withheld its answer because it could not check it; do not retry blindly -- asking again runs the tool again";
/** JSON-RPC 2.0's own "Parse error": the gateway's answer to agent bytes it cannot parse as UTF-8 JSON (TEAM-ADR-068 Addendum 1). */
export const JSONRPC_PARSE_ERROR = -32700;
export const APPROVAL_META_KEY = "deepsweep/approval";
/**
 * The largest agent message the gateway will buffer, decide or answer, in
 * bytes: an HTTP request body, a stdio line (newline excluded), and the
 * gateway's own answer to a batch (TEAM-ADR-068 Addendum 1). One cap for both
 * transports, so they cannot drift (TEAM-ADR-040 Decision 1).
 */
export const MAX_MESSAGE_BYTES = 8 * 1024 * 1024;
const OPAQUE = { kind: "opaque" };
const BLANK = { kind: "blank" };
const UNPARSEABLE = { kind: "unparseable" };
/**
 * Classify one inbound agent message, given as the bytes received or as
 * text. Bytes are decoded only when they are valid UTF-8 (RFC 8259 section
 * 8.1): a lossy decoding would let the gateway decide one message while the
 * server, given the raw bytes, reads another. One JSON.parse, as before.
 */
export function parseInbound(message) {
    if (typeof message !== "string" && !isUtf8(message))
        return UNPARSEABLE;
    const text = (typeof message === "string" ? message : message.toString("utf8")).trim();
    if (text.length === 0)
        return BLANK;
    let v;
    try {
        v = JSON.parse(text);
    }
    catch {
        return UNPARSEABLE;
    }
    if (Array.isArray(v))
        return { kind: "batch", elements: v };
    if (typeof v === "object" && v !== null)
        return { kind: "frame", frame: v };
    return OPAQUE;
}
const PRINTABLE_ASCII = /^[\x21-\x7e]*$/;
const INVISIBLE = /[\p{White_Space}\p{Cc}\p{Cf}]/gu;
/**
 * The form in which a lenient reader may compare a name (TEAM-ADR-068
 * Addendum 1): NFKC, full case folding, and every whitespace, control and
 * format character removed. Names with the same fold can be read as one name
 * by some server; Go's encoding/json, for one, matches object keys without
 * regard to case. Printable ASCII only needs lower-casing.
 */
export function foldName(name) {
    if (PRINTABLE_ASCII.test(name))
        return name.toLowerCase();
    return name.normalize("NFKC").toUpperCase().toLowerCase().normalize("NFKC").replace(INVISIBLE, "");
}
/** The first own key of `obj` that folds to one of `names` without being spelled exactly so: a look-alike, not the member itself. */
export function lookalikeKey(obj, names) {
    for (const k of Object.keys(obj))
        if (!names.includes(k) && names.includes(foldName(k)))
            return k;
    return undefined;
}
/** True when two own keys of `obj` share a fold: a lenient reader may take either one for the other. */
export function hasFoldCollision(obj) {
    const seen = new Set();
    for (const k of Object.keys(obj)) {
        const f = foldName(k);
        if (seen.has(f))
            return true;
        seen.add(f);
    }
    return false;
}
/** Parse one frame. Blank, non-JSON, a JSON scalar and a JSON array → undefined. Inbound agent traffic goes through parseInbound, which tells a batch apart from opaque bytes. */
export function parseFrame(line) {
    const r = parseInbound(line);
    return r.kind === "frame" ? r.frame : undefined;
}
/**
 * The id of every REQUEST in a JSON-RPC batch, in order: an object with a
 * string `method` and an `id` that JSON-RPC allows (string, number or null).
 * A notification (no `id`), a response and anything malformed is not a
 * request, so it gets no answer of its own.
 */
export function batchRequestIds(elements) {
    const ids = [];
    for (const e of elements) {
        if (typeof e !== "object" || e === null || Array.isArray(e))
            continue;
        const rec = e;
        const id = rec["id"];
        if (typeof rec["method"] === "string" && (typeof id === "string" || typeof id === "number" || id === null))
            ids.push(id);
    }
    return ids;
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
/**
 * The tools array a server message carries in its result, or undefined
 * (TEAM-ADR-069 fix pass 6, R6-1/R6-2). Any message whose `result` is an
 * object with a `tools` array counts, whatever its id, method or framing: a
 * client matches answers to requests more loosely than the gateway can
 * predict (the MCP TypeScript SDK by Number(id)), so every tools result the
 * server sends is checked, not only the answer the gateway expects.
 */
export function toolsInResult(message) {
    if (typeof message !== "object" || message === null || Array.isArray(message))
        return undefined;
    const result = message.result;
    if (typeof result !== "object" || result === null || Array.isArray(result))
        return undefined;
    const tools = result.tools;
    return Array.isArray(tools) ? tools : undefined;
}
/**
 * True when a client could take the answer id `answer` for the request id
 * `request` (fix pass 6, R6-1): the same value, the same text, or the same
 * number. The MCP TypeScript SDK matches by Number(answer.id), so "2", "2.0",
 * " 2 " and "0x2" all answer request 2. Only string and number ids match
 * loosely; anything else matches only itself.
 */
export function looseIdMatch(answer, request) {
    if (answer === request)
        return true;
    const kinds = (v) => typeof v === "string" || typeof v === "number";
    if (!kinds(answer) || !kinds(request))
        return false;
    if (String(answer) === String(request))
        return true;
    const a = Number(answer);
    return !Number.isNaN(a) && a === Number(request);
}
/** True when `message` is an answer (a result or an error) a client could take for the request with id `requestId` (fix pass 7). */
export function answersRequest(message, requestId) {
    if (typeof message !== "object" || message === null || Array.isArray(message))
        return false;
    const m = message;
    return (m.result !== undefined || m.error !== undefined) && m.id !== undefined && looseIdMatch(m.id, requestId);
}
/** The gateway's own refusal. `data` carries SHAPE only (rule name, token) — never args. */
export function gatewayError(id, code, message, data) {
    const error = { code, message };
    if (data !== undefined)
        error["data"] = data;
    return JSON.stringify({ jsonrpc: "2.0", id, error });
}
