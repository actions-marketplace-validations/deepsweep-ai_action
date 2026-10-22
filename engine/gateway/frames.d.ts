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
export declare const GATEWAY_ERROR_KILLED = -32043;
/** A message the gateway cannot decide as ONE call: a JSON-RPC batch, or a tools/call whose params do not name a tool (TEAM-ADR-068). */
export declare const GATEWAY_ERROR_UNDECIDABLE = -32044;
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
export declare const GATEWAY_ERROR_UNRECORDABLE = -32045;
/** The HTTP upstream failed after the gateway sent it a request (unreachable, or an answer over the size cap); for a tools/call, the call may already have run. */
export declare const GATEWAY_ERROR_UPSTREAM_FAILED = -32050;
/**
 * A tools/call that was forwarded and RAN, whose answer the gateway withheld
 * because it could not check it (TEAM-ADR-069 fix pass 7, R7-2): the answer
 * could not be decoded within MAX_DECODED_BYTES, or it came with another
 * request's tools result that could not be pinned. Its result is recorded
 * first, as for every forwarded call (stderr says so when it cannot be).
 * Asking again runs the tool again.
 */
export declare const GATEWAY_ERROR_CALL_ANSWER_WITHHELD = -32051;
export declare const CALL_ANSWER_WITHHELD_MESSAGE = "deepsweep: the tool call ran, but the gateway withheld its answer because it could not check it; do not retry blindly -- asking again runs the tool again";
/** JSON-RPC 2.0's own "Parse error": the gateway's answer to agent bytes it cannot parse as UTF-8 JSON (TEAM-ADR-068 Addendum 1). */
export declare const JSONRPC_PARSE_ERROR = -32700;
export declare const APPROVAL_META_KEY = "deepsweep/approval";
/**
 * The largest agent message the gateway will buffer, decide or answer, in
 * bytes: an HTTP request body, a stdio line (newline excluded), and the
 * gateway's own answer to a batch (TEAM-ADR-068 Addendum 1). One cap for both
 * transports, so they cannot drift (TEAM-ADR-040 Decision 1).
 */
export declare const MAX_MESSAGE_BYTES: number;
/**
 * One inbound AGENT message (a stdio line or an HTTP POST body), classified
 * before anything is decided (TEAM-ADR-068 and its Addendum 1):
 *   - "frame"        a single JSON object: decideFrame decides it;
 *   - "batch"        a JSON array, i.e. a JSON-RPC batch: refused whole, never relayed;
 *   - "unparseable"  bytes that are not UTF-8, or text JSON.parse rejects: refused
 *                    with -32700, never relayed (a laxer reader might find a call in it);
 *   - "blank"        empty or whitespace only: a stdio transport relays it (it
 *                    separates nothing and carries nothing); an HTTP body cannot be blank;
 *   - "opaque"       a JSON scalar: relayed untouched (it cannot carry a call).
 */
export type Inbound = {
    readonly kind: "frame";
    readonly frame: McpFrame;
} | {
    readonly kind: "batch";
    readonly elements: readonly unknown[];
} | {
    readonly kind: "unparseable";
} | {
    readonly kind: "blank";
} | {
    readonly kind: "opaque";
};
/**
 * Classify one inbound agent message, given as the bytes received or as
 * text. Bytes are decoded only when they are valid UTF-8 (RFC 8259 section
 * 8.1): a lossy decoding would let the gateway decide one message while the
 * server, given the raw bytes, reads another. One JSON.parse, as before.
 */
export declare function parseInbound(message: string | Buffer): Inbound;
/**
 * The form in which a lenient reader may compare a name (TEAM-ADR-068
 * Addendum 1): NFKC, full case folding, and every whitespace, control and
 * format character removed. Names with the same fold can be read as one name
 * by some server; Go's encoding/json, for one, matches object keys without
 * regard to case. Printable ASCII only needs lower-casing.
 */
export declare function foldName(name: string): string;
/** The first own key of `obj` that folds to one of `names` without being spelled exactly so: a look-alike, not the member itself. */
export declare function lookalikeKey(obj: object, names: readonly string[]): string | undefined;
/** True when two own keys of `obj` share a fold: a lenient reader may take either one for the other. */
export declare function hasFoldCollision(obj: object): boolean;
/** Parse one frame. Blank, non-JSON, a JSON scalar and a JSON array → undefined. Inbound agent traffic goes through parseInbound, which tells a batch apart from opaque bytes. */
export declare function parseFrame(line: string): McpFrame | undefined;
/**
 * The id of every REQUEST in a JSON-RPC batch, in order: an object with a
 * string `method` and an `id` that JSON-RPC allows (string, number or null).
 * A notification (no `id`), a response and anything malformed is not a
 * request, so it gets no answer of its own.
 */
export declare function batchRequestIds(elements: readonly unknown[]): Array<string | number | null>;
/** The governed verb. Returns the call tuple or undefined when the frame is anything else. */
export declare function toolCallOf(frame: McpFrame): ToolCall | undefined;
/** True when this frame is a response (result or error) — pairs with a forwarded request id. */
export declare function isResponse(frame: McpFrame): boolean;
/**
 * The tools array a server message carries in its result, or undefined
 * (TEAM-ADR-069 fix pass 6, R6-1/R6-2). Any message whose `result` is an
 * object with a `tools` array counts, whatever its id, method or framing: a
 * client matches answers to requests more loosely than the gateway can
 * predict (the MCP TypeScript SDK by Number(id)), so every tools result the
 * server sends is checked, not only the answer the gateway expects.
 */
export declare function toolsInResult(message: unknown): readonly unknown[] | undefined;
/**
 * True when a client could take the answer id `answer` for the request id
 * `request` (fix pass 6, R6-1): the same value, the same text, or the same
 * number. The MCP TypeScript SDK matches by Number(answer.id), so "2", "2.0",
 * " 2 " and "0x2" all answer request 2. Only string and number ids match
 * loosely; anything else matches only itself.
 */
export declare function looseIdMatch(answer: unknown, request: unknown): boolean;
/** True when `message` is an answer (a result or an error) a client could take for the request with id `requestId` (fix pass 7). */
export declare function answersRequest(message: unknown, requestId: unknown): boolean;
/** The gateway's own refusal. `data` carries SHAPE only (rule name, token) — never args. */
export declare function gatewayError(id: string | number | null, code: number, message: string, data?: Record<string, string>): string;
