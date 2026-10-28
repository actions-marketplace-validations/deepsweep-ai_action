import type { Recorded } from "./record.js";
import type { LedgerSigningKey } from "../review/ledger-sign.js";
/**
 * True when a Content-Type declares no charset, or declares UTF-8 (TEAM-ADR-068
 * Addendum 1). The gateway reads a body as UTF-8 (RFC 8259 section 8.1), so a
 * body declared in another charset could be read differently by a server that
 * honours the header, and the gateway would have decided a message the server
 * never sees. Every charset parameter must say UTF-8; one it cannot read
 * (empty, half-quoted, or the extended `charset*` form) counts as not UTF-8.
 */
export declare function declaresOnlyUtf8(contentType: string | undefined): boolean;
/**
 * The most a body may decode to, in bytes, across all of its encodings
 * together: 16 MiB, twice MAX_MESSAGE_BYTES (TEAM-ADR-069 fix pass 7, R7-1).
 * The gateway already refuses a body over 8 MiB as sent; a compressed body
 * may decode to more than that, and JSON rarely compresses by more than ten
 * times, so twice the plain limit leaves room for any answer a server would
 * send plainly while keeping memory bounded. Fix pass 6 decoded without a
 * limit: a 1.2 MB gzip body of 1,200 MB took the gateway to 3.7 GB.
 */
export declare const MAX_DECODED_BYTES: number;
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
export declare function decodeBody(body: Buffer, contentEncoding: string | string[] | undefined, budget?: number): Buffer | undefined;
/** One dispatched server-sent event: its type ("" when none was given) and its data, with multi-line data joined by "\n". */
export interface SseEvent {
    readonly event: string;
    readonly data: string;
}
/**
 * Split an event stream into events the way the WHATWG event-stream parser
 * does (fix pass 6, R6-2): lines end in CRLF, LF or CR; a line starting with
 * a colon is a comment; `data` lines are joined with "\n"; a blank line
 * dispatches. The event still pending at the end of the body is dispatched
 * too, which a client may not do: the gateway checks more, never less. A
 * leading byte-order mark is dropped.
 */
export declare function sseEvents(text: string): SseEvent[];
/** What the gateway could read of a response body (fix pass 6, R6-2). */
export interface BodyMessages {
    /** Every JSON-RPC message found: the body as one JSON value (an object, or each element of an array), and every event's data. */
    readonly messages: readonly unknown[];
    /** False when a Content-Encoding is unknown or does not decode. */
    readonly readable: boolean;
    /** True when the body read completely into messages: as one JSON value, or as events whose every message-type event parsed. */
    readonly complete: boolean;
    /**
     * The body as one JSON object, when it is one and no coding had to be undone
     * to read it (fix pass 8). A forwarded call's result is recorded from it, as
     * it was from a second parse of the raw body before; any other body is
     * recorded by the hash of its raw bytes.
     */
    readonly single?: {
        readonly result?: unknown;
        readonly error?: unknown;
    };
}
/**
 * False only when `text` cannot hold a JSON member named "tools" (fix pass 8):
 * JSON spells a member name with literal characters or with \u escapes (no
 * other escape yields a letter), so a name "tools" appears as the text
 * `"tools"` or carries a `\u`. Sound, not exact: true means "parse to see".
 */
export declare function mayNameTools(text: string): boolean;
/**
 * Read a Streamable-HTTP response body as a client could (fix pass 6, R6-2):
 * undo its Content-Encoding; read it as one JSON value (an object or a batch
 * array) AND as an event stream, whatever its Content-Type says, and keep the
 * messages of both. Before, the gateway read one object, or only the last
 * single `data:` line of a stream, so a rug pull in the first of two events,
 * in data split over two lines, or in an array was relayed unchecked.
 */
export declare function messagesInBody(body: Buffer, contentEncoding?: string | string[], toolsOnly?: boolean): BodyMessages;
/**
 * Pin every tools result in a response body's messages (TEAM-ADR-039 over
 * HTTP; fix pass 6, R6-2: all of them, in every body, whatever request it
 * answers). Throws what observeToolList throws.
 */
export declare function observeBodyTools(workspaceRoot: string, serverName: string, messages: readonly unknown[], nowIso: string, key: LedgerSigningKey | undefined, diag: (l: string) => void): void;
/** Pin a tools/list response body (TEAM-ADR-039) over HTTP: every tools result in it (fix pass 6). */
export declare function observeToolList(workspaceRoot: string, serverName: string, body: Buffer, nowIso: string, key: LedgerSigningKey | undefined, diag: (l: string) => void): void;
/**
 * Record a tools/call result from an HTTP response body, read once by
 * messagesInBody (fix pass 8: the same parse the pin check uses). A body that
 * is one JSON object sent with no coding to undo is recorded by its result or
 * error; anything else (a stream, a batch, a coded or unreadable body) is
 * hashed over its raw bytes with a `streamed` marker. The same bytes give the
 * same record as before fix pass 8, except a body whose declared coding does
 * not decode: it is now hashed as raw bytes too.
 */
export declare function recordToolResultOverBody(workspaceRoot: string, callEntryHash: string, body: Buffer, read: BodyMessages, now: Date, t0: number, key: LedgerSigningKey | undefined): Recorded;
