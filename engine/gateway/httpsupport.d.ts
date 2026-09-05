import type { LedgerSigningKey } from "../review/ledger-sign.js";
/** Extract the JSON-RPC result object from a Streamable-HTTP body: a bare JSON frame, or the last `data:` line of an SSE stream. */
export declare function frameFromBody(body: Buffer): {
    result?: unknown;
    error?: unknown;
    streamed: boolean;
} | undefined;
/** Pin a tools/list response body (TEAM-ADR-039) over HTTP. */
export declare function observeToolList(workspaceRoot: string, serverName: string, body: Buffer, nowIso: string, key: LedgerSigningKey | undefined, diag: (l: string) => void): void;
/** Record a tools/call result from an HTTP response body. A stream is hashed over its raw bytes with a `streamed` marker. */
export declare function recordToolResultOverBody(workspaceRoot: string, callEntryHash: string, body: Buffer, now: Date, t0: number, key: LedgerSigningKey | undefined): void;
