/**
 * Transparent stdio gateway (TEAM-ADR-036): agent ⇄ [gateway] ⇄ MCP server.
 *
 * The agent is configured to launch THIS process instead of the server; the
 * gateway spawns the real server command and pipes newline-delimited JSON-RPC
 * both ways. Only `tools/call` is inspected (intercept.ts). Blocked calls are
 * answered by the gateway with a JSON-RPC error and never reach the server.
 * So is anything the gateway cannot decide as one call (TEAM-ADR-068): a
 * JSON-RPC batch line, or a tools/call that does not name its tool; and, since
 * Addendum 1, a line it cannot parse as UTF-8 JSON (-32700), a look-alike of
 * a governed method or key, and a line over the size cap. Everything else,
 * blank lines and ordering included, is forwarded untouched.
 *
 * Determinism seam: `now()` and `key` are injected by the composition root
 * (gateway-host.ts); this module never reads the ambient clock.
 */
import { type ChildProcess } from "node:child_process";
import type { Readable, Writable } from "node:stream";
import type { LedgerSigningKey } from "../review/ledger-sign.js";
import { type Recorded } from "./record.js";
export interface StdioGatewayOptions {
    readonly workspaceRoot: string;
    readonly serverName: string;
    readonly command: string;
    readonly args?: readonly string[];
    readonly env?: NodeJS.ProcessEnv;
    readonly principal: string | null;
    readonly userConfigRoot?: string | undefined;
    readonly agentIn: Readable;
    readonly agentOut: Writable;
    readonly now: () => Date;
    readonly key?: LedgerSigningKey | undefined;
    /** Diagnostics sink (stderr in production). */
    readonly diag?: (line: string) => void;
    /** Cap on one agent line in bytes, newline excluded (default MAX_MESSAGE_BYTES, the HTTP body cap). */
    readonly maxLineBytes?: number;
}
export interface StdioGateway {
    readonly child: ChildProcess;
    /** Resolves with the child's exit code once the upstream exits. */
    readonly done: Promise<number | null>;
    readonly stats: {
        readonly forwarded: number;
        readonly blocked: number;
        readonly held: number;
    };
}
/** A cap on the lines a lineSplitter delivers (TEAM-ADR-068 Addendum 1). */
export interface LineLimit {
    /** The longest line delivered, in bytes, newline excluded. */
    readonly maxBytes: number;
    /** Called ONCE for each longer line, as soon as it is known to be too long. That line is never delivered. */
    readonly onOverflow: () => void;
}
/**
 * Split a byte stream into complete lines; keeps the partial tail between
 * chunks. Each line is decoded only once it is complete, so a multi-byte
 * character split across chunks survives, and `onLine` also gets the line's
 * exact bytes. With a limit, a line longer than `maxBytes` is refused as soon
 * as it outgrows the cap, and the rest of it is discarded up to its newline,
 * so the buffer never grows past the cap. Without one it is unbounded.
 */
export declare function lineSplitter(onLine: (line: string, bytes: Buffer) => void, limit?: LineLimit): (chunk: Buffer | string) => void;
/**
 * Record a forwarded call's result and return the operator's diagnostic line
 * when its record is missing or unsigned, else undefined. Only store
 * failures are reported; anything else propagates. Shared by both
 * transports so their wording cannot drift (TEAM-ADR-040 Decision 1).
 */
export declare function resultDiagnostic(serverName: string, record: () => Recorded): string | undefined;
/** The JSON-RPC error that answers such a tools/list, for the request's id (null when it had none). Shared by both transports. */
export declare function unpinnedListAnswer(id: string | number | null | undefined): string;
/**
 * Pin a tools/list answer's tools, and return undefined, or the operator's
 * diagnostic when they could not be pinned (fix pass 2, M-2): the pin store
 * could not be written, or was refused by containment. Before, the failure was
 * thrown: over stdio it ended the gateway process, over HTTP it answered a
 * bare 500. Only those failures are caught; anything else propagates. Shared
 * by both transports. Since fix pass 3 (R3-1) the pins are saved before
 * anything is recorded, so a ledger or signature failure is a note, not a
 * pin failure, and a drift that could not be saved still trips its tool.
 * Since fix pass 4 (R4-1) the pins are saved holding the ledger lock, so a
 * lock that cannot be taken is a pin failure again; and a drift whose save
 * failed is still recorded, with a note here when even that failed (R4-4).
 */
export declare function pinFailure(serverName: string, pin: () => void): string | undefined;
export declare function startStdioGateway(o: StdioGatewayOptions): StdioGateway;
