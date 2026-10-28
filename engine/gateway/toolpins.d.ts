import { type LedgerEntry } from "../review/ledger.js";
import type { LedgerSigningKey } from "../review/ledger-sign.js";
export declare const TOOL_PINS_FILE = "tool-pins.json";
export interface ToolPin {
    readonly hash: string;
    readonly pinnedAt: string;
    readonly status: "pinned" | "drifted";
    /** The hash most recently observed when status is "drifted". */
    readonly seenHash?: string;
    /** How many times a person has re-pinned this tool; absent means never (TEAM-ADR-069 fix pass 4, R4-5). */
    readonly repins?: number;
    /**
     * The hash of every field of the tool but `_meta` (fix pass 6, R6-3). A pin
     * saved before fix pass 6 has none; the next list whose description hash
     * matches adds it, so an upgrade flags nothing. `hash` stays the description
     * hash, so earlier builds and rule-pack bindings read the pin as before.
     */
    readonly fieldsHash?: string;
    /** The fields hash of what was seen, when status is "drifted". */
    readonly seenFieldsHash?: string;
}
export interface ToolPinsFile {
    readonly schemaVersion: 1;
    readonly servers: Record<string, Record<string, ToolPin>>;
}
/** A containment refusal of the pin store (ADR-003): a symlinked or non-regular `tool-pins.json`. */
export declare class ToolPinRefusalError extends Error {
    constructor(reason: string);
}
/**
 * Read the pin store. Absent → no pins. Malformed, or present but unreadable
 * (permissions, over the store's size cap, not a regular file) → undefined,
 * and the caller fails closed by treating every tool as tripped. Before
 * TEAM-ADR-069 fix pass 2 an unreadable store read as absent, so a drifted
 * tool was forwarded once `tool-pins.json` could not be read (the round-2
 * review, P1 class): an unreadable safety store never degrades.
 */
export declare function readToolPins(workspaceRoot: string): ToolPinsFile | undefined;
/** The stored pin of one tool, read as own properties only (fix pass 5). The one way anything reads a pin. */
export declare function storedPin(pins: ToolPinsFile | undefined, serverName: string, toolName: string): ToolPin | undefined;
/** Canonical identity of what a tool CLAIMS to be. Byte-preserving (ADR-003): any code-point change is drift. */
export declare function toolDescriptionHash(tool: Record<string, unknown>): string;
/**
 * The hash of every field of a tool but `_meta` (TEAM-ADR-069 fix pass 6,
 * R6-3): title, annotations, outputSchema, icons and any field the protocol
 * adds later. A model or its client reads these; `_meta` is left out because
 * servers put changing bookkeeping there. Before, a rug pull carried in the
 * title or the annotations was relayed and the call forwarded.
 */
export declare function toolFieldsHash(tool: Record<string, unknown>): string;
export interface ObserveResult {
    readonly pinned: readonly string[];
    readonly unchanged: readonly string[];
    readonly drifted: readonly string[];
    readonly entries: readonly LedgerEntry[];
    /**
     * What of the pin records is missing, for the operator's diagnostic
     * (TEAM-ADR-069 fix pass 3, R3-1): an entry the ledger refused or could not
     * take, or a signature that could not be written. The pins themselves are
     * saved: they are written first.
     */
    readonly notes: readonly string[];
}
/**
 * The operator's diagnostic lines for one observed tools/list, shared by both
 * transports so they cannot word it differently (TEAM-ADR-040 Decision 1): one
 * per drifted tool, and one per pin record that is missing or unsigned (fix
 * pass 3, R3-1).
 */
export declare function observeDiagnostics(serverName: string, r: ObserveResult): string[];
/**
 * The most pin entries recorded in one hold of the ledger lock (fix pass 6,
 * R6-4). A list that pinned or changed thousands of tools recorded them all in
 * one hold, about 0.45 ms apiece, and other gateways waiting on the lock were
 * refused after their 2 s wait. Entries are recorded after the pins are saved,
 * in turns of at most this many, so another gateway can take its turn between.
 */
export declare const RECORD_TURN = 250;
/** The notes `observeToolList` attached to the error it threw, for the operator's diagnostic; none for any other error. */
export declare function pinSaveNotes(e: unknown): readonly string[];
/**
 * The most new tools one tools/list answer may pin (fix pass 5). Past it, the
 * first MAX_NEW_PINS_PER_LIST are pinned, the drifts in the answer are saved,
 * and the answer is withheld; asking again pins the next ones (fix pass 6:
 * before, nothing was pinned and a server with more tools was withheld for
 * good).
 */
export declare const MAX_NEW_PINS_PER_LIST = 1000;
/**
 * The size a save that pins new tools (or adds fields hashes) may make the
 * pin store (fix pass 6, R6-4). The rest, up to the 1 MB it is read at, is
 * kept for drift marks and re-pins: a store filled with pins still has room
 * to save that a tool changed, so a restarted gateway still refuses it.
 */
export declare const PIN_STORE_GROWTH_BYTES = 900000;
/**
 * Observe one `tools/list` result. First sight pins (TOFU); a changed hash
 * marks the tool drifted (breaker tripped) and records `gateway.tool_drift`
 * once; an already-drifted tool that changes AGAIN updates seenHash silently
 * (still tripped). Returns which tools fell into which bucket.
 *
 * Order (TEAM-ADR-069 fix pass 4, R4-1): first every drift is latched from a
 * read without the lock, so a lock that cannot be taken still withholds the
 * list and refuses the changed tool. Then, holding the ledger lock, the store
 * is read again, only this server's entries change on that fresh copy, and it
 * is written. A drift in the store is never undone here; only a person's
 * re-pin does that. The entries are recorded after the lock is released, in
 * turns (fix pass 6, R6-4).
 *
 * If the save throws, the drift entries are recorded anyway, once per latch
 * (fix pass 4, R4-4), and the error is thrown on for the caller to withhold
 * the list; the latches go on refusing the changed tools. A latched drift is
 * saved with what the server serves now when the tool is listed (fix pass 4,
 * R4-2).
 *
 * Limits (fix pass 6, R6-4): at most MAX_NEW_PINS_PER_LIST new pins per answer,
 * and new pins only while the store stays within PIN_STORE_GROWTH_BYTES. Past
 * either, the drift marks are still saved, what fits is pinned, and the
 * answer is withheld (a ToolPinRefusalError, thrown after the entries are
 * recorded).
 */
export declare function observeToolList(workspaceRoot: string, serverName: string, tools: readonly unknown[], nowIso: string, key?: LedgerSigningKey): ObserveResult;
/**
 * Is the breaker tripped for this tool? Unpinned tools are NOT tripped (a call
 * before any tools/list is governed by policy alone). A drift this process
 * observed that the store does not hold yet → tripped (fix pass 3, R3-1),
 * until the store supersedes it (fix pass 4, R4-5: a re-pin made elsewhere is
 * honoured, not undone). Unreadable store → tripped (fail closed), and so is
 * one refused by containment (a symlinked or non-regular `tool-pins.json`),
 * which used to throw out of the decision and end a stdio gateway (found
 * alongside R3-1).
 */
export declare function isToolTripped(workspaceRoot: string, serverName: string, toolName: string): boolean;
/**
 * Human re-pins a drifted tool to what the server currently claims (its last
 * seen hash). Ledger event `gateway.tool_repinned`. The read, the check and
 * the write hold the ledger lock (fix pass 4, R4-1), so a re-pin and a
 * gateway's save never overwrite each other; the pin counts its re-pins.
 */
export declare function repinTool(workspaceRoot: string, serverName: string, toolName: string, approver: string, nowIso: string, key?: LedgerSigningKey): {
    readonly ok: boolean;
    readonly reason?: "unreadable" | "unknown-tool" | "not-drifted";
};
