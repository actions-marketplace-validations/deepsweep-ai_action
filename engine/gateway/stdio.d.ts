/**
 * Transparent stdio gateway (TEAM-ADR-036): agent ⇄ [gateway] ⇄ MCP server.
 *
 * The agent is configured to launch THIS process instead of the server; the
 * gateway spawns the real server command and pipes newline-delimited JSON-RPC
 * both ways. Only `tools/call` is inspected (intercept.ts). Blocked calls are
 * answered by the gateway with a JSON-RPC error and never reach the server.
 * Everything else — bytes, ordering, non-JSON lines — is forwarded untouched.
 *
 * Determinism seam: `now()` and `key` are injected by the composition root
 * (gateway-host.ts); this module never reads the ambient clock.
 */
import { type ChildProcess } from "node:child_process";
import type { Readable, Writable } from "node:stream";
import type { LedgerSigningKey } from "../review/ledger-sign.js";
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
/** Split a byte stream into complete lines; keeps the partial tail between chunks. */
export declare function lineSplitter(onLine: (line: string) => void): (chunk: Buffer | string) => void;
export declare function startStdioGateway(o: StdioGatewayOptions): StdioGateway;
