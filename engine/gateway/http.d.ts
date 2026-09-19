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
import { type Server } from "node:http";
import type { LedgerSigningKey } from "../review/ledger-sign.js";
export interface HttpGatewayOptions {
    readonly workspaceRoot: string;
    readonly serverName: string;
    /** Upstream MCP endpoint (Streamable HTTP). */
    readonly upstreamUrl: string;
    readonly principal: string | null;
    readonly userConfigRoot?: string | undefined;
    readonly host?: string;
    readonly port?: number;
    readonly now: () => Date;
    readonly key?: LedgerSigningKey | undefined;
    readonly diag?: (line: string) => void;
    /** Cap on a single request/response body (bytes). */
    readonly maxBodyBytes?: number;
}
export interface HttpGateway {
    readonly server: Server;
    readonly url: string;
    readonly stats: {
        forwarded: number;
        blocked: number;
        held: number;
    };
    close(): Promise<void>;
}
export declare function startHttpGateway(o: HttpGatewayOptions): Promise<HttpGateway>;
