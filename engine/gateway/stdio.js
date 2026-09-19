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
import { spawn } from "node:child_process";
import { isResponse, parseFrame } from "./frames.js";
import { recordToolResult } from "./intercept.js";
import { relayLine } from "./relay.js";
import { decideFrame } from "./decide.js";
import { observeToolList } from "./toolpins.js";
/** Split a byte stream into complete lines; keeps the partial tail between chunks. */
export function lineSplitter(onLine) {
    let tail = "";
    return (chunk) => {
        tail += chunk.toString();
        let i = tail.indexOf("\n");
        while (i >= 0) {
            onLine(tail.slice(0, i));
            tail = tail.slice(i + 1);
            i = tail.indexOf("\n");
        }
    };
}
export function startStdioGateway(o) {
    const diag = o.diag ?? (() => undefined);
    // Env: inherited from the host unless the composition root supplies a full
    // environment explicitly (the engine never reads its own environment).
    const child = spawn(o.command, [...(o.args ?? [])], { stdio: ["pipe", "pipe", "inherit"], ...(o.env !== undefined ? { env: o.env } : {}) });
    const stats = { forwarded: 0, blocked: 0, held: 0 };
    const inflight = new Map();
    const listRequests = new Set();
    const idKey = (id) => `${typeof id}:${String(id)}`;
    const fromAgent = lineSplitter((line) => {
        const frame = parseFrame(line);
        if (frame === undefined) {
            relayLine(child.stdin, line);
            return;
        }
        const id = frame.id === undefined ? null : frame.id;
        const d = decideFrame(frame, { workspaceRoot: o.workspaceRoot, serverName: o.serverName, principal: o.principal, userConfigRoot: o.userConfigRoot, nowIso: o.now().toISOString(), key: o.key });
        if (d.kind === "pass") {
            // Remember tools/list requests so the RESPONSE can be pinned (TEAM-ADR-039).
            if (d.pinOnResponse)
                listRequests.add(idKey(id));
            relayLine(child.stdin, line);
            return;
        }
        if (d.kind === "reject") {
            stats[d.reason === "held" ? "held" : "blocked"] += 1;
            relayLine(o.agentOut, d.errorFrame);
            diag(`${d.reason} ${o.serverName}/${d.tool}${d.rule ? ` rule=${d.rule}` : ""}`);
            return;
        }
        stats.forwarded += 1;
        if (d.callEntryHash !== null)
            inflight.set(idKey(id), { entryHash: d.callEntryHash, t0: o.now().getTime() });
        relayLine(child.stdin, line);
    });
    const fromServer = lineSplitter((line) => {
        const frame = parseFrame(line);
        if (frame !== undefined && isResponse(frame)) {
            const k = idKey(frame.id === undefined ? null : frame.id);
            if (listRequests.delete(k) && frame.result !== undefined) {
                const tools = frame.result.tools;
                if (Array.isArray(tools)) {
                    const r = observeToolList(o.workspaceRoot, o.serverName, tools, o.now().toISOString(), o.key);
                    for (const t of r.drifted)
                        diag(`tool drift ${o.serverName}/${t}`);
                }
            }
            const call = inflight.get(k);
            if (call !== undefined) {
                inflight.delete(k);
                const t = o.now();
                recordToolResult({
                    workspaceRoot: o.workspaceRoot,
                    callEntryHash: call.entryHash,
                    result: frame.error !== undefined ? frame.error : frame.result,
                    isError: frame.error !== undefined,
                    latencyMs: t.getTime() - call.t0,
                    nowIso: t.toISOString(),
                    key: o.key,
                });
            }
        }
        relayLine(o.agentOut, line);
    });
    o.agentIn.on("data", fromAgent);
    o.agentIn.on("end", () => child.stdin.end());
    child.stdout.on("data", fromServer);
    const done = new Promise((resolve) => child.on("exit", (code) => resolve(code)));
    return { child, done, stats };
}
