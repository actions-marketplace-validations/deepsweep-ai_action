/**
 * Tool-description pinning AT THE WIRE (TEAM-ADR-039) — the rug-pull circuit
 * breaker.
 *
 * ADR-003 pins tool descriptions from static config files. A live MCP server
 * can change what a tool SAYS it does after the agent trusted it (the "rug
 * pull": benign description at review time, exfiltration instructions at
 * call time). The gateway sees every `tools/list` response, so it can pin the
 * canonical hash of each tool's (name, description, inputSchema) on first
 * sight (TOFU) and detect any later change — per server, per tool.
 *
 * Response: a drifted tool is a `gateway.tool_drift` ledger event AND a
 * tripped breaker: subsequent `tools/call` to that tool is DENIED (fail
 * closed, ADR-010 posture) until a human re-pins
 * (`deepsweep-gateway repin --name <server> --tool <tool>`), which is itself a
 * ledger event. Content never enters the ledger — only hashes.
 *
 * Store: `.deepsweep/tool-pins.json` (contained, atomic). Shape:
 *   { schemaVersion: 1, servers: { [server]: { [tool]: { hash, pinnedAt, status: "pinned"|"drifted", seenHash? } } } }
 */
import { canonicalize, sha256Hex } from "../review/canonical.js";
import { appendLedgerEntry } from "../review/ledger.js";
import { appendLedgerSignature, signLedgerEntry } from "../review/ledger-sign.js";
import { readStoreText, writeStoreAtomic } from "../review/store.js";
export const TOOL_PINS_FILE = "tool-pins.json";
class ToolPinRefusalError extends Error {
    constructor(reason) {
        super(`tool pins refused: ${reason}`);
        this.name = "ToolPinRefusalError";
    }
}
const refuse = (reason) => new ToolPinRefusalError(reason);
const EMPTY = { schemaVersion: 1, servers: {} };
/** Read the pin store. Malformed → undefined (caller fails closed by treating every tool as unpinnable). */
export function readToolPins(workspaceRoot) {
    const text = readStoreText(workspaceRoot, TOOL_PINS_FILE, refuse);
    if (text === undefined)
        return EMPTY;
    try {
        const v = JSON.parse(text);
        if (typeof v !== "object" || v === null || Array.isArray(v))
            return undefined;
        const f = v;
        if (f["schemaVersion"] !== 1 || typeof f["servers"] !== "object" || f["servers"] === null)
            return undefined;
        return v;
    }
    catch {
        return undefined;
    }
}
function writeToolPins(workspaceRoot, pins) {
    writeStoreAtomic(workspaceRoot, TOOL_PINS_FILE, `${JSON.stringify(pins, null, 2)}\n`, refuse);
}
/** Canonical identity of what a tool CLAIMS to be. Byte-preserving (ADR-003): any code-point change is drift. */
export function toolDescriptionHash(tool) {
    return sha256Hex(canonicalize({ name: tool["name"], description: tool["description"] ?? null, inputSchema: tool["inputSchema"] ?? null }));
}
function record(root, kind, payload, nowIso, key, out) {
    const e = appendLedgerEntry(root, kind, payload, nowIso);
    if (e === "corrupt")
        return;
    if (key !== undefined)
        appendLedgerSignature(root, signLedgerEntry(e, key));
    out.push(e);
}
/**
 * Observe one `tools/list` result. First sight pins (TOFU); a changed hash
 * marks the tool drifted (breaker tripped) and records `gateway.tool_drift`;
 * an already-drifted tool that changes AGAIN updates seenHash silently
 * (still tripped). Returns which tools fell into which bucket.
 */
export function observeToolList(workspaceRoot, serverName, tools, nowIso, key) {
    const pins = readToolPins(workspaceRoot);
    const entries = [];
    if (pins === undefined) {
        record(workspaceRoot, "gateway.tool_pins_unreadable", { serverHash: sha256Hex(serverName) }, nowIso, key, entries);
        return { pinned: [], unchanged: [], drifted: [], entries };
    }
    const server = { ...(pins.servers[serverName] ?? {}) };
    const pinned = [];
    const unchanged = [];
    const drifted = [];
    for (const raw of tools) {
        if (typeof raw !== "object" || raw === null || Array.isArray(raw))
            continue;
        const t = raw;
        const name = t["name"];
        if (typeof name !== "string" || name.length === 0)
            continue;
        const hash = toolDescriptionHash(t);
        const cur = server[name];
        if (cur === undefined) {
            server[name] = { hash, pinnedAt: nowIso, status: "pinned" };
            pinned.push(name);
            record(workspaceRoot, "gateway.tool_pinned", { serverHash: sha256Hex(serverName), toolHash: sha256Hex(name), descriptionHash: hash }, nowIso, key, entries);
        }
        else if (cur.hash === hash) {
            if (cur.status === "drifted") {
                // The server reverted to the pinned description: breaker stays tripped until a human re-pins;
                // record the observation so the timeline shows the flip-flop.
                server[name] = { ...cur, seenHash: hash };
            }
            unchanged.push(name);
        }
        else {
            const first = cur.status !== "drifted";
            server[name] = { ...cur, status: "drifted", seenHash: hash };
            drifted.push(name);
            if (first)
                record(workspaceRoot, "gateway.tool_drift", { serverHash: sha256Hex(serverName), toolHash: sha256Hex(name), pinnedHash: cur.hash, seenHash: hash }, nowIso, key, entries);
        }
    }
    writeToolPins(workspaceRoot, { schemaVersion: 1, servers: { ...pins.servers, [serverName]: server } });
    return { pinned, unchanged, drifted, entries };
}
/** Is the breaker tripped for this tool? Unpinned tools are NOT tripped (a call before any tools/list is governed by policy alone). Unreadable store → tripped (fail closed). */
export function isToolTripped(workspaceRoot, serverName, toolName) {
    const pins = readToolPins(workspaceRoot);
    if (pins === undefined)
        return true;
    return pins.servers[serverName]?.[toolName]?.status === "drifted";
}
/** Human re-pins a drifted tool to what the server currently claims (its last seen hash). Ledger event `gateway.tool_repinned`. */
export function repinTool(workspaceRoot, serverName, toolName, approver, nowIso, key) {
    const pins = readToolPins(workspaceRoot);
    if (pins === undefined)
        return { ok: false, reason: "unreadable" };
    const cur = pins.servers[serverName]?.[toolName];
    if (cur === undefined)
        return { ok: false, reason: "unknown-tool" };
    if (cur.status !== "drifted")
        return { ok: false, reason: "not-drifted" };
    const next = { hash: cur.seenHash ?? cur.hash, pinnedAt: nowIso, status: "pinned" };
    writeToolPins(workspaceRoot, { schemaVersion: 1, servers: { ...pins.servers, [serverName]: { ...pins.servers[serverName], [toolName]: next } } });
    const out = [];
    record(workspaceRoot, "gateway.tool_repinned", { serverHash: sha256Hex(serverName), toolHash: sha256Hex(toolName), previousHash: cur.hash, descriptionHash: next.hash, approverHash: sha256Hex(approver) }, nowIso, key, out);
    return { ok: true };
}
