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
import { spawn } from "node:child_process";
import { CALL_ANSWER_WITHHELD_MESSAGE, GATEWAY_ERROR_CALL_ANSWER_WITHHELD, GATEWAY_ERROR_UNRECORDABLE, gatewayError, looseIdMatch, MAX_MESSAGE_BYTES, parseInbound, toolsInResult } from "./frames.js";
import { recordToolResultEntry } from "./intercept.js";
import { relayLine } from "./relay.js";
import { decideFrame, forwardDiagnostic, OVERSIZE_ANSWER, PARSE_ERROR_ANSWER, refuseBatch, rejectDiagnostic } from "./decide.js";
import { describeStoreError } from "./record.js";
import { observeDiagnostics, observeToolList, pinSaveNotes, ToolPinRefusalError } from "./toolpins.js";
/**
 * Split a byte stream into complete lines; keeps the partial tail between
 * chunks. Each line is decoded only once it is complete, so a multi-byte
 * character split across chunks survives, and `onLine` also gets the line's
 * exact bytes. With a limit, a line longer than `maxBytes` is refused as soon
 * as it outgrows the cap, and the rest of it is discarded up to its newline,
 * so the buffer never grows past the cap. Without one it is unbounded.
 */
export function lineSplitter(onLine, limit) {
    const max = limit === undefined ? Infinity : limit.maxBytes;
    let parts = [];
    let size = 0;
    let discarding = false;
    return (chunk) => {
        let buf = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
        let i = buf.indexOf(0x0a);
        while (i >= 0) {
            const head = buf.subarray(0, i);
            if (discarding)
                discarding = false;
            else if (size + head.length > max)
                limit.onOverflow();
            else {
                const bytes = parts.length === 0 ? head : Buffer.concat([...parts, head]);
                onLine(bytes.toString("utf8"), bytes);
            }
            parts = [];
            size = 0;
            buf = buf.subarray(i + 1);
            i = buf.indexOf(0x0a);
        }
        if (buf.length === 0 || discarding)
            return;
        if (size + buf.length > max) {
            discarding = true;
            parts = [];
            size = 0;
            limit.onOverflow();
            return;
        }
        parts.push(buf);
        size += buf.length;
    };
}
/**
 * Record a forwarded call's result and return the operator's diagnostic line
 * when its record is missing or unsigned, else undefined. Only store
 * failures are reported; anything else propagates. Shared by both
 * transports so their wording cannot drift (TEAM-ADR-040 Decision 1).
 */
export function resultDiagnostic(serverName, record) {
    let r;
    try {
        r = record();
    }
    catch (e) {
        const why = describeStoreError(e);
        if (why === undefined)
            throw e;
        return `result ${serverName} -- not recorded: a gateway record could not be written or read (${why})`;
    }
    if (r.status === "refused")
        return `result ${serverName} -- not recorded: ${r.why}`;
    return r.unsigned === undefined ? undefined : `result ${serverName} -- the gateway.tool_result entry is on the ledger, but ${r.unsigned}`;
}
/**
 * The agent's answer to a tools/list whose tool descriptions could not be
 * pinned (TEAM-ADR-069 fix pass 2, M-2): the list is not relayed, because a
 * description the gateway did not pin could later change without the
 * rug-pull breaker noticing. Listing tools changes nothing, so a retry is
 * safe. A tool whose change this gateway saw in that list is refused -32042
 * meanwhile, whatever the store holds (fix pass 3, R3-1).
 */
const UNPINNED_LIST_MESSAGE = "deepsweep: tools/list answer withheld -- the gateway could not pin the tool descriptions, so it did not relay them; retry once an operator restores the gateway's store";
/** The JSON-RPC error that answers such a tools/list, for the request's id (null when it had none). Shared by both transports. */
export function unpinnedListAnswer(id) {
    return gatewayError(id ?? null, GATEWAY_ERROR_UNRECORDABLE, UNPINNED_LIST_MESSAGE);
}
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
export function pinFailure(serverName, pin) {
    try {
        pin();
        return undefined;
    }
    catch (e) {
        const why = e instanceof ToolPinRefusalError ? e.message : describeStoreError(e);
        if (why === undefined)
            throw e;
        return [`unpinned ${serverName} tools/list -- not relayed: the tool descriptions could not be pinned (${why})`, ...pinSaveNotes(e)].join("; ");
    }
}
export function startStdioGateway(o) {
    const diag = o.diag ?? (() => undefined);
    // Env: inherited from the host unless the composition root supplies a full
    // environment explicitly (the engine never reads its own environment).
    const child = spawn(o.command, [...(o.args ?? [])], { stdio: ["pipe", "pipe", "inherit"], ...(o.env !== undefined ? { env: o.env } : {}) });
    const stats = { forwarded: 0, blocked: 0, held: 0 };
    // Pending requests, by exact id; an answer is matched to them as a client
    // matches it, loosely (fix pass 6, R6-1).
    const inflight = new Map();
    const listRequests = new Map();
    const idKey = (id) => `${typeof id}:${String(id)}`;
    /** The key of the first pending request in `pending` that `answerId` answers, exact before loose. */
    const answered = (pending, answerId, idOf) => {
        const exact = typeof answerId === "string" || typeof answerId === "number" || answerId === null ? idKey(answerId) : undefined;
        if (exact !== undefined && pending.has(exact))
            return exact;
        for (const [k, v] of pending)
            if (looseIdMatch(answerId, idOf(v)))
                return k;
        return undefined;
    };
    const maxLine = o.maxLineBytes ?? MAX_MESSAGE_BYTES;
    const fromAgent = lineSplitter((line, bytes) => {
        const inbound = parseInbound(bytes);
        if (inbound.kind === "opaque" || inbound.kind === "blank") {
            relayLine(child.stdin, line);
            return;
        }
        if (inbound.kind === "unparseable") {
            // TEAM-ADR-068 Addendum 1: never relayed; a laxer reader could find a call in it.
            stats.blocked += 1;
            relayLine(o.agentOut, PARSE_ERROR_ANSWER);
            diag(`unparseable ${o.serverName}`);
            return;
        }
        if (inbound.kind === "batch") {
            // TEAM-ADR-068: a batch is refused whole and never reaches the server.
            const r = refuseBatch(inbound.elements, maxLine);
            stats.blocked += r.refused;
            relayLine(o.agentOut, r.errorFrame);
            diag(`undecidable ${o.serverName} batch of ${inbound.elements.length}`);
            return;
        }
        const frame = inbound.frame;
        const id = frame.id === undefined ? null : frame.id;
        const d = decideFrame(frame, { workspaceRoot: o.workspaceRoot, serverName: o.serverName, principal: o.principal, userConfigRoot: o.userConfigRoot, nowIso: o.now().toISOString(), key: o.key });
        if (d.kind === "pass") {
            // Remember tools/list requests so the RESPONSE can be pinned (TEAM-ADR-039).
            if (d.pinOnResponse)
                listRequests.set(idKey(id), id);
            relayLine(child.stdin, line);
            return;
        }
        if (d.kind === "reject") {
            stats[d.reason === "held" ? "held" : "blocked"] += 1;
            relayLine(o.agentOut, d.errorFrame);
            diag(rejectDiagnostic(d, o.serverName));
            return;
        }
        stats.forwarded += 1;
        const fwdNote = forwardDiagnostic(d, o.serverName);
        if (fwdNote !== undefined)
            diag(fwdNote);
        inflight.set(idKey(id), { id, entryHash: d.callEntryHash, t0: o.now().getTime() });
        relayLine(child.stdin, line);
    }, {
        maxBytes: maxLine,
        // TEAM-ADR-068 Addendum 1: an over-cap line is refused, never buffered whole or relayed.
        onOverflow: () => {
            stats.blocked += 1;
            relayLine(o.agentOut, OVERSIZE_ANSWER);
            diag(`oversize ${o.serverName}`);
        },
    });
    /**
     * A server line (fix pass 6, R6-1). Every message in it whose result carries
     * a tools array is checked, whatever its id and whether it is one object or
     * a JSON array: before, only an answer whose id matched a pending tools/list
     * exactly (type and value) was checked, and a client that matches by
     * Number(id) took "2" or "2.0" for request 2 while the gateway relayed it
     * unchecked. If the tools cannot be pinned, the whole line is withheld and
     * the agent gets -32045 under that message's id. An answer a client could
     * take for a pending tools/list that carries no tools array is withheld too.
     *
     * Answers to forwarded calls come first (fix pass 7, R7-2): the call RAN, so
     * its result is recorded before anything else, and the tools result in a
     * call's own answer is the tool's data, not the server's tools, so it is not
     * pinned. Before, such an answer could be withheld as -32045 ("nothing was
     * sent, asking again is safe") with no result on the ledger, and a retry ran
     * the tool twice. If a line must be withheld for another message in it, each
     * call it answered gets -32051, which says the call ran.
     */
    const fromServer = lineSplitter((line) => {
        const inbound = parseInbound(line);
        const messages = inbound.kind === "frame" ? [inbound.frame] : inbound.kind === "batch" ? [...inbound.elements] : [];
        const responseOf = (m) => {
            const rec = typeof m === "object" && m !== null && !Array.isArray(m) ? m : undefined;
            return rec === undefined || (rec.result === undefined && rec.error === undefined) ? undefined : rec;
        };
        // 1. Answers to forwarded calls: record their results.
        const callAnswers = [];
        const answering = new Set();
        for (const m of messages) {
            const rec = responseOf(m);
            if (rec === undefined)
                continue;
            const k = answered(inflight, rec.id === undefined ? null : rec.id, (v) => v.id);
            const call = k === undefined ? undefined : inflight.get(k);
            if (call === undefined)
                continue;
            inflight.delete(k);
            callAnswers.push(call.id);
            const t = o.now();
            // The call already ran: its answer reaches the agent whatever happens
            // to its record (TEAM-ADR-069 fix pass 1). A result that cannot be
            // recorded is said so on stderr; the next decision then finds the
            // ledger's problem and refuses.
            const note = resultDiagnostic(o.serverName, () => recordToolResultEntry({
                workspaceRoot: o.workspaceRoot,
                callEntryHash: call.entryHash,
                result: rec.error !== undefined ? rec.error : rec.result,
                isError: rec.error !== undefined,
                latencyMs: t.getTime() - call.t0,
                nowIso: t.toISOString(),
                key: o.key,
            }));
            if (note !== undefined)
                diag(note);
            answering.add(m);
        }
        // 2. Every other tools result is checked. A line withheld for one of them
        // is answered -32051 for every call it answered (the call ran), and -32045
        // under the other message's id only when no call answered in the line has
        // that id (fix pass 9, R9-1): a client takes the FIRST answer whose id
        // matches, so a same-id decoy's -32045 would tell it that a call which ran
        // is safe to ask again.
        const withholdLine = (replyId) => {
            for (const id of callAnswers)
                relayLine(o.agentOut, gatewayError(id, GATEWAY_ERROR_CALL_ANSWER_WITHHELD, CALL_ANSWER_WITHHELD_MESSAGE));
            if (callAnswers.length > 0)
                diag(`result ${o.serverName} -- ${callAnswers.length} call answer(s) in the same line were withheld with it; the call(s) ran`);
            if (!callAnswers.some((id) => looseIdMatch(replyId, id)))
                relayLine(o.agentOut, unpinnedListAnswer(replyId));
        };
        for (const m of messages) {
            const rec = responseOf(m);
            if (rec === undefined || answering.has(m))
                continue;
            const answerId = rec.id === undefined ? null : rec.id;
            const replyId = typeof answerId === "string" || typeof answerId === "number" ? answerId : null;
            const listKey = answered(listRequests, answerId, (v) => v);
            if (listKey !== undefined)
                listRequests.delete(listKey);
            const tools = toolsInResult(m);
            if (tools !== undefined) {
                const failed = pinFailure(o.serverName, () => {
                    const r = observeToolList(o.workspaceRoot, o.serverName, tools, o.now().toISOString(), o.key);
                    for (const l of observeDiagnostics(o.serverName, r))
                        diag(l);
                });
                if (failed !== undefined) {
                    diag(failed);
                    withholdLine(replyId);
                    return;
                }
            }
            else if (listKey !== undefined && rec.result !== undefined) {
                diag(`unpinned ${o.serverName} tools/list -- not relayed: the answer carries no tools array the gateway can check`);
                withholdLine(replyId);
                return;
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
