/**
 * Transport-independent governance decision for ONE inbound MCP frame
 * (TEAM-ADR-040). Both the stdio gateway and the Streamable-HTTP gateway call
 * this so the two transports cannot drift in what they allow, deny, hold or
 * pin — the decision is defined once, tested once.
 *
 * A frame is classified into exactly one disposition:
 *   - "pass"     not a governed verb (or tools/list): forward untouched. If it
 *                is a tools/list REQUEST, `pinOnResponse` is true so the caller
 *                pins the response.
 *   - "forward"  a tools/call the policy permits, ALREADY RECORDED: forward it
 *                (the caller must remember callEntryHash to attribute the result).
 *                There is no forward without a call entry (TEAM-ADR-069).
 *   - "reject"   deny / hold / rug-pull-drift / kill switch, a tools/call the
 *                gateway cannot decide (TEAM-ADR-068), or one it cannot record
 *                (TEAM-ADR-069): DO NOT forward; the caller writes `errorFrame`
 *                back to the agent verbatim.
 *
 * Every decision about a named tools/call is on the ledger (TEAM-ADR-069): a
 * kill-switch state the ledger did not record is recorded first, as observed;
 * kill-switch and drift refusals are recorded as `gateway.tool_refused`; a
 * policy decision is recorded by the intercept loop. When the ledger cannot be
 * read or appended, nothing is forwarded or spent, in every mode; the refusal
 * says why in `unrecorded`, which the transports print as a diagnostic.
 *
 * A JSON-RPC BATCH never reaches decideFrame: `refuseBatch` answers it whole
 * (TEAM-ADR-068), so "every call is a policy decision" (TEAM-ADR-036
 * Decision 3) cannot be bypassed by wrapping a call in an array. Nor do bytes
 * the gateway cannot parse, or a message over the size cap: the transports
 * answer those with PARSE_ERROR_ANSWER and OVERSIZE_ANSWER (Addendum 1).
 */
import { batchRequestIds, foldName, GATEWAY_ERROR_APPROVAL_REQUIRED, GATEWAY_ERROR_DENIED, GATEWAY_ERROR_KILLED, GATEWAY_ERROR_TOOL_DRIFTED, GATEWAY_ERROR_UNDECIDABLE, GATEWAY_ERROR_UNRECORDABLE, gatewayError, hasFoldCollision, JSONRPC_PARSE_ERROR, lookalikeKey, MAX_MESSAGE_BYTES, toolCallOf } from "./frames.js";
import { killswitchState, observedKillswitchPayload, recordedKillswitchState } from "./killswitch.js";
import { interceptToolCall, recordToolRefusal } from "./intercept.js";
import { describeStoreError, ledgerProblem, recordEntry } from "./record.js";
import { isToolTripped } from "./toolpins.js";
import { LEDGER_MAX_BYTES, summarizeLedger, withLedgerLock } from "../review/ledger.js";
const UNDECIDABLE_CALL = "deepsweep: tools/call refused -- params must be an object whose name is a non-empty string, or the gateway cannot decide the call";
const UNDECIDABLE_BATCH = "deepsweep: JSON-RPC batch refused -- the gateway decides one message at a time; send each request on its own (MCP 2025-06-18 removed batching)";
const UNDECIDABLE_BATCH_TOO_LARGE = "deepsweep: JSON-RPC batch refused -- too many requests to answer one by one within the gateway's size cap; send each request on its own";
const UNDECIDABLE_LOOKALIKE = "deepsweep: message refused -- a method name or member key only looks like one the gateway governs (case, width, spacing or invisible characters); spell it exactly";
/** The gateway's answer to agent bytes it cannot parse as UTF-8 JSON: JSON-RPC's own parse error, id null (TEAM-ADR-068 Addendum 1). */
export const PARSE_ERROR_ANSWER = gatewayError(null, JSONRPC_PARSE_ERROR, "deepsweep: parse error -- the gateway forwards only messages it can parse as UTF-8 JSON, so this one was not sent");
/** The gateway's answer to an agent message larger than its size cap, id null (TEAM-ADR-068 Addendum 1). */
export const OVERSIZE_ANSWER = gatewayError(null, GATEWAY_ERROR_UNDECIDABLE, "deepsweep: message refused -- larger than the gateway's size cap, so it was not sent");
/** The gateway's answer to an HTTP body that declares a charset other than UTF-8, id null (TEAM-ADR-068 Addendum 1). */
export const CHARSET_ANSWER = gatewayError(null, GATEWAY_ERROR_UNDECIDABLE, "deepsweep: request refused -- the gateway reads UTF-8 JSON only; send Content-Type application/json with no charset, or charset=utf-8");
/** The methods the gateway governs: tools/call is decided, and a tools/list reply is pinned (TEAM-ADR-039). */
const GOVERNED_METHODS = ["tools/call", "tools/list"];
/**
 * TEAM-ADR-068 Addendum 1: true when a lenient server could read this frame
 * as a governed call other than the one the gateway would decide. That is a
 * look-alike "method" key or a method value that only folds to a governed
 * method (on any frame), a look-alike "params" or "id" key (on a governed
 * method), a look-alike "name" or "arguments" key inside tools/call params, or
 * two top-level argument keys that fold alike (the policy's argument
 * conditions read one of them). Go's encoding/json, for one, reads "Method",
 * "Params" or "Name" as the member the gateway checked, and the last of two
 * such keys wins.
 */
function isLookalike(frame) {
    if (lookalikeKey(frame, ["method"]) !== undefined)
        return true;
    const m = frame.method;
    if (typeof m !== "string")
        return false;
    if (!GOVERNED_METHODS.includes(m))
        return GOVERNED_METHODS.includes(foldName(m));
    if (lookalikeKey(frame, ["params", "id"]) !== undefined)
        return true;
    const p = frame.params;
    if (m !== "tools/call" || typeof p !== "object" || p === null)
        return false;
    if (lookalikeKey(p, ["name", "arguments"]) !== undefined)
        return true;
    const args = p["arguments"];
    return typeof args === "object" && args !== null && hasFoldCollision(args);
}
/** A refusal of a frame the gateway cannot decide as one call. No ledger entry: it names no tool to attribute a record to (TEAM-ADR-068 Decision 4, which TEAM-ADR-069 leaves standing for these). */
function undecidable(frame, tool, message) {
    return { kind: "reject", reason: "undecidable", tool, errorFrame: gatewayError(frame.id === undefined ? null : frame.id, GATEWAY_ERROR_UNDECIDABLE, message) };
}
const UNRECORDABLE_CALL = "deepsweep: tools/call refused -- the gateway cannot write its audit record, so it forwards nothing; the call was not sent, and can be retried once an operator restores the ledger";
/**
 * Room a decision needs on the ledger before it starts (TEAM-ADR-069 fix pass
 * 1, M1): the observed-switch, decision, call and approval entries, and the
 * result entry of a call that is forwarded, with margin. A call is not
 * forwarded unless its result can still be recorded; appendLedgerEntry
 * refuses anything past the cap itself, so the file never passes it.
 */
export const LEDGER_DECISION_HEADROOM_BYTES = 64 * 1024;
/**
 * Turn a thrown store failure into the reason a record could not be written,
 * naming the file (fix pass 1, m3). Anything that is not a store failure is
 * rethrown unchanged.
 */
function storeFailure(e) {
    const why = describeStoreError(e);
    if (why === undefined)
        throw e;
    return `a gateway record could not be written or read (${why})`;
}
/** Record one entry; on failure say why, never throw a store failure. */
function tryRecord(record) {
    try {
        const r = record();
        if (r.status === "refused")
            return { recorded: false, why: r.why };
        return r.unsigned === undefined ? { recorded: true } : { recorded: true, unsigned: r.unsigned };
    }
    catch (e) {
        return { recorded: false, why: storeFailure(e) };
    }
}
/**
 * What a refusal whose call entry is missing says about the ledger (fix pass
 * 2, m-a; the rule of fix pass 1, m3): "not recorded" only when this decision
 * wrote nothing; otherwise which of its entries ARE on the ledger. `since` is
 * the ledger's entry count when this decision began its own entries; the
 * decision holds the ledger lock, so every entry from there on is its own.
 * If the ledger cannot be read again, it says that instead of guessing.
 */
function missingCallEntry(workspaceRoot, since, why) {
    let s;
    try {
        s = summarizeLedger(workspaceRoot);
    }
    catch (e) {
        s = { status: "unreadable", cause: storeFailure(e) };
    }
    if (s.status !== "ok")
        return { unrecorded: `${why}; what else this decision wrote could not be checked, because the ledger could not be read again` };
    const kinds = [...s.summary.lastOfKind.values()].filter((e) => e.seq >= since).sort((a, b) => a.seq - b.seq).map((e) => e.kind);
    if (kinds.length === 0)
        return { unrecorded: why };
    return { partial: `the ${kinds.join(" and ")} ${kinds.length === 1 ? "entry is" : "entries are"} on the ledger, but the gateway.tool_call entry is not: ${why}` };
}
/** The ledger as this decision finds it: its summary, or why it cannot take this decision's records. */
function ledgerFor(workspaceRoot) {
    try {
        const r = summarizeLedger(workspaceRoot);
        if (r.status !== "ok")
            return { problem: ledgerProblem(workspaceRoot, r.cause) };
        // Fix pass 1, M3: a chain an earlier build restarted can never export;
        // new records would join evidence that cannot be verified.
        if (r.summary.restartedAt !== undefined)
            return { problem: ledgerProblem(workspaceRoot, "restarted") };
        if (r.summary.bytes + LEDGER_DECISION_HEADROOM_BYTES > LEDGER_MAX_BYTES)
            return { problem: ledgerProblem(workspaceRoot, "full") };
        return { summary: r.summary };
    }
    catch (e) {
        return { problem: storeFailure(e) };
    }
}
/**
 * A refusal of a call whose call entry is not on the ledger. A policy denial
 * is still answered -32040 (TEAM-ADR-069 Decision 1a; fix pass 2, m-a);
 * anything else -32045. The diagnostic says "not recorded" only when nothing
 * of this decision is on the ledger; otherwise the note says what is.
 */
function refusedWithoutCallEntry(call, reason, rule, missing, notes) {
    const said = "partial" in missing ? { note: [...notes, missing.partial].join("; ") } : { unrecorded: missing.unrecorded, ...(notes.length === 0 ? {} : { note: notes.join("; ") }) };
    if (reason === "blocked") {
        return { kind: "reject", reason, tool: call.name, rule: rule, errorFrame: gatewayError(call.id, GATEWAY_ERROR_DENIED, "deepsweep: tools/call denied by policy", { rule: rule }), ...said };
    }
    return { kind: "reject", reason, tool: call.name, errorFrame: gatewayError(call.id, GATEWAY_ERROR_UNRECORDABLE, UNRECORDABLE_CALL), ...said };
}
function unrecordable(call, why) {
    return { kind: "reject", reason: "unrecordable", tool: call.name, errorFrame: gatewayError(call.id, GATEWAY_ERROR_UNRECORDABLE, UNRECORDABLE_CALL), unrecorded: why };
}
/** Decide one already-parsed frame. Pure w.r.t. transport; performs the ledger side effects of a governed call. */
export function decideFrame(frame, ctx) {
    // TEAM-ADR-068 Addendum 1: a look-alike of a governed name is refused
    // before anything else reads the frame, in every mode.
    if (isLookalike(frame))
        return undecidable(frame, "(look-alike)", UNDECIDABLE_LOOKALIKE);
    const call = toolCallOf(frame);
    if (call === undefined) {
        if (frame.method !== "tools/call")
            return { kind: "pass", pinOnResponse: frame.method === "tools/list" };
        // TEAM-ADR-068: a tools/call that does not name its tool has no resource to
        // ask the policy about. Relaying it as "pass" would let the server decide
        // what the gateway could not, so it is refused, in every mode.
        return undecidable(frame, "(unnamed)", UNDECIDABLE_CALL);
    }
    // Fix pass 1 (M5): the whole decision holds the ledger lock, so its
    // records are contiguous and no other gateway on this workspace appends
    // between the read below and this decision's own entries. A lock that
    // cannot be taken is a ledger that cannot take records: the kill switch
    // still refuses, and a call is not forwarded.
    let started = false;
    try {
        return withLedgerLock(ctx.workspaceRoot, () => {
            started = true;
            return decideCall(call, ctx, undefined);
        });
    }
    catch (e) {
        // Only a failure to TAKE the lock decides again (without it); anything
        // thrown by the decision itself propagates, as before.
        if (started)
            throw e;
        return decideCall(call, ctx, storeFailure(e));
    }
}
/** The decision about one named tools/call. `lockProblem`: why the ledger lock could not be taken, if it could not. */
function decideCall(call, ctx, lockProblem) {
    // TEAM-ADR-069: read the ledger ONCE, before anything is decided or spent.
    // A ledger that cannot be read cannot take this decision's record.
    const ledger = lockProblem === undefined ? ledgerFor(ctx.workspaceRoot) : { problem: lockProblem };
    let problem = "problem" in ledger ? ledger.problem : undefined;
    const notes = [];
    const ks = killswitchState(ctx.workspaceRoot, ctx.userConfigRoot);
    // TEAM-ADR-069 Decision 3: a switch state the ledger did not record (the
    // file created or deleted by hand) is recorded first, as observed.
    // The ledger's entry count once any observed-switch entry is written: every
    // later entry is this decision's own (the lock is held), which is how a
    // refusal says truthfully what of it is on the ledger (fix pass 2, m-a).
    let since = "summary" in ledger ? ledger.summary.count : 0;
    if ("summary" in ledger && recordedKillswitchState(ledger.summary.lastOfKind.get("gateway.killswitch")) !== (ks.active ? "on" : "off")) {
        const r = tryRecord(() => recordEntry(ctx.workspaceRoot, "gateway.killswitch", observedKillswitchPayload(ks), ctx.nowIso, ctx.key));
        if (!r.recorded)
            problem = r.why;
        else {
            since += 1;
            if (r.unsigned !== undefined)
                notes.push(`the observed kill-switch entry is on the ledger, but ${r.unsigned}`);
        }
    }
    const refusal = { workspaceRoot: ctx.workspaceRoot, principal: ctx.principal, serverName: ctx.serverName, toolName: call.name, args: call.args, nowIso: ctx.nowIso, key: ctx.key };
    /** The diagnostic fields of a refusal that was or was not recorded. */
    const outcome = (r) => {
        if (r === undefined)
            return { unrecorded: problem };
        if (!r.recorded)
            return { unrecorded: r.why };
        const all = r.unsigned === undefined ? notes : [...notes, `the refusal is on the ledger, but ${r.unsigned}`];
        return all.length === 0 ? {} : { note: all.join("; ") };
    };
    // The kill switch outranks every other disposition, including drift and an
    // unrecordable ledger: an operator who threw it wants NOTHING forwarded, and
    // an unreadable switch file counts as thrown (killswitch.ts fail-closed
    // contract). The refusal is recorded (Decision 2) whenever the ledger can
    // take it.
    if (ks.active) {
        const r = problem === undefined ? tryRecord(() => recordToolRefusal({ ...refusal, reason: "killed", switchSource: ks.source })) : undefined;
        return { kind: "reject", reason: "killed", tool: call.name, errorFrame: gatewayError(call.id, GATEWAY_ERROR_KILLED, "deepsweep: kill switch active -- every tool call is refused until an operator resumes (deepsweep-gateway resume)", { tool: call.name }), ...outcome(r) };
    }
    if (isToolTripped(ctx.workspaceRoot, ctx.serverName, call.name)) {
        const r = problem === undefined ? tryRecord(() => recordToolRefusal({ ...refusal, reason: "drifted" })) : undefined;
        return { kind: "reject", reason: "drifted", tool: call.name, errorFrame: gatewayError(call.id, GATEWAY_ERROR_TOOL_DRIFTED, "deepsweep: tool description drifted since it was pinned — refused until a human re-pins (deepsweep-gateway repin)", { tool: call.name }), ...outcome(r) };
    }
    // TEAM-ADR-069 Decision 1: nothing is decided under policy, and no approval
    // token is spent, for a call that cannot be recorded. In every mode.
    if (problem !== undefined)
        return unrecordable(call, problem);
    let r;
    try {
        r = interceptToolCall({
            workspaceRoot: ctx.workspaceRoot,
            principal: ctx.principal,
            serverName: ctx.serverName,
            toolName: call.name,
            args: call.args,
            approvalToken: call.approvalToken,
            userConfigRoot: ctx.userConfigRoot,
            nowIso: ctx.nowIso,
            key: ctx.key,
        });
    }
    catch (e) {
        // interceptToolCall reports its own recording failures (fix pass 2,
        // m-a); a store failure thrown past it anyway still refuses the call,
        // and says what of this decision is on the ledger.
        return refusedWithoutCallEntry(call, "unrecordable", undefined, missingCallEntry(ctx.workspaceRoot, since, storeFailure(e)), notes);
    }
    if (r.note !== undefined)
        notes.push(r.note);
    const noted = notes.length === 0 ? {} : { note: notes.join("; ") };
    if (r.callEntry === "corrupt") {
        // No call entry: neither a forward nor a hold, whose token would be bound
        // to an entry that does not exist. A denial is still the denial.
        const missing = missingCallEntry(ctx.workspaceRoot, since, r.unrecorded ?? "the audit ledger refused the call entry");
        return refusedWithoutCallEntry(call, r.action === "blocked" ? "blocked" : "unrecordable", r.authorize.ruleLabel, missing, notes);
    }
    if (r.action === "blocked") {
        return { kind: "reject", reason: "blocked", tool: call.name, rule: r.authorize.ruleLabel, errorFrame: gatewayError(call.id, GATEWAY_ERROR_DENIED, "deepsweep: tools/call denied by policy", { rule: r.authorize.ruleLabel }), ...noted };
    }
    if (r.action === "held") {
        const data = { rule: r.authorize.ruleLabel };
        if (r.approvalToken !== undefined)
            data["approvalToken"] = r.approvalToken;
        return { kind: "reject", reason: "held", tool: call.name, rule: r.authorize.ruleLabel, errorFrame: gatewayError(call.id, GATEWAY_ERROR_APPROVAL_REQUIRED, "deepsweep: human approval required — retry with the approval token in params._meta[\"deepsweep/approval\"] once granted", data), ...noted };
    }
    // Fix pass 1, M2: the call entry says forwarded (or approved), so the call
    // is forwarded even when a signature could not be written. The entry is
    // true; the verifier reports the missing signature as a gap.
    return { kind: "forward", callEntryHash: r.callEntry.entryHash, intercept: r, tool: call.name, ...noted };
}
/**
 * The operator's diagnostic line for a refusal, shared by both transports so
 * they cannot word it differently (TEAM-ADR-040 Decision 1): the reason, the
 * server and tool, the deciding rule, and, when the refusal is not on the
 * ledger, why (TEAM-ADR-069).
 */
export function rejectDiagnostic(d, serverName) {
    return `${d.reason} ${serverName}/${d.tool}${d.rule !== undefined ? ` rule=${d.rule}` : ""}${d.unrecorded !== undefined ? ` -- not recorded: ${d.unrecorded}` : ""}${d.note !== undefined ? ` -- ${d.note}` : ""}`;
}
/** The operator's diagnostic line for a forwarded call, when something about its record is missing (fix pass 1, M2); otherwise undefined. */
export function forwardDiagnostic(d, serverName) {
    return d.note === undefined ? undefined : `forwarded ${serverName}/${d.tool} -- ${d.note}`;
}
/**
 * Refuse a JSON-RPC batch WHOLE, in every mode (TEAM-ADR-068). Nothing in it
 * is relayed. Deciding each element and relaying only the permitted ones
 * would rewrite the frame the agent sent (TEAM-ADR-036 Decision 2), and MCP
 * 2025-06-18 removed batching, so current clients send one message at a
 * time. Each request gets its own error, as JSON-RPC 2.0 answers a batch; a
 * notification gets none. A batch with no request still gets one id-null
 * error, so a refusal is never silent. The answer never outgrows `maxBytes`
 * (Addendum 1): a small request can carry a long answer, so a batch whose
 * per-id answer would exceed the cap gets ONE id-null error instead.
 */
export function refuseBatch(elements, maxBytes = MAX_MESSAGE_BYTES) {
    const ids = batchRequestIds(elements);
    if (ids.length === 0)
        return { errorFrame: gatewayError(null, GATEWAY_ERROR_UNDECIDABLE, UNDECIDABLE_BATCH), refused: 1, answer: "no-request" };
    const answers = [];
    let size = 1; // "[" now; each answer adds its bytes plus one "," or the closing "]"
    for (const id of ids) {
        const a = gatewayError(id, GATEWAY_ERROR_UNDECIDABLE, UNDECIDABLE_BATCH);
        size += Buffer.byteLength(a) + 1;
        if (size > maxBytes)
            return { errorFrame: gatewayError(null, GATEWAY_ERROR_UNDECIDABLE, UNDECIDABLE_BATCH_TOO_LARGE), refused: ids.length, answer: "too-large" };
        answers.push(a);
    }
    return { errorFrame: `[${answers.join(",")}]`, refused: ids.length, answer: "per-id" };
}
