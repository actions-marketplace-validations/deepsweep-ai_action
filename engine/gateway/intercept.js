/**
 * The intercept–evaluate–record loop (TEAM-ADR-036) — the gateway's one
 * behavioural decision, kept pure of transport so stdio and HTTP share it and
 * so it is unit-tested without spawning anything.
 *
 * For every `tools/call`:
 *   1. `authorizeAction` (ADR-009/010) decides allow / deny / require-approval
 *      and appends its own `policy.decision` ledger entry (hashes only).
 *   2. a `gateway.tool_call` entry binds that decision to the call: server /
 *      tool / args as SHA-256 digests, the decision, and how the gateway ACTED
 *      (forwarded · blocked · held · approved). Content is never stored — the
 *      customer's own vault holds it; the compiler verifies disclosures
 *      against these hashes at packet time (selective disclosure).
 *   3. `require-approval` → deny-with-resumable-token (approval.ts). A retry
 *      carrying an approved token for the SAME tuple is forwarded.
 *   4. When the upstream answers, `gateway.tool_result` records resultHash,
 *      latency and isError, chained to the call entry.
 * A call the gateway refuses BEFORE policy (kill switch, tool drift) is
 * recorded by `recordToolRefusal` as `gateway.tool_refused` (TEAM-ADR-069).
 * Every entry is signed per TEAM-ADR-028 when a host-injected key is present.
 */
import { authorizeAction } from "../api/authorize.js";
import { canonicalize, sha256Canonical, sha256Hex } from "../review/canonical.js";
import { summarizeLedger } from "../review/ledger.js";
import { appendLedgerSignature, signLedgerEntry } from "../review/ledger-sign.js";
import { issueApprovalToken, redeemToken } from "./approval.js";
import { appendSignedEntry, describeStoreError, ledgerProblem, recordEntry, unsignedNote } from "./record.js";
import { readToolPins, storedPin } from "./toolpins.js";
export function resourceFor(serverName, toolName) {
    // ADR-009 resource matchers are LOGICAL identifiers (no scheme://authority);
    // `mcp/<server>/*` gives operators a per-server rule with the trailing wildcard.
    return `mcp/${serverName}/${toolName}`;
}
/** The approval binding of one call: principal, action, resource and arguments as digests (TEAM-ADR-036 Decision 4). */
function bindingOf(principal, resource, args) {
    return {
        principalHash: sha256Hex(principal ?? ""),
        actionHash: sha256Hex("tool.invoke"),
        resourceHash: sha256Hex(resource),
        argsHash: sha256Hex(canonicalize(args)),
    };
}
/** The words for a store failure that stopped a record: its code and file. */
function storeWhy(e) {
    const why = describeStoreError(e);
    if (why === undefined)
        throw e;
    return `a gateway record could not be written or read (${why})`;
}
/**
 * Decide + record ONE tool call. Never throws on policy grounds, nor for a
 * record that cannot be written (TEAM-ADR-069 fix pass 2, m-a): that is
 * reported in `callEntry: "corrupt"` with `unrecorded`, and the action the
 * policy decided is kept, so a denial is still answered as a denial.
 * Containment errors and anything that is not a store failure propagate.
 */
export function interceptToolCall(p) {
    const resource = resourceFor(p.serverName, p.toolName);
    // TEAM-ADR-041: hand the tool identity (and its TEAM-ADR-039 pin, when one
    // exists) to the authorizer so installed rule packs can classify it. A
    // DRIFTED tool never reaches here (decideFrame refuses it first); an
    // unreadable pin store yields no hash — classification then rests on the
    // name alone and says so ("vendor", never "pinned").
    const pinnedHash = storedPin(readToolPins(p.workspaceRoot), p.serverName, p.toolName)?.hash;
    const notes = [];
    let decisionUnrecorded;
    const authorize = authorizeAction({
        workspaceRoot: p.workspaceRoot,
        principal: p.principal,
        action: "tool.invoke",
        resource,
        nowIso: p.nowIso,
        key: p.key,
        tool: { serverName: p.serverName, toolName: p.toolName, ...(pinnedHash !== undefined ? { descriptionHash: pinnedHash } : {}) },
        ...(p.userConfigRoot !== undefined ? { userConfigRoot: p.userConfigRoot } : {}),
        // The materiality atom (C04) sees the call's arguments only here, where
        // they exist. Non-object args stay absent -- the atom then fails closed.
        ...(typeof p.args === "object" && p.args !== null && !Array.isArray(p.args)
            ? { callArgs: p.args }
            : {}),
        // Fix pass 2 (m-a): the signing rule of fix pass 1 (M2) now holds for the
        // decision's own entry too. Before, a sidecar unwritable from the start
        // threw here, so every call was refused -32045 "not recorded" although
        // its policy.decision was on the ledger, and a denial lost its -32040.
        onRecordFailure: (e, written) => {
            const why = describeStoreError(e);
            if (why === undefined)
                throw e;
            if (written === undefined)
                decisionUnrecorded = `a gateway record could not be written or read (${why})`;
            else
                notes.push(`the policy.decision entry is on the ledger, but ${unsignedNote(why, written.seq)}`);
        },
    });
    const binding = bindingOf(p.principal, resource, p.args);
    // Observe mode: record, forward, never block (ADR-009 advisory posture).
    const acted = authorize.actedOn ?? "allow";
    let action = acted === "deny" ? "blocked" : acted === "require-approval" ? "held" : "forwarded";
    if (!authorize.ledgerAppended) {
        // The decision itself is not on the ledger: nothing is acted on, no
        // approval is spent, and no call entry claims a decision that has no record.
        return { authorize, action, binding, callEntry: "corrupt", unrecorded: decisionUnrecorded ?? ledgerProblemOrRace(p.workspaceRoot) };
    }
    if (acted === "require-approval") {
        if (p.approvalToken !== undefined) {
            let r;
            try {
                r = redeemToken(p.workspaceRoot, p.approvalToken, binding, p.nowIso);
            }
            catch (e) {
                // The token store or the ledger failed while the approval was being
                // used (the residual stated in fix pass 1, m2). No call entry.
                return { authorize, action, binding, callEntry: "corrupt", unrecorded: `the approval could not be recorded as used: ${storeWhy(e)}` };
            }
            if (r.verdict === "unrecorded") {
                // The ledger refused approval.consumed, so the token was NOT spent
                // (fix pass 1, m2), and no call entry is written: the call is refused.
                return { authorize, action: "held", binding, callEntry: "corrupt", unrecorded: `the approval could not be recorded as used: ${ledgerProblemOrRace(p.workspaceRoot)}` };
            }
            if (r.ledger !== null && r.ledger !== "corrupt" && p.key !== undefined) {
                try {
                    appendLedgerSignature(p.workspaceRoot, signLedgerEntry(r.ledger, p.key));
                }
                catch (e) {
                    const why = describeStoreError(e);
                    if (why === undefined)
                        throw e;
                    notes.push(`the ${r.ledger.kind} entry is on the ledger, but ${unsignedNote(why, r.ledger.seq)}`);
                }
            }
            action = r.verdict === "redeemed" ? "approved" : "held";
        }
    }
    const base = {
        serverHash: sha256Hex(p.serverName),
        toolHash: sha256Hex(p.toolName),
        ...binding,
        decision: acted,
        mode: authorize.mode,
        rule: authorize.ruleLabel,
        action,
    };
    let rec;
    try {
        rec = recordEntry(p.workspaceRoot, "gateway.tool_call", base, p.nowIso, p.key);
    }
    catch (e) {
        // Fix pass 2 (m-a): kept as this call's outcome, so a denial stays a denial. The failed write left no torn line (M-4).
        return { authorize, action, binding, callEntry: "corrupt", unrecorded: storeWhy(e) };
    }
    if (rec.status === "refused")
        return { authorize, action, binding, callEntry: "corrupt", unrecorded: rec.why };
    const callEntry = rec.entry;
    if (rec.unsigned !== undefined)
        notes.push(`the gateway.tool_call entry is on the ledger, but ${rec.unsigned}`);
    let token;
    if (action === "held" && p.approvalToken === undefined) {
        try {
            token = issueApprovalToken(p.workspaceRoot, binding, callEntry.entryHash, p.nowIso, authorize.requiredApprovals);
        }
        catch (e) {
            const why = describeStoreError(e);
            if (why === undefined)
                throw e;
            notes.push(`the hold is on the ledger, but its approval token could not be stored (${why}), so no token was issued`);
        }
    }
    const note = notes.length === 0 ? {} : { note: notes.join("; ") };
    return token === undefined ? { authorize, action, binding, callEntry, ...note } : { authorize, action, approvalToken: token, binding, callEntry, ...note };
}
/**
 * Why the ledger refused an append that the decision's own read expected to
 * succeed: the problem a fresh read shows (the file became malformed, or it
 * is full), else a concurrent change.
 */
function ledgerProblemOrRace(workspaceRoot) {
    const s = summarizeLedger(workspaceRoot);
    return s.status === "ok" ? "the audit ledger changed during this decision, or has no room for the entry" : ledgerProblem(workspaceRoot, s.cause);
}
function resultPayload(p) {
    return { callEntryHash: p.callEntryHash, resultHash: sha256Canonical(p.result), isError: p.isError, latencyMs: Math.max(0, Math.round(p.latencyMs)) };
}
/**
 * Record the upstream's answer, chained to the call entry. Content → hash
 * only. The transports use this form: a refusal or a missing signature is
 * reported, never thrown, because the call already ran and its answer must
 * still reach the agent (TEAM-ADR-069 fix pass 1).
 */
export function recordToolResultEntry(p) {
    return recordEntry(p.workspaceRoot, "gateway.tool_result", resultPayload(p), p.nowIso, p.key);
}
/** Record the upstream's answer, chained to the call entry. Content → hash only. A refusal is "corrupt"; a signature failure throws. */
export function recordToolResult(p) {
    return appendSignedEntry(p.workspaceRoot, "gateway.tool_result", resultPayload(p), p.nowIso, p.key);
}
/**
 * Record a refusal the gateway made before policy: the kill switch, or a
 * drifted tool (TEAM-ADR-069 Decision 2). `gateway.tool_refused` carries the
 * same digests as `gateway.tool_call` (so a selective disclosure of the
 * server, tool, principal or arguments verifies against it) plus the closed
 * reason code, and for the kill switch which file refused. No
 * `policy.decision` precedes it: the policy was never asked. Frozen by
 * contracts/schemas/tool-refusal-record.v1.json.
 */
export function recordToolRefusal(p) {
    const resource = resourceFor(p.serverName, p.toolName);
    return recordEntry(p.workspaceRoot, "gateway.tool_refused", {
        serverHash: sha256Hex(p.serverName),
        toolHash: sha256Hex(p.toolName),
        ...bindingOf(p.principal, resource, p.args),
        reason: p.reason,
        ...(p.reason === "killed" ? { switchSource: p.switchSource } : {}),
    }, p.nowIso, p.key);
}
