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
 * Every entry is signed per TEAM-ADR-028 when a host-injected key is present.
 */
import { authorizeAction } from "../api/authorize.js";
import { canonicalize, sha256Hex } from "../review/canonical.js";
import { appendLedgerEntry } from "../review/ledger.js";
import { appendLedgerSignature, signLedgerEntry } from "../review/ledger-sign.js";
import { issueApprovalToken, redeemToken } from "./approval.js";
import { readToolPins } from "./toolpins.js";
export function resourceFor(serverName, toolName) {
    // ADR-009 resource matchers are LOGICAL identifiers (no scheme://authority);
    // `mcp/<server>/*` gives operators a per-server rule with the trailing wildcard.
    return `mcp/${serverName}/${toolName}`;
}
function record(root, kind, payload, nowIso, key) {
    const entry = appendLedgerEntry(root, kind, payload, nowIso);
    if (entry !== "corrupt" && key !== undefined)
        appendLedgerSignature(root, signLedgerEntry(entry, key));
    return entry;
}
/** Decide + record ONE tool call. Never throws on policy grounds; store-containment errors propagate (exit-3 class). */
export function interceptToolCall(p) {
    const resource = resourceFor(p.serverName, p.toolName);
    // TEAM-ADR-041: hand the tool identity (and its TEAM-ADR-039 pin, when one
    // exists) to the authorizer so installed rule packs can classify it. A
    // DRIFTED tool never reaches here (decideFrame refuses it first); an
    // unreadable pin store yields no hash — classification then rests on the
    // name alone and says so ("vendor", never "pinned").
    const pinnedHash = readToolPins(p.workspaceRoot)?.servers[p.serverName]?.[p.toolName]?.hash;
    const authorize = authorizeAction({
        workspaceRoot: p.workspaceRoot,
        principal: p.principal,
        action: "tool.invoke",
        resource,
        nowIso: p.nowIso,
        key: p.key,
        tool: { serverName: p.serverName, toolName: p.toolName, ...(pinnedHash !== undefined ? { descriptionHash: pinnedHash } : {}) },
        ...(p.userConfigRoot !== undefined ? { userConfigRoot: p.userConfigRoot } : {}),
    });
    const binding = {
        principalHash: sha256Hex(p.principal ?? ""),
        actionHash: sha256Hex("tool.invoke"),
        resourceHash: sha256Hex(resource),
        argsHash: sha256Hex(canonicalize(p.args)),
    };
    // Observe mode: record, forward, never block (ADR-009 advisory posture).
    const acted = authorize.actedOn ?? "allow";
    let action = "forwarded";
    let token;
    if (acted === "deny")
        action = "blocked";
    else if (acted === "require-approval") {
        if (p.approvalToken !== undefined) {
            const r = redeemToken(p.workspaceRoot, p.approvalToken, binding, p.nowIso);
            if (r.ledger !== null && r.ledger !== "corrupt" && p.key !== undefined)
                appendLedgerSignature(p.workspaceRoot, signLedgerEntry(r.ledger, p.key));
            action = r.verdict === "redeemed" ? "approved" : "held";
        }
        else
            action = "held";
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
    const callEntry = record(p.workspaceRoot, "gateway.tool_call", base, p.nowIso, p.key);
    if (action === "held" && callEntry !== "corrupt" && p.approvalToken === undefined) {
        token = issueApprovalToken(p.workspaceRoot, binding, callEntry.entryHash, p.nowIso);
    }
    return token === undefined ? { authorize, action, binding, callEntry } : { authorize, action, approvalToken: token, binding, callEntry };
}
/** Record the upstream's answer, chained to the call entry. Content → hash only. */
export function recordToolResult(p) {
    return record(p.workspaceRoot, "gateway.tool_result", { callEntryHash: p.callEntryHash, resultHash: sha256Hex(canonicalize(p.result)), isError: p.isError, latencyMs: Math.max(0, Math.round(p.latencyMs)) }, p.nowIso, p.key);
}
