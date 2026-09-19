/**
 * Deny-with-resumable-token (TEAM-ADR-036).
 *
 * `require-approval` on a LIVE stream is not implemented by holding the
 * in-flight request (agent-side timeouts make that a race). Instead the
 * gateway DENIES fail-closed (ADR-010 posture kept intact), records the
 * decision, and issues a single-use approval token bound to the exact
 * (principalHash, actionHash, resourceHash, argsHash) tuple. A human approves
 * out-of-band; the agent retries carrying the token in `_meta`; the token
 * converts THAT retry — and only a retry of the same tuple — to allow.
 *
 * The evidence trail this produces reads: denial → out-of-band approval →
 * permitted retry. Every step is a ledger entry (metadata only: hashes +
 * token hash). THE HONEST LIMIT, for anyone writing copy about this trail:
 * the `approver` field is caller-supplied free text (default "operator") and
 * is NOT authenticated — the entries prove the approval protocol ran and are
 * externally verifiable; they do not prove the approver was a human, or who.
 * Shipped copy must never claim otherwise (TEAM-ADR-053; the guard is
 * tests/approver-identity-language-guard.test.ts).
 *
 * Store: `.deepsweep/approvals.jsonl` (contained store, append-only, 0600).
 * The token itself is random and is NEVER written to the ledger — only its
 * SHA-256, so the ledger cannot be used to mint an approval.
 */
import { randomBytes } from "node:crypto";
import { canonicalize, sha256Hex } from "../review/canonical.js";
import { appendLedgerEntry } from "../review/ledger.js";
import { appendStoreLine, readStoreText } from "../review/store.js";
import { appendLedgerSignature, signLedgerEntry } from "../review/ledger-sign.js";
export const APPROVALS_FILE = "approvals.jsonl";
/**
 * Approvals EXPIRE (TEAM-ADR-055). Before this, a granted token lived until
 * consumed — a standing convert-to-allow capability with no clock, found by
 * the 2026-08-27 trust-score refutation. The flow this protects is live
 * (deny -> human approves -> agent retries within the same working session),
 * so the default is minutes. Both checks measure from the record's own `at`:
 * a PENDING token expires between issue and approve (the human would be
 * approving a stale request); an APPROVED token expires between grant and
 * redeem (the standing capability). An unparseable timestamp counts as
 * expired — fail closed, never fail eternal.
 */
export const DEFAULT_APPROVAL_TTL_MS = 15 * 60 * 1000;
function isExpired(recordAtIso, nowIso, ttlMs) {
    const at = Date.parse(recordAtIso);
    const now = Date.parse(nowIso);
    if (!Number.isFinite(at) || !Number.isFinite(now))
        return true;
    return now - at > ttlMs;
}
class ApprovalRefusalError extends Error {
    constructor(reason) {
        super(`approvals refused: ${reason}`);
        this.name = "ApprovalRefusalError";
    }
}
const refuse = (reason) => new ApprovalRefusalError(reason);
export function tokenHashOf(token) {
    return sha256Hex(token);
}
/** Read the store; the LAST record per tokenHash wins (append-only state machine). */
export function readApprovals(workspaceRoot) {
    const text = readStoreText(workspaceRoot, APPROVALS_FILE, refuse);
    const out = new Map();
    if (text === undefined)
        return out;
    for (const line of text.split("\n")) {
        if (line.trim().length === 0)
            continue;
        try {
            const r = JSON.parse(line);
            if (typeof r.tokenHash === "string" && typeof r.status === "string")
                out.set(r.tokenHash, r);
        }
        catch {
            // A torn/malformed line is skipped: it can only ever REMOVE an approval, never grant one.
        }
    }
    return out;
}
function writeRecord(workspaceRoot, r) {
    appendStoreLine(workspaceRoot, APPROVALS_FILE, `${JSON.stringify(r)}\n`, refuse);
}
/** Issue a pending token for a denied call. Returns the plaintext token exactly once. */
export function issueApprovalToken(workspaceRoot, binding, denialEntryHash, nowIso) {
    const token = randomBytes(18).toString("base64url");
    writeRecord(workspaceRoot, { ...binding, tokenHash: tokenHashOf(token), status: "pending", denialEntryHash, at: nowIso });
    return token;
}
/** Human approves a pending token. Records `approval.granted` in the ledger (hashes only). */
export function approveToken(workspaceRoot, token, approver, nowIso, key, ttlMs = DEFAULT_APPROVAL_TTL_MS) {
    const th = tokenHashOf(token);
    const cur = readApprovals(workspaceRoot).get(th);
    if (cur === undefined)
        return { ok: false, status: "unknown", ledger: null };
    if (cur.status !== "pending")
        return { ok: false, status: cur.status, ledger: null };
    if (isExpired(cur.at, nowIso, ttlMs)) {
        return { ok: false, status: "revoked", ledger: markRevoked(workspaceRoot, cur, "expired", "ttl", nowIso, key) };
    }
    const next = { ...cur, status: "approved", approver, at: nowIso };
    writeRecord(workspaceRoot, next);
    const ledger = appendLedgerEntry(workspaceRoot, "approval.granted", { tokenHash: th, denialEntryHash: cur.denialEntryHash, approverHash: sha256Hex(approver), resourceHash: cur.resourceHash }, nowIso);
    if (ledger !== "corrupt" && key !== undefined)
        appendLedgerSignature(workspaceRoot, signLedgerEntry(ledger, key));
    return { ok: true, status: "approved", ledger };
}
/** Transition a record to revoked and put the transition on the ledger. */
function markRevoked(workspaceRoot, cur, reason, revoker, nowIso, key) {
    writeRecord(workspaceRoot, { ...cur, status: "revoked", reason, at: nowIso });
    const ledger = appendLedgerEntry(workspaceRoot, "approval.revoked", { tokenHash: cur.tokenHash, denialEntryHash: cur.denialEntryHash, revokerHash: sha256Hex(revoker), resourceHash: cur.resourceHash, reason }, nowIso);
    if (ledger !== "corrupt" && key !== undefined)
        appendLedgerSignature(workspaceRoot, signLedgerEntry(ledger, key));
    return ledger;
}
/**
 * Explicitly revoke a pending or approved token (TEAM-ADR-055) — the writer
 * the "revoked" status never had: the status existed in the type while no
 * code could produce it, so an operator who granted a wrong approval had no
 * way to take it back short of deleting the store.
 *
 * THE HONEST LIMIT (TEAM-ADR-053 discipline): `revoker`, like `approver`, is
 * caller-supplied free text and is NOT authenticated. The ledger proves the
 * revocation protocol ran and is externally verifiable; it does not prove
 * who ran it. Copy about this trail must never claim otherwise.
 *
 * A consumed token is terminal: revoking it would rewrite history the
 * ledger already attests, so that returns ok:false rather than a record.
 */
export function revokeToken(workspaceRoot, token, revoker, nowIso, key) {
    const th = tokenHashOf(token);
    const cur = readApprovals(workspaceRoot).get(th);
    if (cur === undefined)
        return { ok: false, status: "unknown", ledger: null };
    if (cur.status !== "pending" && cur.status !== "approved")
        return { ok: false, status: cur.status, ledger: null };
    return { ok: true, status: "revoked", ledger: markRevoked(workspaceRoot, cur, "revoked", revoker, nowIso, key) };
}
/**
 * Consume an approved token on a retry. Single-use; the retry must present the
 * SAME (principal, action, resource, args) tuple the denial recorded, so an
 * approval for one call can never be replayed against a different one.
 */
export function redeemToken(workspaceRoot, token, binding, nowIso, ttlMs = DEFAULT_APPROVAL_TTL_MS) {
    const th = tokenHashOf(token);
    const cur = readApprovals(workspaceRoot).get(th);
    if (cur === undefined)
        return { verdict: "unknown", ledger: null };
    if (cur.status !== "approved")
        return { verdict: "not-approved", ledger: null };
    if (isExpired(cur.at, nowIso, ttlMs)) {
        return { verdict: "expired", ledger: markRevoked(workspaceRoot, cur, "expired", "ttl", nowIso, undefined) };
    }
    const same = canonicalize({ p: cur.principalHash, a: cur.actionHash, r: cur.resourceHash, g: cur.argsHash }) ===
        canonicalize({ p: binding.principalHash, a: binding.actionHash, r: binding.resourceHash, g: binding.argsHash });
    if (!same)
        return { verdict: "binding-mismatch", ledger: null };
    writeRecord(workspaceRoot, { ...cur, status: "consumed", at: nowIso });
    const ledger = appendLedgerEntry(workspaceRoot, "approval.consumed", { tokenHash: th, denialEntryHash: cur.denialEntryHash, resourceHash: cur.resourceHash }, nowIso);
    return { verdict: "redeemed", ledger };
}
