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
import { appendLedgerEntry, withLedgerLock } from "../review/ledger.js";
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
/**
 * Append one approval record, holding the ledger lock, and roll a failed
 * write back (TEAM-ADR-069 fix pass 2, found alongside M-4). A record torn by
 * a full disk was skipped on read, and so was the NEXT record, which was
 * appended onto the same line: a lost "consumed" record let one approval be
 * redeemed a second time. The lock is what makes rolling back safe, because
 * no other writer that takes it can have appended since (the gateway already
 * holds it for a whole decision, so this is re-entrant there). If a torn
 * record could not be rolled back (the truncation failed too), the next record
 * still starts on a new line, so it is never glued onto the torn one and lost
 * with it (fix pass 3, R3-4: a lost "consumed" record let a token forward twice).
 */
function writeRecord(workspaceRoot, r) {
    withLedgerLock(workspaceRoot, () => appendStoreLine(workspaceRoot, APPROVALS_FILE, `${JSON.stringify(r)}\n`, refuse, { rollBackOnFailure: true, startOnNewLine: true }), refuse);
}
/** Issue a pending token for a denied call. Returns the plaintext token exactly once. */
export function issueApprovalToken(workspaceRoot, binding, denialEntryHash, nowIso, requiredApprovals) {
    const token = randomBytes(18).toString("base64url");
    const required = typeof requiredApprovals === "number" && Number.isInteger(requiredApprovals) && requiredApprovals > 1 ? requiredApprovals : undefined;
    writeRecord(workspaceRoot, { ...binding, tokenHash: tokenHashOf(token), status: "pending", denialEntryHash, at: nowIso, ...(required !== undefined ? { required } : {}) });
    return token;
}
/** Human approves a pending token. Records `approval.granted` in the ledger (hashes only). */
export function approveToken(workspaceRoot, token, approver, nowIso, key, ttlMs = DEFAULT_APPROVAL_TTL_MS) {
    return approveByHash(workspaceRoot, tokenHashOf(token), approver, nowIso, key, ttlMs);
}
/** Pending, unexpired approvals for the approval card. The plaintext token is
 * never stored, so listing leaks nothing an approver could redeem with -- the
 * AGENT holds the token; the card only grants the record. */
export function listPendingApprovals(workspaceRoot, nowIso, ttlMs = DEFAULT_APPROVAL_TTL_MS) {
    const out = [];
    for (const [th, r] of readApprovals(workspaceRoot)) {
        if (r.status !== "pending" || isExpired(r.at, nowIso, ttlMs))
            continue;
        const age = Date.parse(nowIso) - Date.parse(r.at);
        out.push({
            tokenHash: th,
            granted: (r.approverHashes ?? []).length,
            required: r.required ?? 1,
            principalHash: r.principalHash,
            actionHash: r.actionHash,
            resourceHash: r.resourceHash,
            argsHash: r.argsHash,
            at: r.at,
            expiresInMs: Math.max(0, ttlMs - (Number.isFinite(age) ? age : ttlMs)),
        });
    }
    return out;
}
/** Grant a pending record by its token hash — the approval-card path
 * (2026-09-17). SOUND because granting and redeeming are separate powers:
 * only the agent that received the one-time plaintext token can redeem, so
 * approving by hash releases exactly the call the denial bound, nothing
 * else. Same integrity gate as approveToken: a named approver, and never
 * the denied principal. */
export function approveByHash(workspaceRoot, th, approver, nowIso, key, ttlMs = DEFAULT_APPROVAL_TTL_MS) {
    // A grant with no named grantor is not a grant (2026-09-17 audit, C02).
    // The name is still unauthenticated free text -- the TEAM-ADR-053 limit
    // stands -- but an EMPTY name can no longer slide through on a default.
    if (approver.trim().length === 0)
        return { ok: false, status: "unknown", ledger: null };
    const cur = readApprovals(workspaceRoot).get(th);
    if (cur === undefined)
        return { ok: false, status: "unknown", ledger: null };
    if (cur.status !== "pending")
        return { ok: false, status: cur.status, ledger: null };
    // Separation of duties, executable form (audit C05): the principal that
    // was denied cannot be the name that approves the retry. Hash-equality of
    // unauthenticated names is the honest ceiling until TEAM-ADR-056 ships a
    // verifier-rooted approver; it stops the lazy self-approval, not a liar.
    if (cur.principalHash !== undefined && sha256Hex(approverIdentityKey(approver)) === cur.principalHash) {
        const ledger = appendLedgerEntry(workspaceRoot, "approval.refused_self", { tokenHash: th, denialEntryHash: cur.denialEntryHash, approverHash: sha256Hex(approverIdentityKey(approver)) }, nowIso);
        if (ledger !== "corrupt" && key !== undefined)
            appendLedgerSignature(workspaceRoot, signLedgerEntry(ledger, key));
        return { ok: false, status: "pending", ledger };
    }
    if (isExpired(cur.at, nowIso, ttlMs)) {
        return { ok: false, status: "revoked", ledger: markRevoked(workspaceRoot, cur, "expired", "ttl", nowIso, key) };
    }
    // C03 quorum: distinct named approvers accumulate on the record; the
    // status flips to approved only when the rule's requirement is met. The
    // same name cannot count twice (hash membership), and every grant --
    // including a partial one -- lands on the ledger with its progress.
    const required = cur.required ?? 1;
    const aHash = sha256Hex(approverIdentityKey(approver));
    const have = new Set(cur.approverHashes ?? []);
    if (have.has(aHash))
        return { ok: false, status: "pending", ledger: null };
    have.add(aHash);
    const granted = have.size;
    const done = granted >= required;
    const next = {
        ...cur,
        status: done ? "approved" : "pending",
        approver,
        at: nowIso,
        approverHashes: [...have],
        ...(cur.required !== undefined ? { required: cur.required } : {}),
    };
    writeRecord(workspaceRoot, next);
    const ledger = appendLedgerEntry(workspaceRoot, done ? "approval.granted" : "approval.granted_partial", { tokenHash: th, denialEntryHash: cur.denialEntryHash, approverHash: aHash, resourceHash: cur.resourceHash, granted, required }, nowIso);
    if (ledger !== "corrupt" && key !== undefined)
        appendLedgerSignature(workspaceRoot, signLedgerEntry(ledger, key));
    return { ok: done, status: done ? "approved" : "pending", ledger };
}
/**
 * Canonical form of an approver identity, before hashing.
 *
 * THE DEFECT THIS CLOSES (found by the 2026-09-19 claim audit). Quorum
 * membership hashed `approver.trim()` raw, so ONE person satisfied a 2-of-2
 * dual-authorization rule by granting twice as "brad" then "Brad". The Set
 * saw two distinct hashes and flipped the record to approved. Case was the
 * cheapest bypass; Unicode width and combining forms are the same class
 * ("ｂrad", "brad" + combining marks), which is why NFKC runs before casing.
 *
 * DISPLAY IS UNAFFECTED: the record still stores the string as typed. This
 * governs IDENTITY COMPARISON only.
 *
 * Honest limit, stated rather than implied: this makes one PERSON harder to
 * count twice under trivially different spellings. It does not authenticate
 * anyone — the approver remains caller-supplied text (TEAM-ADR-053), and
 * TEAM-ADR-056's verifier-rooted identity is the real fix. Two people
 * colluding, or one person using two genuinely different names, is outside
 * what any normalization can reach.
 */
export function approverIdentityKey(approver) {
    return approver.normalize("NFKC").trim().toLowerCase();
}
/** Transition a record to revoked and put the transition on the ledger. */
function markRevoked(workspaceRoot, cur, reason, revoker, nowIso, key) {
    writeRecord(workspaceRoot, { ...cur, status: "revoked", reason, at: nowIso });
    const ledger = appendLedgerEntry(workspaceRoot, "approval.revoked", { tokenHash: cur.tokenHash, denialEntryHash: cur.denialEntryHash, revokerHash: sha256Hex(approverIdentityKey(revoker)), resourceHash: cur.resourceHash, reason }, nowIso);
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
    // QUORUM IS RE-DERIVED HERE, never trusted from the status field (2026-09-19
    // audit). `status` is one byte in a file the record's own ADR says an agent
    // can append to; a record reading "approved" with one hash against a
    // requirement of two must not redeem. Deny-wins: an absent hash list counts
    // as zero approvers, so a hand-written record cannot redeem by omission.
    const requiredAtRedeem = cur.required ?? 1;
    if ((cur.approverHashes ?? []).length < requiredAtRedeem) {
        return { verdict: "quorum-unmet", ledger: null };
    }
    if (isExpired(cur.at, nowIso, ttlMs)) {
        return { verdict: "expired", ledger: markRevoked(workspaceRoot, cur, "expired", "ttl", nowIso, undefined) };
    }
    const same = canonicalize({ p: cur.principalHash, a: cur.actionHash, r: cur.resourceHash, g: cur.argsHash }) ===
        canonicalize({ p: binding.principalHash, a: binding.actionHash, r: binding.resourceHash, g: binding.argsHash });
    if (!same)
        return { verdict: "binding-mismatch", ledger: null };
    // TEAM-ADR-069 fix pass 1 (m2): the ledger entry FIRST, then the store. A
    // ledger that refuses the entry (or a write that throws) leaves the token
    // approved, so a call the gateway then refuses has not spent a human's
    // approval. The residual order risk is stated in TEAM-ADR-069 Addendum 1:
    // if the store write fails after the entry, approval.consumed is on the
    // ledger while the token stays approved, and the call is refused.
    const ledger = appendLedgerEntry(workspaceRoot, "approval.consumed", { tokenHash: th, denialEntryHash: cur.denialEntryHash, resourceHash: cur.resourceHash }, nowIso);
    if (ledger === "corrupt")
        return { verdict: "unrecorded", ledger };
    writeRecord(workspaceRoot, { ...cur, status: "consumed", at: nowIso });
    return { verdict: "redeemed", ledger };
}
