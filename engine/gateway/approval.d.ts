import { type LedgerEntry } from "../review/ledger.js";
import { type LedgerSigningKey } from "../review/ledger-sign.js";
export declare const APPROVALS_FILE = "approvals.jsonl";
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
export declare const DEFAULT_APPROVAL_TTL_MS: number;
export interface ApprovalBinding {
    readonly principalHash: string;
    readonly actionHash: string;
    readonly resourceHash: string;
    readonly argsHash: string;
}
export type ApprovalStatus = "pending" | "approved" | "consumed" | "revoked";
export interface ApprovalRecord extends ApprovalBinding {
    readonly tokenHash: string;
    readonly status: ApprovalStatus;
    /** Ledger entryHash of the denial that issued the token. */
    readonly denialEntryHash: string;
    readonly at: string;
    readonly approver?: string;
    /** C03 quorum: distinct named approvers required (default 1). */
    readonly required?: number;
    /** Hashes of the distinct approver names already granted. */
    readonly approverHashes?: readonly string[];
    /** For status "revoked": "expired" (TTL) or "revoked" (explicit). */
    readonly reason?: string;
}
export declare function tokenHashOf(token: string): string;
/** Read the store; the LAST record per tokenHash wins (append-only state machine). */
export declare function readApprovals(workspaceRoot: string): Map<string, ApprovalRecord>;
/** Issue a pending token for a denied call. Returns the plaintext token exactly once. */
export declare function issueApprovalToken(workspaceRoot: string, binding: ApprovalBinding, denialEntryHash: string, nowIso: string, requiredApprovals?: number): string;
export interface ApproveResult {
    readonly ok: boolean;
    readonly status: ApprovalStatus | "unknown";
    readonly ledger: LedgerEntry | "corrupt" | null;
}
/** Human approves a pending token. Records `approval.granted` in the ledger (hashes only). */
export declare function approveToken(workspaceRoot: string, token: string, approver: string, nowIso: string, key?: LedgerSigningKey, ttlMs?: number): ApproveResult;
/** One pending approval as a card can render it: hashes only, never a plaintext token. */
export interface PendingApproval {
    readonly tokenHash: string;
    readonly granted: number;
    readonly required: number;
    readonly principalHash?: string | undefined;
    readonly actionHash: string;
    readonly resourceHash: string;
    readonly argsHash: string;
    readonly at: string;
    readonly expiresInMs: number;
}
/** Pending, unexpired approvals for the approval card. The plaintext token is
 * never stored, so listing leaks nothing an approver could redeem with -- the
 * AGENT holds the token; the card only grants the record. */
export declare function listPendingApprovals(workspaceRoot: string, nowIso: string, ttlMs?: number): PendingApproval[];
/** Grant a pending record by its token hash — the approval-card path
 * (2026-09-17). SOUND because granting and redeeming are separate powers:
 * only the agent that received the one-time plaintext token can redeem, so
 * approving by hash releases exactly the call the denial bound, nothing
 * else. Same integrity gate as approveToken: a named approver, and never
 * the denied principal. */
export declare function approveByHash(workspaceRoot: string, th: string, approver: string, nowIso: string, key?: LedgerSigningKey, ttlMs?: number): ApproveResult;
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
export declare function approverIdentityKey(approver: string): string;
export interface RevokeResult {
    readonly ok: boolean;
    readonly status: ApprovalStatus | "unknown";
    readonly ledger: LedgerEntry | "corrupt" | null;
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
export declare function revokeToken(workspaceRoot: string, token: string, revoker: string, nowIso: string, key?: LedgerSigningKey): RevokeResult;
/** "unrecorded": the token would redeem, but the ledger refused its approval.consumed entry, so it was NOT consumed (TEAM-ADR-069 fix pass 1, m2). */
export type RedeemVerdict = "redeemed" | "unknown" | "not-approved" | "binding-mismatch" | "expired" | "quorum-unmet" | "unrecorded";
/**
 * Consume an approved token on a retry. Single-use; the retry must present the
 * SAME (principal, action, resource, args) tuple the denial recorded, so an
 * approval for one call can never be replayed against a different one.
 */
export declare function redeemToken(workspaceRoot: string, token: string, binding: ApprovalBinding, nowIso: string, ttlMs?: number): {
    readonly verdict: RedeemVerdict;
    readonly ledger: LedgerEntry | "corrupt" | null;
};
