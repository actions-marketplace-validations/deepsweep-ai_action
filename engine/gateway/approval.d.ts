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
    /** For status "revoked": "expired" (TTL) or "revoked" (explicit). */
    readonly reason?: string;
}
export declare function tokenHashOf(token: string): string;
/** Read the store; the LAST record per tokenHash wins (append-only state machine). */
export declare function readApprovals(workspaceRoot: string): Map<string, ApprovalRecord>;
/** Issue a pending token for a denied call. Returns the plaintext token exactly once. */
export declare function issueApprovalToken(workspaceRoot: string, binding: ApprovalBinding, denialEntryHash: string, nowIso: string): string;
export interface ApproveResult {
    readonly ok: boolean;
    readonly status: ApprovalStatus | "unknown";
    readonly ledger: LedgerEntry | "corrupt" | null;
}
/** Human approves a pending token. Records `approval.granted` in the ledger (hashes only). */
export declare function approveToken(workspaceRoot: string, token: string, approver: string, nowIso: string, key?: LedgerSigningKey, ttlMs?: number): ApproveResult;
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
export type RedeemVerdict = "redeemed" | "unknown" | "not-approved" | "binding-mismatch" | "expired";
/**
 * Consume an approved token on a retry. Single-use; the retry must present the
 * SAME (principal, action, resource, args) tuple the denial recorded, so an
 * approval for one call can never be replayed against a different one.
 */
export declare function redeemToken(workspaceRoot: string, token: string, binding: ApprovalBinding, nowIso: string, ttlMs?: number): {
    readonly verdict: RedeemVerdict;
    readonly ledger: LedgerEntry | "corrupt" | null;
};
