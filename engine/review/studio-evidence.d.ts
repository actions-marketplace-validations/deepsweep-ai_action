import { type SignedTreeHead } from "../evidence/treehead.js";
import { type LedgerEntry, type LedgerInclusionProof } from "./ledger.js";
/** The commitment block the embedded verifier checks against. */
export interface StudioEvidence {
    /** ADR-DS-006 envelope over (treeSize, rootHash) of the LEDGER tree. */
    readonly signedTreeHead: SignedTreeHead;
    /**
     * SPKI DER, base64 — present so the signature check runs with NO network
     * (ADR-022). It is the subject of the check, never its trust anchor; the
     * verifier re-derives the key id from these bytes and prints it for the
     * reader to compare against the key they already hold.
     */
    readonly publicKey: string;
    /** One RFC 6962 inclusion proof per embedded row, in ledger order. */
    readonly inclusion: readonly LedgerInclusionProof[];
}
/** Why a Studio artifact carries no commitment. Every value is printed. */
export type StudioUnsignedReason = "no-signing-key" | "empty-ledger" | "malformed-ledger" | "chain-broken" | "unreadable-key";
export type StudioEvidenceResult = {
    readonly status: "signed";
    readonly evidence: StudioEvidence;
} | {
    readonly status: "unsigned";
    readonly reason: StudioUnsignedReason;
};
/**
 * The sentence the artifact prints when it carries no commitment. Wording is
 * contract (a test pins it) for the same reason the packet's `standing` is:
 * this is the sentence a reader of an UNSIGNED file sees, and it must not be
 * mistakable for authenticity.
 *
 * `no-signing-key` is the TRUE case today — the Ed25519 signing ceremony has
 * not happened, so every artifact the engine writes right now lands here.
 * TEAM-ADR-050 anchors heads externally WITHOUT a key, which binds bytes to
 * time; attribution is the separate property this sentence says is missing.
 */
export declare const STUDIO_UNSIGNED_NOTE: Readonly<Record<StudioUnsignedReason, string>>;
/**
 * Build the Studio's commitment block, or say precisely why there is none.
 *
 * Refuses to sign over a broken chain (TEAM-ADR-046: a signed tree head over
 * edited history attests the tampering). Total over its inputs — an operator
 * error becomes a printed refusal, never a thrown stack and never a silently
 * unsigned file that looks the same as a deliberate one.
 */
export declare function buildStudioEvidence(entries: readonly LedgerEntry[] | undefined, nowIso: string, signWithPem: string | undefined): StudioEvidenceResult;
