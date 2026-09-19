/**
 * ADR-018 — append-only audit ledger (S4.3 v0) + chain-head anchoring.
 *
 * LEDGER: `.deepsweep/ledger.jsonl`, one JSON entry per line. Every entry
 * carries `prevHash` (the previous entry's `entryHash`; 64 zeros at
 * genesis) and `entryHash` = SHA-256 over canonicalize(entry minus
 * entryHash). Internal chain verification therefore detects any EDIT —
 * but an attacker who replaces the whole file writes a self-consistent
 * chain, which is exactly what anchoring exists to catch.
 *
 * ANCHOR: {chainHead, entryCount, anchoredAt, genesisHash} — hashes and
 * counts ONLY, no event contents (metadata-first) — signed with the
 * ADR-016 Ed25519 machinery and verified against the same TrustedKey
 * shape. Designed to be published to the cloud plane on sync, or printed
 * for manual escrow. `genesisHash` is what upgrades "something diverged"
 * into the replace-vs-fork classification: a replaced ledger has a
 * different genesis; a forked one shares the genesis but not the anchored
 * head.
 *
 * TRUST MODEL (full statement in ADR-018): an anchor proves the keyholder
 * attested that a ledger with this genesis, head, and count existed. It
 * does NOT prove wall-clock time (anchoredAt is claimed), does NOT protect
 * the un-anchored suffix beyond linkage, and canNOT detect deletion of
 * ledger AND anchor together — absence detection requires the escrow side.
 * Refusals carry hashes/counts/classes only.
 */
import { type KeyObject } from "node:crypto";
import { type ProofVerdict } from "../evidence/merkle.js";
import { type TrustedKey } from "./bundle.js";
export declare const LEDGER_FILE = "ledger.jsonl";
export declare const GENESIS_PREV: string;
/** One ledger entry. `payload` is metadata-only by producer contract. */
export interface LedgerEntry {
    readonly seq: number;
    readonly prevHash: string;
    readonly occurredAt: string;
    readonly kind: string;
    readonly payload: Record<string, string | number | boolean>;
    readonly entryHash: string;
}
/**
 * Payload keys withheld from every PUBLISHED projection of a ledger entry
 * (TEAM-ADR-048).
 *
 * `workspace` is here because the review.run payload is the ROOT PRODUCER of
 * the workspace value: the evidence exporter reads it back for a record's
 * `resourceHash`, the compliance packet copies the payload into every
 * timeline row, and the Studio data island ships the rows verbatim. New
 * entries carry the LABEL (oneshot.ts writes `workspaceLabel(root)`), so this
 * withholding is not what closes the disclosure — it is what closes it for
 * entries ALREADY on disk. The ledger is append-only and hash-chained:
 * history written before TEAM-ADR-048 holds a cleartext basename that can
 * never be rewritten, so it has to be dropped where it would be emitted.
 *
 * The row still carries `entryHash`, which stays the entry's binding
 * reference; a projection was never byte-equal to the payload preimage.
 */
export declare const WITHHELD_PAYLOAD_KEYS: ReadonlySet<string>;
/**
 * TEAM-ADR-047 §4 / TEAM-ADR-052 — the ONE oracle-withholding rule.
 *
 * `argsHash` and `resultHash` are UNKEYED SHA-256 over the raw, unredacted
 * tool arguments and result. They stay unkeyed on purpose (evidence-format.md
 * publishes them as a third-party recompute contract, and selective disclosure
 * recomputes them from the customer's own plaintext), so the disclosure
 * boundary is EMISSION: the digest is emitted only for a field the customer
 * CHOSE to disclose, where the preimage is already in the reader's hands and
 * the digest is the thing that proves it. On every other row a guessable
 * preimage ({"path":"/etc/passwd"}, "", "ok") is confirmable on the first try.
 *
 * This map and this function are the whole rule. The compliance packet passes
 * the row's VERIFIED disclosed fields; the Studio passes nothing, because a
 * `.deepsweep/studio.html` carries no disclosures at all — so both digests are
 * always withheld there. A second copy of this rule is a rule that can
 * disagree with itself, which is how `resultHash` was already missed once.
 */
export declare const ORACLE_DIGEST_KEY_BY_FIELD: ReadonlyMap<string, string>;
/** The payload keys an emitter must withhold, given the fields disclosed on
 * this row. Pass an empty iterable for an artifact that carries no
 * disclosures — every oracle digest is then withheld. */
export declare function oracleWithheldKeys(disclosedFields: Iterable<string>): ReadonlySet<string>;
/**
 * Project one entry for publication. Pure; the on-disk entry is untouched.
 * `extraWithheld` lets a caller withhold more for its own artifact — both
 * published emitters pass `oracleWithheldKeys(...)` (the compliance packet
 * timeline and the Studio data island).
 */
export declare function redactLedgerEntry(entry: LedgerEntry, extraWithheld?: ReadonlySet<string>): LedgerEntry;
export declare class LedgerRefusalError extends Error {
    constructor(reason: string);
}
export declare function hashEntry(entry: Omit<LedgerEntry, "entryHash">): string;
/** Parse + structurally validate the ledger file. Malformed → undefined. */
export declare function readLedger(workspaceRoot: string): LedgerEntry[] | undefined;
/** Verify internal hash-chain integrity (detects edits, not replacement). */
export declare function verifyChain(entries: readonly LedgerEntry[]): boolean;
/** Append one entry — O(1) contained fd append (ADR-018 hot-path
 * amendment; see appendStoreLine for the documented durability trade). */
export declare function appendLedgerEntry(workspaceRoot: string, kind: string, payload: Record<string, string | number | boolean>, nowIso: string): LedgerEntry | "corrupt";
/** The anchored facts — hashes and counts ONLY, never event contents. */
export interface AnchorRecord {
    readonly chainHead: string;
    readonly entryCount: number;
    readonly anchoredAt: string;
    readonly genesisHash: string;
    /** RFC 6962 tree head over the entries' entryHash leaves (TEAM-ADR-025).
     * Optional: anchors signed before PDX-1 lack it and stay verifiable —
     * ADDITIVE, never a rename (the ADR-020 dual-emit discipline). */
    readonly treeHead?: string;
}
/** RFC 6962 tree head (hex) over the ledger's entries. */
export declare function ledgerTreeHead(entries: readonly LedgerEntry[]): string;
/** A portable inclusion proof: one entry provably in the anchored tree,
 * hashes and counts only (metadata-first) — verifiable WITHOUT the ledger. */
export interface LedgerInclusionProof {
    readonly entryHash: string;
    readonly index: number;
    readonly treeSize: number;
    readonly treeHead: string;
    readonly proof: readonly string[];
}
/** Prove one entry's inclusion in the current tree. Refuses out-of-range. */
export declare function proveLedgerInclusion(entries: readonly LedgerEntry[], index: number): LedgerInclusionProof;
/** Verify a portable inclusion proof against its tree head (which a verifier
 * takes from a signed anchor, never from the proof's author). The entryHash
 * is re-leaf-hashed here, so a caller cannot substitute a node for a leaf.
 * Malformed hex fails closed with a reason, never throws. */
export declare function verifyLedgerInclusion(p: LedgerInclusionProof): ProofVerdict;
export interface SignedAnchor {
    readonly anchor: AnchorRecord;
    /** Ed25519 over canonicalize(anchor), base64 (ADR-016 machinery). */
    readonly signature: string;
    readonly keyId: string;
}
/** Export a signed anchor of the CURRENT chain head. Empty ledger refuses. */
export declare function exportAnchor(entries: readonly LedgerEntry[], privateKey: KeyObject, nowIso: string): SignedAnchor;
export type AnchorVerdict = {
    readonly status: "verified";
    readonly detail: string;
} | {
    readonly status: "verified-appended";
    readonly appendedEntries: number;
    readonly detail: string;
} | {
    readonly status: "untrusted-anchor" | "tampered" | "truncated" | "replaced" | "forked";
    readonly detail: string;
};
/**
 * Verify a ledger against a signed anchor. Order of decisions matters and
 * is part of the contract:
 *  1. The ANCHOR itself must verify (pinned key, matching derived keyId,
 *     valid signature, sane shape) — an unverifiable anchor proves nothing.
 *  2. Internal chain integrity ("tampered" — the edit-detection the ledger
 *     already had).
 *  3. entryCount < anchored count → "truncated".
 *  4. genesis differs → "replaced" (wholesale substitution).
 *  5. genesis matches but the entry at the anchored position is not the
 *     anchored head → "forked" (history rewritten after genesis).
 *  6. Head matches at the anchored position: "verified" (exact) or
 *     "verified-appended" (honest growth since the anchor).
 */
export declare function verifyAgainstAnchor(entries: readonly LedgerEntry[], signed: unknown, trustedKeys: readonly TrustedKey[]): AnchorVerdict;
