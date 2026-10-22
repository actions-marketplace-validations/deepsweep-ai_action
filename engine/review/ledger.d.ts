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
import { type StoreUnreadableCause } from "./store.js";
export declare const LEDGER_FILE = "ledger.jsonl";
export declare const GENESIS_PREV: string;
/**
 * The ledger's own read cap, 64 MiB (TEAM-ADR-069 Decision 1c). The store's
 * 1,000,000-byte cap (MAX_FILE_BYTES) exists for files an agent can shape
 * that the review reads; applied to the ledger, it made every ledger past
 * 1 MB read as EMPTY, so the next append restarted the chain at seq 0 and
 * every reader saw no history at all. A forwarded gateway call writes about
 * 1.8 KB (decision, call and result entries, measured), so that happened
 * after roughly 550 calls; this cap holds roughly 36,000. Past it the ledger
 * is refused as unreadable, never read as empty.
 */
export declare const LEDGER_MAX_BYTES: number;
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
/** Why a ledger that exists could not be read as one (TEAM-ADR-069). */
export type LedgerUnreadableCause = "malformed" | StoreUnreadableCause;
/**
 * The ledger as found on disk. `ok` with no entries means the ledger has not
 * been written yet; a ledger that exists and cannot be read is `unreadable`,
 * never empty.
 */
export type LedgerRead = {
    readonly status: "ok";
    readonly entries: LedgerEntry[];
} | {
    readonly status: "unreadable";
    readonly cause: LedgerUnreadableCause;
};
/** Read and structurally validate the ledger, saying why when it cannot be read. Throws only for store-containment violations. */
export declare function inspectLedger(workspaceRoot: string): LedgerRead;
/** The ledger file's absolute path, for an operator's diagnostic. No containment check: it names the file, it does not open it. */
export declare function ledgerPath(workspaceRoot: string): string;
/**
 * The index of the first entry that starts the chain over (seq 0 with the
 * genesis prevHash) anywhere but at the start, or undefined (TEAM-ADR-069 fix
 * pass 1, M3). A structural check only: cheap enough for every summary. Such
 * a ledger can never export, whoever wrote the restart.
 */
export declare function ledgerRestartIndex(entries: readonly LedgerEntry[]): number | undefined;
/**
 * True when the restart at `index` has exactly the shape builds before
 * TEAM-ADR-069 wrote (fix pass 1, M3; tightened by fix pass 2, M-3):
 *  - everything before it is one chain that verifies, and takes more than
 *    1,000,000 bytes (the old read cap, past which the ledger read as empty);
 *  - from `index` on, EVERY entry is a self-hashing genesis entry, because
 *    each later append by such a build also read the ledger as empty;
 *  - except that the entries after those may be one continuation that a
 *    current build appended (it reads the whole ledger, so it chains from the
 *    last restart entry: seq equal to its position, prevHash the previous
 *    entry's hash), and that continuation must verify to the end.
 * Fix pass 1 checked only the restart entry, so an edit after it, or one
 * entry of a never-restarted ledger rewritten as a genesis entry, exported as
 * "restarted by an earlier version" (the round-2 review). Anything else that
 * breaks the chain is reported as an edit. Stated residual: someone who
 * rewrites EVERY entry from some point on as a self-hashing genesis entry
 * produces this shape; the chain alone never detected a rewritten tail
 * (ADR-018), which signatures and anchors exist for.
 */
export declare function isEarlierBuildRestart(entries: readonly LedgerEntry[], index: number): boolean;
/**
 * Parse + structurally validate the ledger file. A ledger that is malformed,
 * over LEDGER_MAX_BYTES, or otherwise unreadable → undefined; an absent one
 * → []. (Before TEAM-ADR-069 an oversized or unreadable ledger returned [],
 * which appendLedgerEntry then extended from genesis.)
 */
export declare function readLedger(workspaceRoot: string): LedgerEntry[] | undefined;
/** Verify internal hash-chain integrity (detects edits, not replacement). */
export declare function verifyChain(entries: readonly LedgerEntry[]): boolean;
/** What an append needs to know about the ledger: how many entries, the newest one, the newest of each kind, its size, and whether an earlier build restarted it. */
export interface LedgerSummary {
    readonly count: number;
    readonly head: LedgerEntry | undefined;
    readonly lastOfKind: ReadonlyMap<string, LedgerEntry>;
    /** The ledger file's size in bytes when summarised (0 when absent). */
    readonly bytes: number;
    /** See ledgerRestartIndex. */
    readonly restartedAt: number | undefined;
}
export type LedgerSummaryRead = {
    readonly status: "ok";
    readonly summary: LedgerSummary;
} | {
    readonly status: "unreadable";
    readonly cause: LedgerUnreadableCause;
};
/** Why an append was refused: the ledger cannot be read, or it has no room for this entry under LEDGER_MAX_BYTES. */
export type LedgerAppendRefusal = LedgerUnreadableCause | "full";
/**
 * The ledger's count, newest entry, newest entry of each kind, size and
 * restart point, or why it cannot be read (TEAM-ADR-069). Validates the whole
 * ledger exactly as readLedger does whenever the file has changed since the
 * last summary this process took or wrote; otherwise answers from that
 * summary.
 */
export declare function summarizeLedger(workspaceRoot: string): LedgerSummaryRead;
/** The advisory lock file every appender takes around read-then-append (TEAM-ADR-069 fix pass 1, M5). */
export declare const LEDGER_LOCK_FILE = "ledger.lock";
/**
 * Where a pid means something (TEAM-ADR-069 fix pass 2, M-1): the host name,
 * and on Linux the PID namespace (`/proc/self/ns/pid`, for example
 * `pid:[4026531836]`). A gateway in a container is PID 1 in its own
 * namespace, and cannot see the pids of another container's processes, so a
 * pid from a lock written elsewhere says nothing about whether its holder is
 * alive. Elsewhere than Linux there are no PID namespaces: null. On Linux, a
 * namespace that cannot be read is "unknown", which matches nothing.
 */
export interface LockPlace {
    readonly host: string;
    readonly pidNs: string | null;
}
/** This process's place, given the platform and a way to read a symlink (parameters so both platforms' branches are tested on either). */
export declare function lockPlaceOf(host: string, platform: NodeJS.Platform, readlink: (path: string) => string): LockPlace;
/**
 * Run `fn` holding the ledger's advisory lock (TEAM-ADR-069 fix pass 1, M5;
 * fix pass 2, M-1 and M-2). Two gateways on one workspace (the quick start's
 * default: one per MCP server) each read the ledger's head and appended the
 * next seq; without a lock they forked the chain (the review measured 345
 * duplicate seqs in 1,200 entries). The lock is a file created with O_EXCL
 * holding a LockToken: a random nonce, the pid, and the host and PID
 * namespace the pid belongs to. A waiter backs off from 50 µs to 2 ms, and
 * after LOCK_WAIT_MS throws ELOCKED, which the gateway reports as "could not
 * be recorded". staleLockFound says when a lock is stale; breakStaleLock
 * breaks one; the release removes the lock only if it is still this
 * acquisition's own. If the token cannot be written, the empty lock just
 * created is removed before the error is thrown (M-2): left behind, it made
 * every call wait and be refused until it was 30 s old.
 *
 * Advisory: a writer that does not take it (an older build, a hand edit) is
 * not stopped by it. Residuals, stated in the ADR: a holder stalled past
 * LOCK_STALE_MS can be broken while still inside its critical section; two
 * machines with the same host name and PID-namespace identity sharing a
 * workspace are taken for one; and the rare put-back described at
 * breakStaleLock.
 */
export declare function withLedgerLock<T>(workspaceRoot: string, fn: () => T, refuseWith?: (reason: string) => Error): T;
/**
 * Append one entry, or say why not (TEAM-ADR-069). O(1) contained fd append
 * (ADR-018 hot-path amendment; see appendStoreLine for the durability
 * trade). Refused, and nothing written: a ledger that cannot be read, and an
 * entry that would take the file past LEDGER_MAX_BYTES (fix pass 1, M1: the
 * ledger never grows past the size every reader accepts, so it stays
 * exportable). Throws only for store failures: containment refusals, and
 * write errors including a short write (B1).
 */
export declare function appendLedgerEntryOrRefuse(workspaceRoot: string, kind: string, payload: Record<string, string | number | boolean>, nowIso: string): {
    readonly entry: LedgerEntry;
} | {
    readonly refused: LedgerAppendRefusal;
};
/**
 * Append one entry. A refusal (see appendLedgerEntryOrRefuse) is the
 * "corrupt" sentinel, which every caller already surfaces loudly. Throws
 * only for store failures.
 */
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
