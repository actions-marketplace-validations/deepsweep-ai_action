/**
 * The gateway's write path to the audit ledger (TEAM-ADR-069): append an
 * entry and, when the host injected a key, its per-entry signature
 * (TEAM-ADR-028). The call record, the refusal record and the kill-switch
 * records all go through here, so a new kind cannot be written unsigned by
 * accident, and every failure is described the same way.
 */
import { type LedgerAppendRefusal, type LedgerEntry } from "../review/ledger.js";
import { type LedgerSigningKey } from "../review/ledger-sign.js";
/** The operator's sentence for a ledger that cannot take a record: its path and the cause (M4). */
export declare function ledgerProblem(workspaceRoot: string, cause: LedgerAppendRefusal | "restarted"): string;
/**
 * Describe a store failure that means "this record could not be written or
 * signed", naming the file (fix pass 1, m3): a containment refusal of the
 * ledger or its signature sidecar, or a file-system error with its code and
 * path. Anything else is not a recording failure, and gets undefined.
 */
export declare function describeStoreError(e: unknown): string | undefined;
/** What happened to one record: written (and, when a key was given, signed or not), or refused with the reason. */
export type Recorded = {
    readonly status: "recorded";
    readonly entry: LedgerEntry;
    readonly unsigned?: string;
} | {
    readonly status: "refused";
    readonly why: string;
};
/** The operator's words for an entry that is on the ledger without its signature (fix pass 2: true whether the verifier then says "signature-gap" or, when no entry has one, "unsigned"). */
export declare function unsignedNote(why: string, seq: number): string;
/**
 * Append one entry, then sign it, holding the ledger lock across both (fix
 * pass 2: the sidecar's roll-back on a failed write relies on it). The ENTRY
 * is the record: once it is on the ledger it is not undone, and a signature
 * that cannot be written is reported in `unsigned`, never thrown (fix pass 1,
 * M2). A refused append writes nothing. A store failure of the entry itself
 * throws, and leaves no torn line (fix pass 2, M-4).
 */
export declare function recordEntry(workspaceRoot: string, kind: string, payload: Record<string, string | number | boolean>, nowIso: string, key: LedgerSigningKey | undefined): Recorded;
/** Append and sign, the pre-fix-pass contract: a refusal is "corrupt", and a signature failure throws. Used where the caller is an operator command. */
export declare function appendSignedEntry(workspaceRoot: string, kind: string, payload: Record<string, string | number | boolean>, nowIso: string, key: LedgerSigningKey | undefined): LedgerEntry | "corrupt";
