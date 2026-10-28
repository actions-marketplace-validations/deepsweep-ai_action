/**
 * The gateway's write path to the audit ledger (TEAM-ADR-069): append an
 * entry and, when the host injected a key, its per-entry signature
 * (TEAM-ADR-028). The call record, the refusal record and the kill-switch
 * records all go through here, so a new kind cannot be written unsigned by
 * accident, and every failure is described the same way.
 */
import { appendLedgerEntryOrRefuse, LEDGER_MAX_BYTES, ledgerPath, LedgerRefusalError, withLedgerLock } from "../review/ledger.js";
import { appendLedgerSignature, LedgerSignatureRefusalError, signLedgerEntry } from "../review/ledger-sign.js";
/** Why an append was refused, in words an operator can act on (TEAM-ADR-069 fix pass 1, M4). */
const APPEND_REFUSAL = {
    malformed: "is malformed (a line is not a ledger entry; a torn last line is the usual cause); the gateway never rewrites it",
    oversized: `is larger than its ${LEDGER_MAX_BYTES / (1024 * 1024)} MiB read cap`,
    full: `has no room left under its ${LEDGER_MAX_BYTES / (1024 * 1024)} MiB cap`,
    // Fix pass 2 (M-3): neutral. The gateway's check is structural; only the
    // export's full check can tell an earlier version's restart from an edit.
    restarted: "starts a new chain at seq 0 after its first entry, so new records would join history that cannot be exported as one chain; an evidence export names the cause, then archive the ledger and its signatures and start a new one",
    "not-a-file": "is not a regular file",
    "read-error": "could not be read",
};
/** The operator's sentence for a ledger that cannot take a record: its path and the cause (M4). */
export function ledgerProblem(workspaceRoot, cause) {
    return `the audit ledger ${ledgerPath(workspaceRoot)} ${APPEND_REFUSAL[cause]}`;
}
/**
 * Describe a store failure that means "this record could not be written or
 * signed", naming the file (fix pass 1, m3): a containment refusal of the
 * ledger or its signature sidecar, or a file-system error with its code and
 * path. Anything else is not a recording failure, and gets undefined.
 */
export function describeStoreError(e) {
    if (e instanceof LedgerRefusalError || e instanceof LedgerSignatureRefusalError)
        return e.message;
    const err = e;
    if (typeof err?.code !== "string")
        return undefined;
    const where = typeof err.path === "string" ? `${err.code} on ${err.path}` : err.code;
    // Fix pass 3 (R3-3): a failed append that could not be rolled back says so.
    return typeof err.tornLeft === "string" ? `${where} (a partial write was left in place: ${err.tornLeft})` : where;
}
/** The operator's words for an entry that is on the ledger without its signature (fix pass 2: true whether the verifier then says "signature-gap" or, when no entry has one, "unsigned"). */
export function unsignedNote(why, seq) {
    return `its signature could not be written (${why}); a verifier will find no signature for seq ${seq}`;
}
/**
 * Append one entry, then sign it, holding the ledger lock across both (fix
 * pass 2: the sidecar's roll-back on a failed write relies on it). The ENTRY
 * is the record: once it is on the ledger it is not undone, and a signature
 * that cannot be written is reported in `unsigned`, never thrown (fix pass 1,
 * M2). A refused append writes nothing. A store failure of the entry itself
 * throws, and leaves no torn line (fix pass 2, M-4).
 */
export function recordEntry(workspaceRoot, kind, payload, nowIso, key) {
    return withLedgerLock(workspaceRoot, () => {
        const r = appendLedgerEntryOrRefuse(workspaceRoot, kind, payload, nowIso);
        if ("refused" in r)
            return { status: "refused", why: ledgerProblem(workspaceRoot, r.refused) };
        if (key === undefined)
            return { status: "recorded", entry: r.entry };
        try {
            appendLedgerSignature(workspaceRoot, signLedgerEntry(r.entry, key));
        }
        catch (e) {
            const why = describeStoreError(e);
            if (why === undefined)
                throw e;
            return { status: "recorded", entry: r.entry, unsigned: unsignedNote(why, r.entry.seq) };
        }
        return { status: "recorded", entry: r.entry };
    });
}
/** Append and sign, the pre-fix-pass contract: a refusal is "corrupt", and a signature failure throws. Used where the caller is an operator command. */
export function appendSignedEntry(workspaceRoot, kind, payload, nowIso, key) {
    const r = appendLedgerEntryOrRefuse(workspaceRoot, kind, payload, nowIso);
    if ("refused" in r)
        return "corrupt";
    if (key !== undefined)
        appendLedgerSignature(workspaceRoot, signLedgerEntry(r.entry, key));
    return r.entry;
}
