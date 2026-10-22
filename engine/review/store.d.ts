/** The single durable-state directory (ADR-003). */
export declare const STORE_DIR = ".deepsweep";
export interface StorePaths {
    root: string;
    dir: string;
    file: string;
}
/**
 * Containment checks per ADR-003; throws the caller's refusal error on
 * violation. `refuse` receives the reason and returns the error to throw.
 */
export declare function checkedStorePaths(workspaceRoot: string, fileName: string, refuse: (reason: string) => Error): StorePaths;
/**
 * Containment checks for the store DIRECTORY only (TEAM-ADR-069 fix pass 1):
 * for a file other processes create and remove constantly (the ledger lock),
 * resolving the file's own path races their unlink. Such a file must be
 * opened with O_NOFOLLOW, so a symlink planted in its place fails.
 */
export declare function checkedStoreDir(workspaceRoot: string, refuse: (reason: string) => Error): {
    readonly root: string;
    readonly dir: string;
};
/**
 * What a contained read of one store file found (TEAM-ADR-069). `absent` is
 * the ONLY outcome that means "nothing has been written yet". Everything else
 * that stops the read is `unreadable`, with its cause, so a caller that must
 * never mistake an unreadable file for an empty one (the audit ledger and its
 * signature sidecar: an empty ledger restarts at genesis) can tell them apart.
 */
export type StoreRead = {
    readonly status: "absent";
} | {
    readonly status: "ok";
    readonly text: string;
} | {
    readonly status: "unreadable";
    readonly cause: StoreUnreadableCause;
};
/** Why a store file that exists could not be read. */
export type StoreUnreadableCause = "not-a-file" | "oversized" | "read-error";
/**
 * Contained read of a store file, distinguishing absent from unreadable.
 * `maxBytes` defaults to the review cap (MAX_FILE_BYTES); the ledger passes
 * its own. Throws the caller's refusal error only for containment violations.
 */
export declare function readStoreFile(workspaceRoot: string, fileName: string, refuse: (reason: string) => Error, maxBytes?: number): StoreRead;
/**
 * Contained read of a store file's text. Returns undefined when absent, not a
 * regular file, over the size cap, or unreadable; throws the caller's refusal
 * error only for containment violations. Callers for which "unreadable" must
 * not read as "absent" use readStoreFile.
 */
export declare function readStoreText(workspaceRoot: string, fileName: string, refuse: (reason: string) => Error): string | undefined;
/**
 * Atomic, contained store write. Returns the SHA-256 of the written bytes so
 * callers can track in-session tamper-check hashes.
 */
export declare function writeStoreAtomic(workspaceRoot: string, fileName: string, text: string, refuse: (reason: string) => Error): {
    fileHash: string;
};
/**
 * Write every byte of `data` at the fd's position, or throw (TEAM-ADR-069 fix
 * pass 1, B1). `writeSync` may return fewer bytes than asked without throwing:
 * measured on a full HFS+ volume under Node 26.5 and Bun 1.3.14 (100 of 501
 * bytes), and Linux ext4/xfs do the same on ENOSPC. Ignoring that return
 * value left a torn record on disk while the caller carried on as if it had
 * been written. A short write is retried from where it stopped (a transient
 * short write completes); a write that makes no progress throws an ENOSPC
 * error naming the file, which callers already treat as "could not record".
 * An error the platform throws itself carries no path, because the write was
 * made on a descriptor; it gets this file's path before it is rethrown (fix
 * pass 2, m-f), so every diagnostic names the file. Every error thrown here
 * carries `written`, the bytes of `data` that did land (fix pass 3, R3-3), so
 * a roll-back removes only this write's own bytes.
 */
export declare function writeAllSync(fd: number, data: Buffer, path: string): void;
/**
 * Contained O(1) line append (ADR-018 hot-path amendment, 2026-08-01): the
 * audit ledger appends one JSONL line per review, and the atomic
 * temp+fsync+rename rewrite made that O(file) with a multi-ms fsync on the
 * REVIEW hot path (live bench tripwire caught it at 2x the ADR-017 budget).
 * Same containment discipline as writeStoreAtomic (checked paths, mkdir
 * re-check, O_NOFOLLOW so a swapped symlink fails the open). Durability
 * trade, documented: no fsync — a crash may lose the line being appended
 * (a lost record is not tamper; the chain re-links from the surviving
 * tail), and a torn line is TAMPER-EVIDENT by design (readLedger → corrupt
 * sentinel → loud finding). Auditability model unchanged (ADR-018).
 *
 * `rollBackOnFailure` (TEAM-ADR-069 fix pass 2, M-4; fix pass 3, R3-3): when
 * the write fails part-way (a full disk), the file is truncated back to its
 * size before this append, so no torn line is left, and once space is freed
 * the next append lands on a whole line without a repair by hand. It
 * truncates only when the file is exactly that size plus this write's own
 * bytes. Otherwise another writer appended after this write began (one that
 * does not take the ledger lock, or one that broke it while this holder
 * stalled past 30 s), and truncating would erase its record: the torn bytes
 * are left in place instead, and the error says so (`tornLeft`). The lock
 * makes that case rare, and the size check narrows it; it does not close it
 * (TEAM-ADR-069 Addendum 4, R4-9): the check and the truncation are separate
 * system calls, and a line such a writer appends between them is erased with
 * no note. If the truncation itself fails, the torn bytes stay and the error
 * says so.
 *
 * `startOnNewLine` (fix pass 3, R3-4): when the file does not end in a
 * newline (a torn line that could not be rolled back), this line starts on a
 * new one, so a torn approval record only ever loses itself and never the
 * record appended after it. Used for the signature sidecar and the approval
 * records. The signature sidecar is read as a whole, though: one torn line
 * there makes the whole file fail verification until the line is removed
 * (Addendum 4, R4-10).
 */
export declare function appendStoreLine(workspaceRoot: string, fileName: string, line: string, refuse: (reason: string) => Error, opts?: {
    readonly rollBackOnFailure?: boolean;
    readonly startOnNewLine?: boolean;
}): void;
