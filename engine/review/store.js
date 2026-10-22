/**
 * Shared contained-store primitives for durable metadata files under
 * `.deepsweep/` (ADR-003 containment invariants, extracted verbatim from the
 * baseline write path so the identity store — ADR-005 — reuses the same
 * audited code instead of duplicating it):
 *  - refuse if `.deepsweep/` or the store file is a symlink or its realpath
 *    escapes the workspace root; regular-file / directory checks;
 *  - reads enforce the MAX_FILE_BYTES cap;
 *  - atomic write via O_CREAT|O_EXCL mode-0600 temp file inside `.deepsweep/`
 *    (same filesystem → atomic rename).
 *
 * Callers own their refusal-error type (the CLI maps containment refusals to
 * exit 3) and their file schema; this module owns only containment + bytes.
 * Extraction note (S2.1): behavior for the baseline is byte-identical to the
 * pre-extraction implementation in baseline.ts — its tests prove it.
 */
import { constants, closeSync, fstatSync, fsyncSync, ftruncateSync, lstatSync, mkdirSync, openSync, readFileSync, readSync, realpathSync, renameSync, unlinkSync, writeSync, } from "node:fs";
import { randomBytes } from "node:crypto";
import { join, resolve, sep } from "node:path";
import { MAX_FILE_BYTES } from "./read.js";
import { sha256Hex } from "./canonical.js";
/** The single durable-state directory (ADR-003). */
export const STORE_DIR = ".deepsweep";
/**
 * Containment checks per ADR-003; throws the caller's refusal error on
 * violation. `refuse` receives the reason and returns the error to throw.
 */
export function checkedStorePaths(workspaceRoot, fileName, refuse) {
    return checkPaths(workspaceRoot, fileName, refuse);
}
/**
 * Containment checks for the store DIRECTORY only (TEAM-ADR-069 fix pass 1):
 * for a file other processes create and remove constantly (the ledger lock),
 * resolving the file's own path races their unlink. Such a file must be
 * opened with O_NOFOLLOW, so a symlink planted in its place fails.
 */
export function checkedStoreDir(workspaceRoot, refuse) {
    const { root, dir } = checkPaths(workspaceRoot, undefined, refuse);
    return { root, dir };
}
function checkPaths(workspaceRoot, fileName, refuse) {
    const root = resolve(workspaceRoot);
    const dir = join(root, STORE_DIR);
    const file = fileName === undefined ? dir : join(dir, fileName);
    const realRoot = realpathSync(root);
    const targets = fileName === undefined
        ? [[STORE_DIR, dir]]
        : [[STORE_DIR, dir], [`${STORE_DIR}/${fileName}`, file]];
    for (const [label, p] of targets) {
        let st;
        try {
            st = lstatSync(p);
        }
        catch {
            continue; // absent is fine
        }
        if (st.isSymbolicLink())
            throw refuse(`${label} is a symlink`);
        const real = realpathSync(p);
        if (real !== realRoot && !real.startsWith(realRoot + sep)) {
            throw refuse(`${label} resolves outside the workspace root`);
        }
        if (p === file && p !== dir && !st.isFile()) {
            throw refuse(`${label} is not a regular file`);
        }
        if (p === dir && !st.isDirectory()) {
            throw refuse(`${label} is not a directory`);
        }
    }
    return { root, dir, file };
}
const ABSENT = { status: "absent" };
/**
 * Contained read of a store file, distinguishing absent from unreadable.
 * `maxBytes` defaults to the review cap (MAX_FILE_BYTES); the ledger passes
 * its own. Throws the caller's refusal error only for containment violations.
 */
export function readStoreFile(workspaceRoot, fileName, refuse, maxBytes = MAX_FILE_BYTES) {
    const { file } = checkedStorePaths(workspaceRoot, fileName, refuse);
    let st;
    try {
        st = lstatSync(file);
    }
    catch (e) {
        return e.code === "ENOENT" ? ABSENT : { status: "unreadable", cause: "read-error" };
    }
    // checkedStorePaths already refused a non-regular file; this arm covers one
    // swapped in between the two lstat calls.
    if (!st.isFile() || st.size > maxBytes)
        return { status: "unreadable", cause: st.isFile() ? "oversized" : "not-a-file" };
    try {
        return { status: "ok", text: readFileSync(file, "utf8") };
    }
    catch {
        return { status: "unreadable", cause: "read-error" };
    }
}
/**
 * Contained read of a store file's text. Returns undefined when absent, not a
 * regular file, over the size cap, or unreadable; throws the caller's refusal
 * error only for containment violations. Callers for which "unreadable" must
 * not read as "absent" use readStoreFile.
 */
export function readStoreText(workspaceRoot, fileName, refuse) {
    const r = readStoreFile(workspaceRoot, fileName, refuse);
    return r.status === "ok" ? r.text : undefined;
}
/**
 * Atomic, contained store write. Returns the SHA-256 of the written bytes so
 * callers can track in-session tamper-check hashes.
 */
export function writeStoreAtomic(workspaceRoot, fileName, text, refuse) {
    const { dir, file } = checkedStorePaths(workspaceRoot, fileName, refuse);
    try {
        mkdirSync(dir);
    }
    catch (e) {
        if (e.code !== "EEXIST")
            throw e;
    }
    // Re-check after mkdir (a symlink could have been raced into place).
    // ACCEPTED RESIDUAL (S1.4 security review P3, v0): a narrow TOCTOU window
    // remains between this re-check and openSync/renameSync — an agent that can
    // race it can already rewrite the store file outright, which ADR-003's
    // threat note accepts for detection-only v0 and mitigates via O_CREAT|O_EXCL
    // on the temp file, provenance disclosure, and the in-session tamper hash
    // (baseline.tampered). Full closure arrives with E4 signing/attestation.
    checkedStorePaths(workspaceRoot, fileName, refuse);
    const tmp = join(dir, `.${fileName}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`);
    const fd = openSync(tmp, "wx", 0o600);
    try {
        try {
            // TEAM-ADR-069 fix pass 1 (B1): a short write must never be renamed
            // into place as the whole file.
            writeAllSync(fd, Buffer.from(text, "utf8"), tmp);
            fsyncSync(fd);
        }
        finally {
            closeSync(fd);
        }
        renameSync(tmp, file);
    }
    catch (e) {
        try {
            unlinkSync(tmp);
        }
        catch {
            /* best effort */
        }
        throw e;
    }
    return { fileHash: sha256Hex(text) };
}
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
export function writeAllSync(fd, data, path) {
    let off = 0;
    while (off < data.length) {
        let n;
        try {
            n = writeSync(fd, data, off, data.length - off);
        }
        catch (e) {
            const err = e;
            if (err.path === undefined)
                err.path = path;
            throw Object.assign(err, { written: off });
        }
        if (n <= 0) {
            throw Object.assign(new Error(`ENOSPC: no space left on device, short write (${off} of ${data.length} bytes) to '${path}'`), {
                code: "ENOSPC",
                syscall: "write",
                path,
                written: off,
            });
        }
        off += n;
    }
}
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
export function appendStoreLine(workspaceRoot, fileName, line, refuse, opts = {}) {
    const { dir, file } = checkedStorePaths(workspaceRoot, fileName, refuse);
    try {
        mkdirSync(dir);
    }
    catch (e) {
        /* v8 ignore next -- reason: non-EEXIST mkdir failures (EACCES/ENOSPC/EROFS) require an environment fault the suite cannot stage portably; the identical arm in writeStoreAtomic is pinned by persistence tests via fs fault injection, and this is the same two-line pattern. */
        if (e.code !== "EEXIST")
            throw e;
    }
    checkedStorePaths(workspaceRoot, fileName, refuse);
    const access = opts.startOnNewLine === true ? constants.O_RDWR : constants.O_WRONLY;
    /* v8 ignore next 2 -- reason: constants.O_NOFOLLOW is defined on every POSIX platform the suite runs on; the ?? 0 fallback exists solely for win32 field use (same annotation as read.ts's NOFOLLOW). */
    const fd = openSync(file, access | constants.O_APPEND | constants.O_CREAT | (constants.O_NOFOLLOW ?? 0), 0o600);
    try {
        const before = fstatSync(fd).size;
        let data = Buffer.from(line, "utf8");
        if (opts.startOnNewLine === true && before > 0 && !endsWithNewline(fd, before))
            data = Buffer.concat([NEWLINE, data]);
        try {
            writeAllSync(fd, data, file);
        }
        catch (e) {
            if (opts.rollBackOnFailure === true)
                rollBack(fd, before, e);
            throw e;
        }
    }
    finally {
        closeSync(fd);
    }
}
const NEWLINE = Buffer.from("\n");
/** True when the file open at `fd`, `size` bytes long, ends in a newline. */
function endsWithNewline(fd, size) {
    const last = Buffer.alloc(1);
    readSync(fd, last, 0, 1, size - 1);
    return last[0] === 0x0a;
}
/**
 * Undo a failed append (see appendStoreLine): truncate to `before` only when
 * the file holds exactly this write's own bytes past it. Otherwise, or if
 * the truncation fails, the error is marked `tornLeft` with why, and the torn
 * bytes stay for the recovery procedure.
 */
function rollBack(fd, before, e) {
    // writeAllSync, the only call in the try, puts `written` on every error it throws.
    const written = e.written;
    let why = "it could not be undone";
    try {
        if (fstatSync(fd).size === before + written) {
            ftruncateSync(fd, before);
            return;
        }
        why = "another writer appended after it began";
    }
    catch {
        /* the truncation failed: `why` says so */
    }
    Object.assign(e, { tornLeft: why });
}
