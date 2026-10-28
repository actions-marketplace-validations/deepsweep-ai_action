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
import { sign as edSign, verify as edVerify } from "node:crypto";
import { canonicalize, sha256Hex } from "./canonical.js";
import { explainInclusion, hashLeaf, inclusionProof, isDigest, merkleRoot, } from "../evidence/merkle.js";
import { keyIdFor } from "./bundle.js";
import { createPublicKey } from "node:crypto";
import { join, resolve } from "node:path";
import { closeSync, constants, fstatSync, linkSync, lstatSync, mkdirSync, openSync, readlinkSync, readSync, renameSync, rmdirSync, unlinkSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { hostname } from "node:os";
import { appendStoreLine, checkedStoreDir, checkedStorePaths, readStoreFile, STORE_DIR, writeAllSync } from "./store.js";
export const LEDGER_FILE = "ledger.jsonl";
export const GENESIS_PREV = "0".repeat(64);
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
export const LEDGER_MAX_BYTES = 64 * 1024 * 1024;
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
export const WITHHELD_PAYLOAD_KEYS = new Set(["workspace"]);
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
export const ORACLE_DIGEST_KEY_BY_FIELD = new Map([
    ["args", "argsHash"],
    ["result", "resultHash"],
]);
/** The payload keys an emitter must withhold, given the fields disclosed on
 * this row. Pass an empty iterable for an artifact that carries no
 * disclosures — every oracle digest is then withheld. */
export function oracleWithheldKeys(disclosedFields) {
    const disclosed = new Set(disclosedFields);
    const withheld = new Set();
    for (const [field, key] of ORACLE_DIGEST_KEY_BY_FIELD) {
        if (!disclosed.has(field))
            withheld.add(key);
    }
    return withheld;
}
/**
 * Project one entry for publication. Pure; the on-disk entry is untouched.
 * `extraWithheld` lets a caller withhold more for its own artifact — both
 * published emitters pass `oracleWithheldKeys(...)` (the compliance packet
 * timeline and the Studio data island).
 */
export function redactLedgerEntry(entry, extraWithheld = new Set()) {
    const payload = {};
    for (const [k, v] of Object.entries(entry.payload)) {
        if (!WITHHELD_PAYLOAD_KEYS.has(k) && !extraWithheld.has(k))
            payload[k] = v;
    }
    return { ...entry, payload };
}
export class LedgerRefusalError extends Error {
    constructor(reason) {
        super(`ledger refused: ${reason}`);
        this.name = "LedgerRefusalError";
    }
}
const refuse = (reason) => new LedgerRefusalError(reason);
export function hashEntry(entry) {
    return sha256Hex(canonicalize(entry));
}
/** Read and structurally validate the ledger, saying why when it cannot be read. Throws only for store-containment violations. */
export function inspectLedger(workspaceRoot) {
    const r = readStoreFile(workspaceRoot, LEDGER_FILE, refuse, LEDGER_MAX_BYTES);
    if (r.status === "absent")
        return { status: "ok", entries: [] };
    if (r.status === "unreadable")
        return r;
    const entries = parseLedgerText(r.text);
    return entries === undefined ? { status: "unreadable", cause: "malformed" } : { status: "ok", entries };
}
/** The ledger file's absolute path, for an operator's diagnostic. No containment check: it names the file, it does not open it. */
export function ledgerPath(workspaceRoot) {
    return join(resolve(workspaceRoot), STORE_DIR, LEDGER_FILE);
}
/**
 * The index of the first entry that starts the chain over (seq 0 with the
 * genesis prevHash) anywhere but at the start, or undefined (TEAM-ADR-069 fix
 * pass 1, M3). A structural check only: cheap enough for every summary. Such
 * a ledger can never export, whoever wrote the restart.
 */
export function ledgerRestartIndex(entries) {
    for (let i = 1; i < entries.length; i++) {
        const e = entries[i];
        if (e.seq === 0 && e.prevHash === GENESIS_PREV)
            return i;
    }
    return undefined;
}
/** The store's read cap before TEAM-ADR-069 (MAX_FILE_BYTES). Past it, earlier builds read the ledger as empty. */
const EARLIER_BUILD_CAP_BYTES = 1_000_000;
/** True for an entry that starts a chain of its own: seq 0, the genesis prevHash, and a correct hash. */
function isSelfHashingGenesis(e) {
    const { entryHash, ...body } = e;
    return e.seq === 0 && e.prevHash === GENESIS_PREV && hashEntry(body) === entryHash;
}
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
export function isEarlierBuildRestart(entries, index) {
    if (index < 1 || index >= entries.length)
        return false;
    const prefix = entries.slice(0, index);
    const prefixBytes = prefix.reduce((n, p) => n + Buffer.byteLength(JSON.stringify(p)) + 1, 0);
    if (prefixBytes <= EARLIER_BUILD_CAP_BYTES || !verifyChain(prefix))
        return false;
    let i = index;
    while (i < entries.length && isSelfHashingGenesis(entries[i]))
        i++;
    if (i === index)
        return false;
    for (; i < entries.length; i++) {
        const e = entries[i];
        const { entryHash, ...body } = e;
        if (e.seq !== i || e.prevHash !== entries[i - 1].entryHash || hashEntry(body) !== entryHash)
            return false;
    }
    return true;
}
/**
 * Parse + structurally validate the ledger file. A ledger that is malformed,
 * over LEDGER_MAX_BYTES, or otherwise unreadable → undefined; an absent one
 * → []. (Before TEAM-ADR-069 an oversized or unreadable ledger returned [],
 * which appendLedgerEntry then extended from genesis.)
 */
export function readLedger(workspaceRoot) {
    const r = inspectLedger(workspaceRoot);
    return r.status === "ok" ? r.entries : undefined;
}
function parseLedgerText(text) {
    const entries = [];
    for (const line of text.split("\n")) {
        if (line.trim() === "")
            continue;
        try {
            const parsed = JSON.parse(line);
            if (typeof parsed !== "object" ||
                parsed === null ||
                typeof parsed["seq"] !== "number" ||
                typeof parsed["prevHash"] !== "string" ||
                typeof parsed["occurredAt"] !== "string" ||
                typeof parsed["kind"] !== "string" ||
                typeof parsed["entryHash"] !== "string" ||
                typeof parsed["payload"] !== "object" ||
                parsed["payload"] === null) {
                return undefined;
            }
            entries.push(parsed);
        }
        catch {
            return undefined;
        }
    }
    return entries;
}
/** Verify internal hash-chain integrity (detects edits, not replacement). */
export function verifyChain(entries) {
    let prev = GENESIS_PREV;
    for (const [i, e] of entries.entries()) {
        const { entryHash, ...body } = e;
        if (e.seq !== i || e.prevHash !== prev || hashEntry(body) !== entryHash)
            return false;
        prev = entryHash;
    }
    return true;
}
function fileIdentity(file) {
    try {
        const st = lstatSync(file, { bigint: true });
        const inode = `${st.dev}:${st.ino}`;
        return { key: `${inode}:${st.size}:${st.mtimeNs}:${st.ctimeNs}`, inode, size: st.size };
    }
    catch {
        return undefined;
    }
}
/** How many trailing bytes of the ledger a summary keeps and re-checks on a cache hit (fix pass 1, m1). */
const TAIL_BYTES = 4096;
/** The `length` bytes of `file` that end at `end`, or undefined when they cannot be read. */
function readRange(file, end, length) {
    try {
        const fd = openSync(file, "r");
        try {
            const buf = Buffer.alloc(length);
            const n = readSync(fd, buf, 0, length, end - length);
            return n === length ? buf : undefined;
        }
        finally {
            closeSync(fd);
        }
    }
    catch {
        return undefined;
    }
}
/**
 * TEAM-ADR-069 Decision 1d: the summary of the ledger an append was made
 * against, per ledger file. Reading and parsing the whole ledger on every
 * append was always O(n); the 1 MB store cap hid that cost by reading every
 * ledger past 1 MB as empty. A hit needs the SAME device, inode, size, mtime
 * and ctime as the state summarised AND the same last TAIL_BYTES bytes, on
 * every hit (fix pass 1, m1; fix pass 2, m-c). Timestamps cannot always tell
 * two writes apart: HFS+ records whole seconds, and a Linux kernel before
 * 6.13 stamps files from a coarse clock tick whose nanosecond digits are not
 * whole milliseconds, so fix pass 1's "whole milliseconds" test missed it.
 * Any other difference forces a full re-read and re-validation, as before.
 */
const SUMMARY_CACHE = new Map();
const SUMMARY_CACHE_MAX = 256;
function summarize(entries, bytes) {
    const lastOfKind = new Map();
    for (const e of entries)
        lastOfKind.set(e.kind, e);
    return { count: entries.length, head: entries[entries.length - 1], lastOfKind, bytes, restartedAt: ledgerRestartIndex(entries) };
}
function remember(file, identity, tail, summary) {
    if (identity === undefined || tail === undefined) {
        SUMMARY_CACHE.delete(file);
        return;
    }
    if (SUMMARY_CACHE.size >= SUMMARY_CACHE_MAX && !SUMMARY_CACHE.has(file))
        SUMMARY_CACHE.clear();
    SUMMARY_CACHE.set(file, { identity: identity.key, inode: identity.inode, tail, summary });
}
/** The last min(TAIL_BYTES, size) bytes of the file as of `identity`. */
function tailOf(file, identity) {
    const size = Number(identity.size);
    return readRange(file, size, Math.min(TAIL_BYTES, size));
}
/**
 * TEAM-ADR-069 fix pass 1 (M6): the cached summary extended by lines another
 * writer APPENDED, reading only those lines, or undefined when the change
 * was anything but an append. With two gateways on one workspace every
 * append invalidated the other's cache, and each call re-parsed the whole
 * ledger (p95 40 ms at 20 MiB, measured by the review). It qualifies as an
 * append only when it is the same file (device and inode), it grew, the
 * bytes the summary ended on are unchanged at the same offset, they end a
 * line, and every new line is a structurally valid entry. Otherwise the
 * whole ledger is re-read and re-validated, as before. Stated residual: an
 * edit further back than TAIL_BYTES that coincides with such an append is
 * not seen here, and stays unseen by this process for as long as its summary
 * lasts, which can be its whole life (fix pass 2, m-b); verification (chain
 * and signatures) and export still catch it.
 */
function grownSummary(file, identity, hit) {
    const before = hit.summary.bytes;
    const after = Number(identity.size);
    // Past the cap, the full read refuses the file as oversized (M1).
    if (hit.inode !== identity.inode || after <= before || after > LEDGER_MAX_BYTES)
        return undefined;
    if (hit.tail.length > 0 && hit.tail[hit.tail.length - 1] !== 0x0a)
        return undefined;
    const oldTail = readRange(file, before, hit.tail.length);
    if (oldTail === undefined || !oldTail.equals(hit.tail))
        return undefined;
    const added = readRange(file, after, after - before);
    if (added === undefined || added[added.length - 1] !== 0x0a)
        return undefined;
    const entries = parseLedgerText(added.toString("utf8"));
    if (entries === undefined)
        return undefined;
    const lastOfKind = new Map(hit.summary.lastOfKind);
    for (const e of entries)
        lastOfKind.set(e.kind, e);
    const firstRestart = entries.findIndex((e) => e.seq === 0 && e.prevHash === GENESIS_PREV);
    const restartedAt = hit.summary.restartedAt ?? (firstRestart >= 0 && hit.summary.count + firstRestart > 0 ? hit.summary.count + firstRestart : undefined);
    const joined = Buffer.concat([hit.tail, added]);
    return {
        summary: { count: hit.summary.count + entries.length, head: entries.length > 0 ? entries[entries.length - 1] : hit.summary.head, lastOfKind, bytes: after, restartedAt },
        tail: joined.subarray(Math.max(0, joined.length - TAIL_BYTES)),
    };
}
/** The summary, the ledger file it describes, and that file's identity and tail when the summary was taken. */
function summaryOf(workspaceRoot) {
    const { file } = checkedStorePaths(workspaceRoot, LEDGER_FILE, refuse);
    const identity = fileIdentity(file);
    const hit = SUMMARY_CACHE.get(file);
    if (hit !== undefined && identity !== undefined && hit.identity === identity.key) {
        const tail = tailOf(file, identity);
        if (tail !== undefined && tail.equals(hit.tail))
            return { read: { status: "ok", summary: hit.summary }, file, identity, tail };
    }
    if (hit !== undefined && identity !== undefined) {
        const grown = grownSummary(file, identity, hit);
        if (grown !== undefined) {
            remember(file, identity, grown.tail, grown.summary);
            return { read: { status: "ok", summary: grown.summary }, file, identity, tail: grown.tail };
        }
    }
    const r = inspectLedger(workspaceRoot);
    if (r.status !== "ok") {
        SUMMARY_CACHE.delete(file);
        return { read: r, file, identity, tail: undefined };
    }
    const tail = identity === undefined ? Buffer.alloc(0) : tailOf(file, identity);
    const summary = summarize(r.entries, identity === undefined ? 0 : Number(identity.size));
    remember(file, identity, tail, summary);
    return { read: { status: "ok", summary }, file, identity, tail };
}
/**
 * The ledger's count, newest entry, newest entry of each kind, size and
 * restart point, or why it cannot be read (TEAM-ADR-069). Validates the whole
 * ledger exactly as readLedger does whenever the file has changed since the
 * last summary this process took or wrote; otherwise answers from that
 * summary.
 */
export function summarizeLedger(workspaceRoot) {
    return summaryOf(workspaceRoot).read;
}
/** The advisory lock file every appender takes around read-then-append (TEAM-ADR-069 fix pass 1, M5). */
export const LEDGER_LOCK_FILE = "ledger.lock";
/** How long an append waits for the lock before it is refused (and the gateway answers -32045). */
const LOCK_WAIT_MS = 2_000;
/** A lock older than this is stale wherever it came from; see staleLockFound for when its process being gone makes it stale sooner. */
const LOCK_STALE_MS = 30_000;
/** Block this thread for `ms` milliseconds. Atomics.wait is allowed on the main thread in Node and in Bun (checked on Node 26.5 and Bun 1.3.14, which the compiled gateway uses). */
function sleepMs(ms) {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}
/** True unless the OS says no such process exists. EPERM means it exists under another user. */
function processAlive(pid) {
    try {
        process.kill(pid, 0);
        return true;
    }
    catch (e) {
        return e.code === "EPERM";
    }
}
/** This process's place, given the platform and a way to read a symlink (parameters so both platforms' branches are tested on either). */
export function lockPlaceOf(host, platform, readlink) {
    if (platform !== "linux")
        return { host, pidNs: null };
    try {
        return { host, pidNs: readlink("/proc/self/ns/pid") };
    }
    catch {
        return { host, pidNs: "unknown" };
    }
}
let OWN_PLACE;
function ownPlace() {
    OWN_PLACE ??= lockPlaceOf(hostname(), process.platform, (p) => readlinkSync(p));
    return OWN_PLACE;
}
function parseLockToken(text) {
    try {
        const t = JSON.parse(text);
        if (typeof t === "object" && t !== null && t["v"] === 1 && typeof t["nonce"] === "string" &&
            Number.isInteger(t["pid"]) && t["pid"] > 0 && typeof t["host"] === "string" &&
            (typeof t["pidNs"] === "string" || t["pidNs"] === null) && typeof t["at"] === "number")
            return t;
    }
    catch {
        /* not a token: written by fix pass 1 ("<pid> <ms>"), not written yet, or damaged */
    }
    return undefined;
}
/** The most of a lock file that is ever read. A token is under 300 bytes. */
const LOCK_READ_MAX = 4096;
/**
 * The first LOCK_READ_MAX bytes of the regular file at `file`, or undefined
 * when there is none to read: gone, a symlink, a FIFO or a device (fix pass 3,
 * R3-5). It never follows a link and never blocks. Anyone who can write
 * `.deepsweep/` could plant `ledger.lock` as a link to a FIFO, and reading it
 * with readFileSync blocked the gateway for good, kill switch included.
 */
function readLockBytes(file) {
    let fd;
    try {
        /* v8 ignore next -- reason: O_NOFOLLOW and O_NONBLOCK are defined on every POSIX platform the suite runs on (same annotation as store.ts). */
        fd = openSync(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
    }
    catch {
        return undefined;
    }
    try {
        if (!fstatSync(fd).isFile())
            return undefined;
        const buf = Buffer.alloc(LOCK_READ_MAX);
        return buf.toString("utf8", 0, readSync(fd, buf, 0, LOCK_READ_MAX, 0));
    }
    finally {
        closeSync(fd);
    }
}
/**
 * The lock file at `file` as it is now, or undefined when it is gone
 * (released or broken meanwhile). Something at that name that is not a
 * regular file (a link, a FIFO, a directory) is never read: its text is
 * empty, so it is judged by age alone, like any lock that does not say where
 * it was written (fix pass 3, R3-5). So is a regular file that cannot be read
 * (mode 000, or another user's): before fix pass 4 (R4-6) it read as gone,
 * was never broken, and every call was refused until someone removed it.
 */
function lockState(file) {
    let st;
    try {
        st = lstatSync(file, { bigint: true });
    }
    catch {
        return undefined;
    }
    const base = { ino: st.ino, ageMs: Date.now() - Number(st.mtimeNs / 1000000n) };
    const text = st.isFile() ? readLockBytes(file) : "";
    if (text !== undefined)
        return { ...base, text };
    return pathExists(file) ? { ...base, text: "" } : undefined;
}
/** True when something is at `path` (never following a link). */
function pathExists(path) {
    try {
        lstatSync(path);
        return true;
    }
    catch {
        return false;
    }
}
/** True when `now` is the very lock that was judged: the same inode and the same bytes (every token carries a nonce). */
function sameLock(now, judged) {
    return now !== undefined && now.ino === judged.ino && now.text === judged.text;
}
/**
 * The lock at `file` if it is stale, else undefined (fix pass 2, M-1).
 * Stale means older than LOCK_STALE_MS, or, sooner, that its process is gone,
 * which is judged only when the lock says it was written on this host, in
 * this PID namespace, by a pid other than ours. A pid equal to ours in a lock
 * this process does not hold is not ours: it is another namespace's process
 * (each container's gateway is PID 1) or a worker thread, so only age applies.
 * A lock that does not say where it was written (fix pass 1's form, or one
 * not written yet) is judged by age too. A lock that vanished was released:
 * the caller tries again, never breaks (fix pass 1: treating "gone" as stale
 * let a waiter unlink a lock its holder had re-taken, and forked the chain).
 */
function staleLockFound(file) {
    const st = lockState(file);
    if (st === undefined)
        return undefined;
    if (st.ageMs > LOCK_STALE_MS)
        return st;
    const token = parseLockToken(st.text);
    const here = ownPlace();
    if (token === undefined || here.pidNs === "unknown" || token.host !== here.host || token.pidNs !== here.pidNs)
        return undefined;
    if (token.pid === process.pid)
        return undefined;
    return processAlive(token.pid) ? undefined : st;
}
/**
 * Create the lock file `file` with O_EXCL and write `token` into it: true
 * when taken, false when it already exists; any other error is thrown. If the
 * token cannot be written, the file just created is removed before the error
 * is thrown (fix pass 2, M-2): left behind empty, it made every call wait and
 * be refused until it was 30 s old. This process created it an instant ago,
 * and an empty or partial lock is judged only by age, so nobody else breaks
 * it: removing it by name removes our own.
 */
function takeLockFile(file, token) {
    let fd;
    try {
        /* v8 ignore next -- reason: constants.O_NOFOLLOW is defined on every POSIX platform the suite runs on (same annotation as store.ts). */
        fd = openSync(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
    }
    catch (e) {
        if (e.code === "EEXIST")
            return false;
        throw e;
    }
    try {
        writeAllSync(fd, Buffer.from(token, "utf8"), file);
    }
    catch (e) {
        closeSync(fd);
        try {
            unlinkSync(file);
        }
        catch {
            /* already gone */
        }
        throw e;
    }
    closeSync(fd);
    return true;
}
/**
 * Break the stale lock judged at `file` (fix pass 2, M-1), and say whether to
 * try the lock again at once (false: another gateway is breaking it, so back
 * off). Fix pass 1 unlinked
 * the lock by name on its own judgment. If another breaker had removed the
 * stale lock first and a gateway had taken a fresh one in between, that
 * unlink removed the LIVE lock, and two gateways appended at once (the round-2
 * review: 5 to 6 forked trials in 40, six gateways starting on a stale lock;
 * 3 and 7 in 40 re-measured here). Now:
 *  1. breakers take turns, through a second lock file (`ledger.lock.break`,
 *     held for microseconds, with the same token and staleness rules); a
 *     waiter that finds a break in progress just tries again;
 *  2. under it, the lock is read again, and broken only if it is still the
 *     very lock that was judged (same inode, same bytes);
 *  3. it is renamed to a name only this acquisition uses and removed only if
 *     what was moved is that lock; a lock moved by mistake (it changed between
 *     the second read and the rename, which needs its stalled holder to wake
 *     in that instant) is put back with link(), which never replaces a lock
 *     taken since, or by rename where the file system has no hard links.
 * The first design (rename and compare, without step 1) acted on judgments
 * made before another breaker's break, and forked MORE (30 and 26 trials in
 * 40): its put-back window let a third gateway take the lock. Measured, and
 * replaced before commit (ADR Addendum 2).
 */
function breakStaleLock(file, judged, token, nonce) {
    const mutex = `${file}.break`;
    // Another gateway is breaking it (the caller backs off and waits), or one
    // died mid-break and left its mutex behind.
    if (!takeLockFile(mutex, token))
        return clearDeadMutex(mutex, token, nonce);
    try {
        // Gone or replaced since it was judged: try again at once. Still there
        // but it could not be moved (an immutable file): back off (fix pass 4,
        // R4-3; trying again at once spun without end).
        return !sameLock(lockState(file), judged) || removeIfUnchanged(file, judged, `${file}.stale.${nonce}`);
    }
    finally {
        releaseLock(mutex, token, nonce, true);
    }
}
/**
 * Remove `file` only if it is still the very file that was judged (fix pass
 * 2, M-1; shared with the break mutex since fix pass 3, R3-2): rename it to
 * `aside`, a name only this caller uses, check that what moved is that file
 * (same inode, same bytes), and remove it. Anything else is put back with
 * link(), which never replaces a file created since, or by rename where the
 * file system has no hard links. Losing the rename (the file is already gone)
 * is fine. Says whether the judged file was moved away (fix pass 4, R4-3): a
 * rename that fails (an immutable file) moves nothing, and a caller that took
 * it as progress tried again at once, for ever.
 */
function removeIfUnchanged(file, judged, aside) {
    try {
        renameSync(file, aside);
    }
    catch {
        return false;
    }
    const moved = sameLock(lockState(aside), judged);
    if (!moved) {
        try {
            linkSync(aside, file);
        }
        catch (e) {
            if (e.code !== "EEXIST") {
                try {
                    renameSync(aside, file);
                }
                catch {
                    /* nothing more can be done; stated in the ADR */
                }
            }
        }
    }
    removeQuietly(aside);
    return moved;
}
/**
 * The break mutex is held by someone else. If a gateway that died while
 * breaking left it (stale by a lock's rules), exactly one waiter removes it:
 * the one that creates, with O_EXCL, the claim file named after that mutex's
 * inode and bytes, and still finds that very mutex once it holds the claim
 * (fix pass 3, R3-2; the round-3 review's "fixC"). Fix pass 2 removed a dead
 * mutex by name, so a waiter that had judged it could remove the LIVE mutex
 * another waiter had just taken, and two breakers ran at once: six to ten
 * gateways starting together on a stale lock and a dead mutex forked 2 to 13
 * trials in 200 (the review measured 2 to 22). A claim left by a waiter that
 * died holding it is judged by age alone, so it delays breaking by at most
 * LOCK_STALE_MS. Since fix pass 4 (R4-6) an aged claim is moved aside and
 * checked like a lock, so one that is a directory or cannot be read ages out
 * too; before, it was unlinked by name, which a directory survives, and every
 * call was refused for good. The mutex is moved to an aside named with this
 * acquisition's nonce (R4-3): a directory planted at the fixed aside name made
 * every rename fail, and the loop spun without end. Says whether to try again
 * at once (false: back off).
 */
function clearDeadMutex(mutex, token, nonce) {
    const judged = staleLockFound(mutex);
    if (judged === undefined)
        return false;
    const claim = `${mutex}.${judged.ino}.${sha256Hex(judged.text).slice(0, 16)}`;
    if (!takeLockFile(claim, token)) {
        const st = lockState(claim);
        if (st !== undefined && st.ageMs > LOCK_STALE_MS && !removeIfUnchanged(claim, st, `${claim}.aged.${nonce}`) && !sameLock(lockState(mutex), judged)) {
            // What moved was another waiter's claim on this same mutex, and it was
            // put back; but the mutex is no longer the one judged, so its holder is
            // past the point where the claim guards anything. If its release found
            // the claim moved aside, nothing else would ever remove it (fix pass 5:
            // fix pass 4 left such claims behind, 21 of 150 trials in the review).
            // Removing it is safe: a waiter that takes a claim by this name re-checks
            // the mutex under it, and removes nothing when the mutex has changed.
            const left = lockState(claim);
            if (left !== undefined)
                removeIfUnchanged(claim, left, `${claim}.done.${nonce}`);
        }
        return false;
    }
    try {
        // Under the claim no other current-build waiter can touch this mutex, so
        // it can only have changed if something else did; the removal is checked
        // all the same.
        return !sameLock(lockState(mutex), judged) || removeIfUnchanged(mutex, judged, `${claim}.aside.${nonce}`);
    }
    finally {
        releaseLock(claim, token, nonce, true);
    }
}
/**
 * Remove `path`; another process removing it first is fine. A directory
 * planted at a lock file's name, once moved aside, is removed if it is empty
 * and otherwise left at the aside name, where it blocks nothing (fix pass 4).
 */
function removeQuietly(path) {
    try {
        unlinkSync(path);
    }
    catch {
        try {
            rmdirSync(path);
        }
        catch {
            /* removed already, or a directory that is not empty */
        }
    }
}
/**
 * Remove the lock at `file` only if it still holds `token`, the bytes this
 * acquisition wrote (fix pass 2, M-1), reading it without following links or
 * blocking (fix pass 3, R3-5). The ledger lock, released on every decision,
 * is removed right after that check. Between the check and the removal it can
 * only have changed if this holder's own lock was broken while it stalled past
 * LOCK_STALE_MS, the stated residual. A break mutex or claim (`checked`), held
 * only while a stale lock is broken, is removed the checked way instead (fix
 * pass 3, R3-2): moved aside and put back unless it is still this token.
 * Checking every release that way measured about +0.2 ms p95 on decideFrame
 * for no case the hot path can reach.
 */
function releaseLock(file, token, nonce, checked) {
    if (!checked) {
        if (readLockBytes(file) === token)
            removeQuietly(file);
        return;
    }
    const mine = lockState(file);
    if (mine !== undefined && mine.text === token)
        removeIfUnchanged(file, mine, `${file}.release.${nonce}`);
}
/** Locks this process holds, by lock file, with their nesting depth: the lock is re-entrant within a process. */
const HELD_LOCKS = new Map();
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
export function withLedgerLock(workspaceRoot, fn, refuseWith = refuse) {
    // Containment is checked on the store directory, not on the lock file:
    // other processes create and remove the lock constantly, and resolving its
    // path races their unlink. The lock is opened with O_NOFOLLOW, so a symlink
    // planted in its place fails. A containment refusal is the caller's own
    // error type (store.ts convention), so the signature sidecar's stays typed.
    const { dir } = checkedStoreDir(workspaceRoot, refuseWith);
    const file = join(dir, LEDGER_LOCK_FILE);
    const depth = HELD_LOCKS.get(file) ?? 0;
    if (depth > 0) {
        // Re-entrant: the gateway takes the lock for a whole decision, and each
        // append inside it asks again (fix pass 1, M5).
        HELD_LOCKS.set(file, depth + 1);
        try {
            return fn();
        }
        finally {
            HELD_LOCKS.set(file, depth);
        }
    }
    const nonce = randomBytes(16).toString("hex");
    const token = `${JSON.stringify({ v: 1, nonce, pid: process.pid, ...ownPlace(), at: Date.now() })}\n`;
    const deadline = Date.now() + LOCK_WAIT_MS;
    let waitMs = 0.05;
    for (;;) {
        try {
            if (takeLockFile(file, token))
                break;
        }
        catch (e) {
            if (e.code !== "ENOENT")
                throw e;
            // First append in this workspace: the store directory does not exist
            // yet. `recursive` makes a concurrent creation by another process benign.
            mkdirSync(dir, { recursive: true });
            checkedStoreDir(workspaceRoot, refuseWith);
        }
        // Every pass checks the deadline (fix pass 4, R4-3): a break that is
        // retried at once used to skip it, and a lock that could never be moved
        // spun without end, kill switch included.
        if (Date.now() >= deadline) {
            throw Object.assign(new Error(`ELOCKED: the ledger lock is still held after ${LOCK_WAIT_MS} ms`), { code: "ELOCKED", path: file });
        }
        // A stale lock is broken and the lock tried again at once; while another
        // gateway is breaking it, or it is live, or it could not be moved, this
        // waiter backs off.
        const stale = staleLockFound(file);
        if (stale !== undefined && breakStaleLock(file, stale, token, nonce))
            continue;
        sleepMs(waitMs);
        waitMs = Math.min(waitMs * 2, 2);
    }
    HELD_LOCKS.set(file, 1);
    try {
        return fn();
    }
    finally {
        HELD_LOCKS.delete(file);
        releaseLock(file, token, nonce, false);
    }
}
/**
 * Append one entry, or say why not (TEAM-ADR-069). O(1) contained fd append
 * (ADR-018 hot-path amendment; see appendStoreLine for the durability
 * trade). Refused, and nothing written: a ledger that cannot be read, and an
 * entry that would take the file past LEDGER_MAX_BYTES (fix pass 1, M1: the
 * ledger never grows past the size every reader accepts, so it stays
 * exportable). Throws only for store failures: containment refusals, and
 * write errors including a short write (B1).
 */
export function appendLedgerEntryOrRefuse(workspaceRoot, kind, payload, nowIso) {
    return withLedgerLock(workspaceRoot, () => appendUnderLock(workspaceRoot, kind, payload, nowIso));
}
function appendUnderLock(workspaceRoot, kind, payload, nowIso) {
    const { read, file, identity, tail } = summaryOf(workspaceRoot);
    // A malformed ledger is NEVER silently rebuilt NOR silently skipped: the
    // caller surfaces the refusal loudly (ledger.corrupt finding) while the
    // corruption stays on disk for verifyAgainstAnchor. The same holds for a
    // ledger that exists but cannot be read (TEAM-ADR-069): it is refused,
    // never an empty ledger to restart at genesis.
    if (read.status !== "ok")
        return { refused: read.cause };
    const { count, head, lastOfKind, restartedAt } = read.summary;
    const prevHash = head === undefined ? GENESIS_PREV : head.entryHash;
    const body = { seq: count, prevHash, occurredAt: nowIso, kind, payload };
    const entry = { ...body, entryHash: hashEntry(body) };
    const line = Buffer.from(`${JSON.stringify(entry)}\n`, "utf8");
    const before = identity?.size ?? 0n;
    if (before + BigInt(line.length) > BigInt(LEDGER_MAX_BYTES))
        return { refused: "full" };
    // Fix pass 2 (M-4): a failed append leaves no torn line; the lock is held.
    appendStoreLine(workspaceRoot, LEDGER_FILE, line.toString("utf8"), refuse, { rollBackOnFailure: true });
    // Keep the summary only when the file grew by exactly this line, in the
    // same file, since the state it summarises. Any other writer in between
    // (or a file replaced under us) means a full re-read next time.
    const after = fileIdentity(file);
    const grewByThisLine = after !== undefined &&
        tail !== undefined &&
        after.size === before + BigInt(line.length) &&
        (identity === undefined || identity.inode === after.inode);
    if (grewByThisLine) {
        const joined = Buffer.concat([tail, line]);
        remember(file, after, joined.subarray(Math.max(0, joined.length - TAIL_BYTES)), {
            count: count + 1,
            head: entry,
            lastOfKind: new Map(lastOfKind).set(kind, entry),
            bytes: Number(after.size),
            restartedAt,
        });
    }
    else
        SUMMARY_CACHE.delete(file);
    return { entry };
}
/**
 * Append one entry. A refusal (see appendLedgerEntryOrRefuse) is the
 * "corrupt" sentinel, which every caller already surfaces loudly. Throws
 * only for store failures.
 */
export function appendLedgerEntry(workspaceRoot, kind, payload, nowIso) {
    const r = appendLedgerEntryOrRefuse(workspaceRoot, kind, payload, nowIso);
    return "entry" in r ? r.entry : "corrupt";
}
/** Leaves of the anchored evidence tree: the RFC 6962 leaf hash of each
 * entry's entryHash bytes. The entryHash already binds the full canonical
 * entry AND its chain position (prevHash/seq are inside the hashed body),
 * so the tree inherits both without re-serializing payloads.
 *
 * TEAM-ADR-025: this tree is a SECOND instantiation of the ONE Merkle
 * module (src/evidence/merkle.ts, ADR-DS-005) — not a second implementation.
 * ADR-DS-005's export tree commits to evidence RECORDS (auditor-facing,
 * frozen by contracts/schemas/evidence-record.v1.json at v0.8.0); this one
 * commits to LEDGER ENTRIES, because an anchor is signed without knowing the
 * workspace label a record carries. Same primitives, same proof format. */
function ledgerLeaves(entries) {
    return entries.map((e) => hashLeaf(Buffer.from(e.entryHash, "hex")));
}
/** RFC 6962 tree head (hex) over the ledger's entries. */
export function ledgerTreeHead(entries) {
    return merkleRoot(ledgerLeaves(entries));
}
/** Prove one entry's inclusion in the current tree. Refuses out-of-range. */
export function proveLedgerInclusion(entries, index) {
    if (!Number.isInteger(index) || index < 0 || index >= entries.length) {
        throw refuse(`cannot prove inclusion of entry ${index} in a ledger of ${entries.length} entries`);
    }
    const leaves = ledgerLeaves(entries);
    return {
        entryHash: entries[index].entryHash,
        index,
        treeSize: entries.length,
        treeHead: merkleRoot(leaves),
        proof: inclusionProof(leaves, index),
    };
}
/** Verify a portable inclusion proof against its tree head (which a verifier
 * takes from a signed anchor, never from the proof's author). The entryHash
 * is re-leaf-hashed here, so a caller cannot substitute a node for a leaf.
 * Malformed hex fails closed with a reason, never throws. */
export function verifyLedgerInclusion(p) {
    if (!isDigest(p.entryHash) || !isDigest(p.treeHead) || !p.proof.every(isDigest)) {
        return { ok: false, why: "proof carries non-sha256-hex material — refusing (fail closed)" };
    }
    return explainInclusion(hashLeaf(Buffer.from(p.entryHash, "hex")), p.index, p.treeSize, p.proof, p.treeHead);
}
/** Export a signed anchor of the CURRENT chain head. Empty ledger refuses. */
export function exportAnchor(entries, privateKey, nowIso) {
    if (entries.length === 0)
        throw refuse("cannot anchor an empty ledger");
    if (!verifyChain(entries))
        throw refuse("cannot anchor a ledger whose own chain does not verify");
    const anchor = {
        chainHead: entries[entries.length - 1].entryHash,
        entryCount: entries.length,
        anchoredAt: nowIso,
        genesisHash: entries[0].entryHash,
        treeHead: ledgerTreeHead(entries),
    };
    const publicKey = createPublicKey(privateKey);
    return {
        anchor,
        signature: edSign(null, Buffer.from(canonicalize(anchor), "utf8"), privateKey).toString("base64"),
        keyId: keyIdFor(publicKey),
    };
}
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
export function verifyAgainstAnchor(entries, signed, trustedKeys) {
    const env = signed;
    const anchor = env?.["anchor"];
    const signature = env?.["signature"];
    const keyId = env?.["keyId"];
    if (typeof env !== "object" ||
        env === null ||
        typeof anchor !== "object" ||
        anchor === null ||
        typeof anchor.chainHead !== "string" ||
        typeof anchor.genesisHash !== "string" ||
        typeof anchor.anchoredAt !== "string" ||
        !Number.isInteger(anchor.entryCount) ||
        anchor.entryCount < 1 ||
        typeof signature !== "string" ||
        typeof keyId !== "string") {
        return { status: "untrusted-anchor", detail: "anchor envelope is malformed" };
    }
    const pinned = trustedKeys.find((k) => k.keyId === keyId);
    if (pinned === undefined) {
        return { status: "untrusted-anchor", detail: `anchor keyId ${keyId} is not pinned` };
    }
    let publicKey;
    try {
        publicKey = pinned.publicKey.includes("BEGIN PUBLIC KEY")
            ? createPublicKey(pinned.publicKey)
            : createPublicKey({ key: Buffer.from(pinned.publicKey, "base64"), format: "der", type: "spki" });
    }
    catch {
        return { status: "untrusted-anchor", detail: `pinned key ${keyId} is not a valid public key` };
    }
    if (keyIdFor(publicKey) !== keyId) {
        return { status: "untrusted-anchor", detail: `pinned key material does not derive keyId ${keyId}` };
    }
    let sigOk = false;
    try {
        sigOk = edVerify(null, Buffer.from(canonicalize(anchor), "utf8"), publicKey, Buffer.from(signature, "base64"));
    }
    catch {
        sigOk = false;
    }
    if (!sigOk) {
        return { status: "untrusted-anchor", detail: `anchor signature does not verify under ${keyId}` };
    }
    if (!verifyChain(entries)) {
        return { status: "tampered", detail: "internal hash chain does not verify — an entry was edited" };
    }
    if (entries.length < anchor.entryCount) {
        return {
            status: "truncated",
            detail: `ledger has ${entries.length} entries but the anchor attested ${anchor.entryCount}`,
        };
    }
    if (entries[0].entryHash !== anchor.genesisHash) {
        return { status: "replaced", detail: "genesis hash differs from the anchored genesis — wholesale replacement" };
    }
    if (entries[anchor.entryCount - 1].entryHash !== anchor.chainHead) {
        return {
            status: "forked",
            detail: `entry ${anchor.entryCount - 1} is not the anchored chain head — history rewritten after genesis`,
        };
    }
    if (anchor.treeHead !== undefined) {
        // TEAM-ADR-025: the anchored RFC 6962 head must reproduce over the
        // anchored prefix. Signature already binds the field; a wrong type or a
        // mismatch is treated as tampering, never ignored (fail closed).
        if (typeof anchor.treeHead !== "string") {
            return { status: "tampered", detail: "anchor treeHead is not a string — malformed anchored fact" };
        }
        if (ledgerTreeHead(entries.slice(0, anchor.entryCount)) !== anchor.treeHead) {
            return {
                status: "tampered",
                detail: "anchored RFC 6962 tree head does not reproduce over the anchored prefix",
            };
        }
    }
    if (entries.length === anchor.entryCount) {
        return { status: "verified", detail: `chain head matches the anchor at ${anchor.entryCount} entries` };
    }
    return {
        status: "verified-appended",
        appendedEntries: entries.length - anchor.entryCount,
        detail: `anchored prefix intact; ${entries.length - anchor.entryCount} honest entries appended since the anchor`,
    };
}
