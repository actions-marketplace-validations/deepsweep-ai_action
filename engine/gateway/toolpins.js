/**
 * Tool-description pinning AT THE WIRE (TEAM-ADR-039) — the rug-pull circuit
 * breaker.
 *
 * ADR-003 pins tool descriptions from static config files. A live MCP server
 * can change what a tool SAYS it does after the agent trusted it (the "rug
 * pull": benign description at review time, exfiltration instructions at
 * call time). The gateway sees every `tools/list` response, so it can pin the
 * canonical hash of each tool's (name, description, inputSchema) on first
 * sight (TOFU) and detect any later change — per server, per tool. Since
 * TEAM-ADR-069 fix pass 6 (R6-3) a second hash covers every field of the tool
 * but `_meta` (title, annotations, outputSchema, icons and any other), so a
 * change a model or its client sees in any of them is a drift too.
 *
 * Response: a drifted tool is a `gateway.tool_drift` ledger event AND a
 * tripped breaker: subsequent `tools/call` to that tool is DENIED (fail
 * closed, ADR-010 posture) until a human re-pins
 * (`deepsweep-gateway repin --name <server> --tool <tool>`), which is itself a
 * ledger event. Content never enters the ledger — only hashes.
 *
 * Store: `.deepsweep/tool-pins.json` (contained, atomic, written holding the
 * ledger lock since TEAM-ADR-069 fix pass 4). Shape:
 *   { schemaVersion: 1, servers: { [server]: { [tool]: { hash, pinnedAt, status: "pinned"|"drifted", seenHash?, repins?, fieldsHash?, seenFieldsHash? } } } }
 */
import { resolve } from "node:path";
import { canonicalize, sha256Hex } from "../review/canonical.js";
import { withLedgerLock } from "../review/ledger.js";
import { MAX_FILE_BYTES } from "../review/read.js";
import { readStoreFile, writeStoreAtomic } from "../review/store.js";
import { appendSignedEntry, describeStoreError, recordEntry } from "./record.js";
export const TOOL_PINS_FILE = "tool-pins.json";
/** A containment refusal of the pin store (ADR-003): a symlinked or non-regular `tool-pins.json`. */
export class ToolPinRefusalError extends Error {
    constructor(reason) {
        super(`tool pins refused: ${reason}`);
        this.name = "ToolPinRefusalError";
    }
}
const refuse = (reason) => new ToolPinRefusalError(reason);
const EMPTY = { schemaVersion: 1, servers: {} };
/**
 * Read the pin store. Absent → no pins. Malformed, or present but unreadable
 * (permissions, over the store's size cap, not a regular file) → undefined,
 * and the caller fails closed by treating every tool as tripped. Before
 * TEAM-ADR-069 fix pass 2 an unreadable store read as absent, so a drifted
 * tool was forwarded once `tool-pins.json` could not be read (the round-2
 * review, P1 class): an unreadable safety store never degrades.
 */
export function readToolPins(workspaceRoot) {
    const r = readStoreFile(workspaceRoot, TOOL_PINS_FILE, refuse);
    if (r.status === "absent")
        return EMPTY;
    if (r.status === "unreadable")
        return undefined;
    try {
        const v = JSON.parse(r.text);
        if (typeof v !== "object" || v === null || Array.isArray(v))
            return undefined;
        const f = v;
        if (f["schemaVersion"] !== 1 || typeof f["servers"] !== "object" || f["servers"] === null)
            return undefined;
        return v;
    }
    catch {
        return undefined;
    }
}
/**
 * Save the pin store. A store that would be larger than the size it is read
 * at is never written (TEAM-ADR-069 fix pass 5): read back, it would be
 * unreadable, and every tool of every server would be refused until someone
 * fixed the file by hand. The save is refused instead, so only the list that
 * would have grown it is withheld.
 */
function writeToolPins(workspaceRoot, pinsOrText) {
    const text = typeof pinsOrText === "string" ? pinsOrText : `${JSON.stringify(pinsOrText, null, 2)}\n`;
    const bytes = Buffer.byteLength(text, "utf8");
    if (bytes > MAX_FILE_BYTES)
        throw refuse(`saving these pins would make ${TOOL_PINS_FILE} ${bytes} bytes, past the ${MAX_FILE_BYTES}-byte (1 MB) limit it can be read at`);
    writeStoreAtomic(workspaceRoot, TOOL_PINS_FILE, text, refuse);
}
/**
 * The value of `o`'s OWN property `k` (TEAM-ADR-069 fix pass 5). A tool is
 * named by the server, so its name can be "__proto__", "constructor" or
 * "toString": a plain lookup found the property every object inherits, and a
 * plain assignment of "__proto__" set the map's prototype. Such a tool was
 * never pinned ("__proto__": a changed description was forwarded) or was read
 * as a pin with no hash (refused from first sight).
 */
function own(o, k) {
    return o !== undefined && Object.hasOwn(o, k) ? o[k] : undefined;
}
/** One server's pins in the store, read as an own property; undefined when there are none or the entry is not an object. */
function serverPins(pins, serverName) {
    const s = pins === undefined ? undefined : own(pins.servers, serverName);
    return typeof s === "object" && s !== null ? s : undefined;
}
/** The stored pin of one tool, read as own properties only (fix pass 5). The one way anything reads a pin. */
export function storedPin(pins, serverName, toolName) {
    return own(serverPins(pins, serverName), toolName);
}
/** Canonical identity of what a tool CLAIMS to be. Byte-preserving (ADR-003): any code-point change is drift. */
export function toolDescriptionHash(tool) {
    return sha256Hex(canonicalize({ name: tool["name"], description: tool["description"] ?? null, inputSchema: tool["inputSchema"] ?? null }));
}
/**
 * The hash of every field of a tool but `_meta` (TEAM-ADR-069 fix pass 6,
 * R6-3): title, annotations, outputSchema, icons and any field the protocol
 * adds later. A model or its client reads these; `_meta` is left out because
 * servers put changing bookkeeping there. Before, a rug pull carried in the
 * title or the annotations was relayed and the call forwarded.
 */
export function toolFieldsHash(tool) {
    const fields = { ...tool };
    delete fields["_meta"];
    return sha256Hex(`tool-fields/v2\n${canonicalize(fields)}`);
}
/**
 * The operator's diagnostic lines for one observed tools/list, shared by both
 * transports so they cannot word it differently (TEAM-ADR-040 Decision 1): one
 * per drifted tool, and one per pin record that is missing or unsigned (fix
 * pass 3, R3-1).
 */
export function observeDiagnostics(serverName, r) {
    return [...r.drifted.map((t) => `tool drift ${serverName}/${t}`), ...r.notes.map((n) => `pinned ${serverName} tools/list -- ${n}`)];
}
/** Latches by workspace and server, then by tool. */
const UNSAVED_DRIFT = new Map();
const serverKey = (workspaceRoot, serverName) => JSON.stringify([resolve(workspaceRoot), serverName]);
const samePin = (a, b) => a.hash === b.hash && a.pinnedAt === b.pinnedAt && (a.repins ?? 0) === (b.repins ?? 0);
/** True when the store's pin `cur` supersedes the latch `l` (see Latch). */
const superseded = (cur, l) => cur === undefined || cur.status === "drifted" || !samePin(cur, l.pin);
/** Latch a drift from `pin` to what was `seen`, unless one is latched against that very pin already: the first sighting, and whether it is recorded, are kept. */
function latch(latches, toolName, pin, seen) {
    const l = latches.get(toolName);
    if (l !== undefined && samePin(l.pin, pin))
        return l;
    const fresh = { seen, pin, recorded: false };
    latches.set(toolName, fresh);
    return fresh;
}
/**
 * A `gateway.tool_drift` entry: the description hashes as before, and the
 * fields hashes when the pin has one (fix pass 6), so a change in the fields
 * alone reads as one: equal description hashes, different fields hashes.
 */
const driftEntry = (serverName, toolName, pin, seen, l) => ({
    kind: "gateway.tool_drift",
    payload: {
        serverHash: sha256Hex(serverName), toolHash: sha256Hex(toolName), pinnedHash: pin.hash, seenHash: seen.hash,
        ...(pin.fieldsHash !== undefined ? { pinnedFieldsHash: pin.fieldsHash, seenFieldsHash: seen.fieldsHash } : {}),
    },
    drift: true,
    ...(l !== undefined ? { latch: l } : {}),
});
/**
 * The most pin entries recorded in one hold of the ledger lock (fix pass 6,
 * R6-4). A list that pinned or changed thousands of tools recorded them all in
 * one hold, about 0.45 ms apiece, and other gateways waiting on the lock were
 * refused after their 2 s wait. Entries are recorded after the pins are saved,
 * in turns of at most this many, so another gateway can take its turn between.
 */
export const RECORD_TURN = 250;
/**
 * How long a recorder waits between its turns, in ms. A waiting gateway polls
 * the lock at most every 2 ms, so without a pause the recorder took the lock
 * back before any waiter saw it free (measured: the other gateway still waited
 * out the whole list).
 */
const TURN_PAUSE_MS = 4;
const pause = (ms) => { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); };
/**
 * Record the pin entries under the one signing rule (fix pass 3, R3-1): an
 * entry the ledger refuses, one it cannot take, and a signature that cannot be
 * written are each a note, never a throw. A drift entry that lands marks its
 * latch recorded, so a drift is recorded once (fix pass 4, R4-4). They are
 * recorded in turns of the ledger lock of at most RECORD_TURN entries.
 */
function recordPinEntries(root, planned, nowIso, key) {
    const entries = [];
    const notes = [];
    let done = 0;
    try {
        while (done < planned.length) {
            if (done > 0)
                pause(TURN_PAUSE_MS);
            const turn = planned.slice(done, done + RECORD_TURN);
            withLedgerLock(root, () => {
                for (const p of turn) {
                    const r = recordEntry(root, p.kind, p.payload, nowIso, key);
                    done += 1;
                    if (r.status === "refused")
                        notes.push(`the ${p.kind} entry is not on the ledger: ${r.why}`);
                    else {
                        if (p.latch !== undefined)
                            p.latch.recorded = true;
                        entries.push(r.entry);
                        if (r.unsigned !== undefined)
                            notes.push(`the ${p.kind} entry is on the ledger, but ${r.unsigned}`);
                    }
                }
            });
        }
    }
    catch (e) {
        const why = describeStoreError(e);
        if (why === undefined)
            throw e;
        notes.push(`${planned.length - done} pin record(s) are not on the ledger: a gateway record could not be written or read (${why})`);
    }
    return { entries, notes };
}
/** What could not be recorded when the pins could not be saved, by the error that was thrown (fix pass 4, R4-4). */
const SAVE_FAILURE_NOTES = new WeakMap();
/** The notes `observeToolList` attached to the error it threw, for the operator's diagnostic; none for any other error. */
export function pinSaveNotes(e) {
    return SAVE_FAILURE_NOTES.get(e) ?? [];
}
/**
 * The tools of a tools/list answer, by name, with EVERY entry listed under
 * that name, in order; anything without a usable name is skipped. A server
 * can name one tool twice (TEAM-ADR-069 fix pass 5, the fix-pass-4 review's
 * BLOCKER): fix pass 4 kept only the last description, so a rug pull listed
 * first and the pinned description listed last was never seen. A tool that
 * cannot be hashed (nested too deeply to encode) refuses the whole answer, so
 * it is withheld (fix pass 6: it threw out of the gateway before).
 */
function listedTools(tools) {
    const out = new Map();
    for (const raw of tools) {
        if (typeof raw !== "object" || raw === null || Array.isArray(raw))
            continue;
        const t = raw;
        const name = t["name"];
        if (typeof name !== "string" || name.length === 0)
            continue;
        let seen;
        try {
            seen = { hash: toolDescriptionHash(t), fieldsHash: toolFieldsHash(t) };
        }
        catch {
            throw refuse(`the description of tool ${JSON.stringify(name.slice(0, 64))} could not be read (nested too deeply)`);
        }
        const all = out.get(name);
        if (all === undefined)
            out.set(name, [seen]);
        else
            all.push(seen);
    }
    return out;
}
/** True when `seen` is not what `pin` pinned: its description hash differs, or, when the pin has one, its fields hash. */
const differs = (seen, pin) => seen.hash !== pin.hash || (pin.fieldsHash !== undefined && seen.fieldsHash !== pin.fieldsHash);
/** The first listed entry that is not what `pin` pinned, or undefined when every entry under the name is. */
function firstDiffering(all, pin) {
    return all.find((s) => differs(s, pin));
}
/** What `pin` pinned, as a Seen: its fields hash, or `fallback`'s where the pin has none yet. */
const pinnedAs = (pin, fallback) => ({ hash: pin.hash, fieldsHash: pin.fieldsHash ?? fallback.fieldsHash });
/** A stored pin this build can read. An earlier build wrote pins with no hash for tools named after inherited properties ("constructor"); those are pinned afresh (fix pass 6). */
const wellFormed = (pin) => typeof pin.hash === "string" && (pin.status === "pinned" || pin.status === "drifted");
/**
 * The most new tools one tools/list answer may pin (fix pass 5). Past it, the
 * first MAX_NEW_PINS_PER_LIST are pinned, the drifts in the answer are saved,
 * and the answer is withheld; asking again pins the next ones (fix pass 6:
 * before, nothing was pinned and a server with more tools was withheld for
 * good).
 */
export const MAX_NEW_PINS_PER_LIST = 1000;
/**
 * The size a save that pins new tools (or adds fields hashes) may make the
 * pin store (fix pass 6, R6-4). The rest, up to the 1 MB it is read at, is
 * kept for drift marks and re-pins: a store filled with pins still has room
 * to save that a tool changed, so a restarted gateway still refuses it.
 */
export const PIN_STORE_GROWTH_BYTES = 900_000;
/** The pin store as text. */
const storeText = (pins) => `${JSON.stringify(pins, null, 2)}\n`;
/**
 * Observe one `tools/list` result. First sight pins (TOFU); a changed hash
 * marks the tool drifted (breaker tripped) and records `gateway.tool_drift`
 * once; an already-drifted tool that changes AGAIN updates seenHash silently
 * (still tripped). Returns which tools fell into which bucket.
 *
 * Order (TEAM-ADR-069 fix pass 4, R4-1): first every drift is latched from a
 * read without the lock, so a lock that cannot be taken still withholds the
 * list and refuses the changed tool. Then, holding the ledger lock, the store
 * is read again, only this server's entries change on that fresh copy, and it
 * is written. A drift in the store is never undone here; only a person's
 * re-pin does that. The entries are recorded after the lock is released, in
 * turns (fix pass 6, R6-4).
 *
 * If the save throws, the drift entries are recorded anyway, once per latch
 * (fix pass 4, R4-4), and the error is thrown on for the caller to withhold
 * the list; the latches go on refusing the changed tools. A latched drift is
 * saved with what the server serves now when the tool is listed (fix pass 4,
 * R4-2).
 *
 * Limits (fix pass 6, R6-4): at most MAX_NEW_PINS_PER_LIST new pins per answer,
 * and new pins only while the store stays within PIN_STORE_GROWTH_BYTES. Past
 * either, the drift marks are still saved, what fits is pinned, and the
 * answer is withheld (a ToolPinRefusalError, thrown after the entries are
 * recorded).
 */
export function observeToolList(workspaceRoot, serverName, tools, nowIso, key) {
    const listed = listedTools(tools);
    const sk = serverKey(workspaceRoot, serverName);
    const latches = UNSAVED_DRIFT.get(sk) ?? new Map();
    const peek = serverPins(readToolPins(workspaceRoot), serverName);
    for (const [name, all] of listed) {
        const cur = own(peek, name);
        const changed = cur === undefined || !wellFormed(cur) ? undefined : firstDiffering(all, cur);
        if (cur !== undefined && cur.status === "pinned" && changed !== undefined)
            latch(latches, name, cur, changed);
    }
    if (latches.size > 0)
        UNSAVED_DRIFT.set(sk, latches);
    const plan = withLedgerLock(workspaceRoot, () => saveLocked(workspaceRoot, serverName, listed, sk, latches, nowIso), refuse);
    if ("failed" in plan) {
        // Not saved: nothing claims a pin (no tool_pinned entry), but each drift is recorded once; its latch refuses the tool meanwhile.
        const r = recordPinEntries(workspaceRoot, plan.planned.filter((p) => p.drift === true), nowIso, key);
        // writeToolPins throws only objects: file-system errors and ToolPinRefusalError.
        if (r.notes.length > 0)
            SAVE_FAILURE_NOTES.set(plan.failed, r.notes);
        throw plan.failed;
    }
    const r = recordPinEntries(workspaceRoot, plan.planned, nowIso, key);
    if (plan.withheld !== undefined) {
        if (r.notes.length > 0)
            SAVE_FAILURE_NOTES.set(plan.withheld, r.notes);
        throw plan.withheld;
    }
    return { pinned: plan.pinned, unchanged: plan.unchanged, drifted: plan.drifted, entries: r.entries, notes: r.notes };
}
/** Under the ledger lock: read the store afresh, change this server's entries, save what fits. Records nothing (the caller does, in turns). */
function saveLocked(root, serverName, listed, sk, latches, nowIso) {
    const pins = readToolPins(root);
    if (pins === undefined) {
        // Nothing is written over a store that cannot be read; isToolTripped trips every tool meanwhile.
        return { pinned: [], unchanged: [], drifted: [], planned: [{ kind: "gateway.tool_pins_unreadable", payload: { serverHash: sha256Hex(serverName) } }] };
    }
    const stored = serverPins(pins, serverName);
    for (const [name, l] of latches)
        if (superseded(own(stored, name), l))
            latches.delete(name);
    // Maps with no prototype, so a tool named "__proto__" is an entry like any other (fix pass 5).
    // `marks` holds only drift marks and seen updates; `server` also holds new pins and fields-hash upgrades.
    const marks = Object.assign(Object.create(null), stored);
    const server = Object.assign(Object.create(null), stored);
    const pinned = [];
    const unchanged = [];
    const drifted = [];
    const planned = [];
    let overCap = 0;
    /** Tools this answer marks drifted, each latched before the write. */
    const marking = [];
    let marked = 0;
    const mark = (name, pin) => { marks[name] = pin; server[name] = pin; marked += 1; };
    const markDrifted = (name, pin, l, served) => {
        mark(name, { ...pin, status: "drifted", seenHash: served.hash, seenFieldsHash: served.fieldsHash });
        drifted.push(name);
        marking.push(name);
        if (!l.recorded)
            planned.push(driftEntry(serverName, name, l.pin, l.seen, l));
    };
    // Every entry listed under a name is compared with its pin: any that differs
    // is a drift, and the first that differs is the one recorded, even when the
    // pinned one is listed too (fix pass 5).
    for (const [name, all] of listed) {
        const stale = own(stored, name);
        const cur = stale !== undefined && wellFormed(stale) ? stale : undefined;
        const l = latches.get(name);
        const first = all[0];
        if (cur === undefined) {
            // First sight pins the first entry; a conflicting entry under the same
            // name is a drift at once. At most MAX_NEW_PINS_PER_LIST per answer.
            if (pinned.length >= MAX_NEW_PINS_PER_LIST) {
                overCap += 1;
                continue;
            }
            const pin = { hash: first.hash, pinnedAt: nowIso, status: "pinned", fieldsHash: first.fieldsHash };
            const changed = firstDiffering(all, pin);
            server[name] = changed === undefined ? pin : { ...pin, status: "drifted", seenHash: changed.hash, seenFieldsHash: changed.fieldsHash };
            pinned.push(name);
            planned.push({ kind: "gateway.tool_pinned", payload: { serverHash: sha256Hex(serverName), toolHash: sha256Hex(name), descriptionHash: pin.hash, fieldsHash: first.fieldsHash } });
            if (changed !== undefined) {
                drifted.push(name);
                planned.push(driftEntry(serverName, name, pin, changed));
            }
        }
        else if (cur.status === "drifted") {
            // Tripped until a person re-pins. The observation is kept, so the timeline
            // shows a flip-flop (back to the pinned description) or a second change.
            const changed = firstDiffering(all, cur);
            const seen = changed ?? pinnedAs(cur, first);
            mark(name, { ...cur, seenHash: seen.hash, seenFieldsHash: seen.fieldsHash });
            (changed === undefined ? unchanged : drifted).push(name);
        }
        else {
            // A pin saved before fix pass 6 gains its fields hash from the first entry
            // when the description hash matches: an upgrade, not a change.
            const pin = cur.fieldsHash !== undefined || all.some((s) => s.hash !== cur.hash) ? cur : { ...cur, fieldsHash: first.fieldsHash };
            const changed = firstDiffering(all, pin);
            // Changed now, or changed earlier and latched (the server may have switched back since).
            // The latch keeps the upgraded pin (same identity: hash, pinnedAt, repins), so its entry carries the fields hashes.
            if (changed !== undefined || l !== undefined)
                markDrifted(name, pin, latch(latches, name, pin, changed ?? pinnedAs(pin, first)), changed ?? pinnedAs(pin, first));
            else {
                if (pin !== cur)
                    server[name] = pin;
                unchanged.push(name);
            }
        }
    }
    // A latched drift of a tool this answer does not list is saved with what was seen.
    for (const [name, l] of latches) {
        if (!listed.has(name))
            markDrifted(name, own(stored, name), l, l.seen);
    }
    const publish = () => {
        if (latches.size > 0)
            UNSAVED_DRIFT.set(sk, latches);
        else
            UNSAVED_DRIFT.delete(sk);
    };
    const full = storeText({ schemaVersion: 1, servers: { ...pins.servers, [serverName]: server } });
    const growth = Buffer.byteLength(full, "utf8") <= PIN_STORE_GROWTH_BYTES;
    let withheld;
    if (overCap > 0)
        withheld = refuse(`this answer names ${pinned.length + overCap} tools that are not pinned yet; at most ${MAX_NEW_PINS_PER_LIST} are pinned from one answer, so ${overCap} are left for the next`);
    try {
        if (growth)
            writeToolPins(root, full);
        else {
            // Only the drift marks: new pins and fields-hash upgrades wait for room.
            // If even the marks with what was seen do not fit, the tools are saved as
            // drifted without it (one byte each): the ledger entries still carry the
            // hashes, and the store still refuses the tools after a restart. A re-pin
            // of such a tool keeps its pinned description until a list with room
            // records what the server serves.
            if (marked > 0) {
                const withSeen = storeText({ schemaVersion: 1, servers: { ...pins.servers, [serverName]: marks } });
                if (Buffer.byteLength(withSeen, "utf8") <= MAX_FILE_BYTES)
                    writeToolPins(root, withSeen);
                else {
                    const slim = Object.assign(Object.create(null), stored);
                    for (const name of marking)
                        slim[name] = { ...own(stored, name), status: "drifted" };
                    writeToolPins(root, storeText({ schemaVersion: 1, servers: { ...pins.servers, [serverName]: slim } }));
                }
            }
            for (const name of pinned) {
                const i = drifted.indexOf(name);
                if (i >= 0)
                    drifted.splice(i, 1);
            }
            if (pinned.length > 0)
                withheld = refuse(`pinning ${pinned.length} new tool(s) would make ${TOOL_PINS_FILE} ${Buffer.byteLength(full, "utf8")} bytes, past the ${PIN_STORE_GROWTH_BYTES} bytes it may grow to by new pins (the rest of its 1 MB is kept for changes)`);
            // Nothing of the new pins was saved: no tool_pinned entry claims one; a drift seen on first sight is still recorded.
            planned.splice(0, planned.length, ...planned.filter((p) => p.kind !== "gateway.tool_pinned"));
            pinned.splice(0, pinned.length);
        }
    }
    catch (e) {
        publish();
        return { failed: e, planned };
    }
    // Saved: the store trips these tools now.
    for (const name of marking)
        latches.delete(name);
    publish();
    return { pinned, unchanged, drifted, planned, ...(withheld !== undefined ? { withheld } : {}) };
}
/**
 * Is the breaker tripped for this tool? Unpinned tools are NOT tripped (a call
 * before any tools/list is governed by policy alone). A drift this process
 * observed that the store does not hold yet → tripped (fix pass 3, R3-1),
 * until the store supersedes it (fix pass 4, R4-5: a re-pin made elsewhere is
 * honoured, not undone). Unreadable store → tripped (fail closed), and so is
 * one refused by containment (a symlinked or non-regular `tool-pins.json`),
 * which used to throw out of the decision and end a stdio gateway (found
 * alongside R3-1).
 */
export function isToolTripped(workspaceRoot, serverName, toolName) {
    const latches = UNSAVED_DRIFT.size === 0 ? undefined : UNSAVED_DRIFT.get(serverKey(workspaceRoot, serverName));
    const l = latches?.get(toolName);
    let pins;
    try {
        pins = readToolPins(workspaceRoot);
    }
    catch (e) {
        if (e instanceof ToolPinRefusalError)
            return true;
        throw e;
    }
    if (pins === undefined)
        return true;
    const cur = storedPin(pins, serverName, toolName);
    if (l !== undefined) {
        if (!superseded(cur, l))
            return true;
        latches.delete(toolName);
    }
    return cur?.status === "drifted";
}
/**
 * Human re-pins a drifted tool to what the server currently claims (its last
 * seen hash). Ledger event `gateway.tool_repinned`. The read, the check and
 * the write hold the ledger lock (fix pass 4, R4-1), so a re-pin and a
 * gateway's save never overwrite each other; the pin counts its re-pins.
 */
export function repinTool(workspaceRoot, serverName, toolName, approver, nowIso, key) {
    return withLedgerLock(workspaceRoot, () => {
        const pins = readToolPins(workspaceRoot);
        if (pins === undefined)
            return { ok: false, reason: "unreadable" };
        const cur = storedPin(pins, serverName, toolName);
        if (cur === undefined)
            return { ok: false, reason: "unknown-tool" };
        if (cur.status !== "drifted")
            return { ok: false, reason: "not-drifted" };
        // The fields hash of what was seen, when the drift recorded one; a drift an
        // earlier build saved has none, and the next list adds it (fix pass 6).
        const fieldsHash = cur.seenHash !== undefined ? cur.seenFieldsHash : cur.fieldsHash;
        const next = { hash: cur.seenHash ?? cur.hash, pinnedAt: nowIso, status: "pinned", repins: (cur.repins ?? 0) + 1, ...(fieldsHash !== undefined ? { fieldsHash } : {}) };
        // Spread and computed keys define own properties, so a tool named "__proto__" is written like any other.
        writeToolPins(workspaceRoot, { schemaVersion: 1, servers: { ...pins.servers, [serverName]: { ...serverPins(pins, serverName), [toolName]: next } } });
        appendSignedEntry(workspaceRoot, "gateway.tool_repinned", { serverHash: sha256Hex(serverName), toolHash: sha256Hex(toolName), previousHash: cur.hash, descriptionHash: next.hash, ...(fieldsHash !== undefined ? { fieldsHash } : {}), approverHash: sha256Hex(approver) }, nowIso, key);
        return { ok: true };
    }, refuse);
}
