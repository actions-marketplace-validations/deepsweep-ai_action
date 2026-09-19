/**
 * Pin-key resolution — the unpredictability half of the pinned-identity
 * scheme (TEAM-ADR-047).
 *
 * WHY THIS MODULE EXISTS. A pinned digest has to be byte-stable across runs
 * for drift detection to work at all, and an unkeyed SHA-256 over a guessable
 * preimage (an internal hostname, a repo basename, an npm package specifier,
 * a three-word tool name) is a CONFIRMATION ORACLE: anyone holding the digest
 * can hash their guesses until one matches. Redaction cannot fix that class —
 * `mcp/filesystem/write_file` contains nothing to redact. Only key material
 * the guesser does not hold closes it, so every pinned identity in this
 * engine is HMAC-SHA256 under a key that never leaves the machine.
 *
 * WHERE THE KEY LIVES, in precedence order:
 *  1. `DEEPSWEEP_PIN_KEY` — >= 64 hex characters (32 bytes). The explicit
 *     custody path: a CI secret, so a committed/restored baseline still
 *     compares on a build agent. A malformed value REFUSES loudly rather than
 *     silently falling back to a weaker key (the value is never echoed).
 *  2. `<state dir>/pin-key`, created 0600 on first use. The state dir is
 *     `DEEPSWEEP_STATE_DIR` when set, else `~/.deepsweep`. Deliberately
 *     OUTSIDE the workspace: `.deepsweep/baseline.json` is designed to be
 *     safe to commit, so a key stored beside it would ship with the artifact
 *     and restore the oracle (the ruling in ADR-005 F1 — "keyed HMAC under
 *     out-of-workspace key material, or nothing").
 *  3. No durable store reachable (read-only or absent home): a per-process
 *     ephemeral key. Pins stay internally consistent for the life of the
 *     process, the baseline's recorded `pinKeyId` stops matching on the next
 *     run, and the existing regenerate-not-migrate path raises a visible
 *     `baseline.regenerated` warning. Degradation is loud, never silent.
 *
 * WHAT THE KEY IS NOT. It is not a tamper control and must never be described
 * as one: an agent that can rewrite `.deepsweep/` can also read this file if
 * it runs as the same user. It buys oracle resistance against a party holding
 * the ARTIFACT, which is the published-artifact threat model, and nothing
 * more. Key loss is not data loss — it forces a re-pin, the same blast radius
 * the baseline already accepts on regeneration.
 *
 * The key material itself is never rendered, logged, exported, or hashed into
 * any output. `keyId` is a non-secret HMAC-derived label (the key is 256-bit
 * random, so the id is not itself invertible).
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { closeSync, mkdirSync, openSync, readFileSync, writeSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
/** Environment variable carrying explicit key material (hex). */
export const PIN_KEY_ENV = "DEEPSWEEP_PIN_KEY";
/** Environment variable overriding the out-of-workspace state directory. */
export const PIN_STATE_DIR_ENV = "DEEPSWEEP_STATE_DIR";
/** File name of the generated key inside the state directory. */
export const PIN_KEY_FILE = "pin-key";
/** Minimum accepted key length in hex characters (32 bytes). */
export const PIN_KEY_MIN_HEX = 64;
/** Domain-separation labels — one namespace per pinned identity kind. */
export const PIN_DOMAIN = {
    mcpServer: "deepsweep/pin/mcpServer/v1",
    toolDescription: "deepsweep/pin/toolDescription/v1",
    agentId: "deepsweep/pin/agentId/v1",
    /** TEAM-ADR-048 — the workspace LABEL that replaces the published basename. */
    workspaceLabel: "deepsweep/pin/workspaceLabel/v1",
};
/** Raised only for an operator-supplied key that cannot be used as given. */
export class PinKeyError extends Error {
    constructor(message) {
        super(message);
        this.name = "PinKeyError";
    }
}
function parseKeyHex(text) {
    const trimmed = text.trim();
    if (trimmed.length < PIN_KEY_MIN_HEX)
        return undefined;
    if (trimmed.length % 2 !== 0)
        return undefined;
    if (!/^[0-9a-fA-F]+$/.test(trimmed))
        return undefined;
    return Buffer.from(trimmed, "hex");
}
function finalize(material, durable) {
    const keyId = createHmac("sha256", material)
        .update("deepsweep/pin-key-id/v1", "utf8")
        .digest("hex")
        .slice(0, 16);
    return { material, keyId, durable };
}
function stateDir() {
    const explicit = process.env[PIN_STATE_DIR_ENV];
    if (explicit !== undefined && explicit !== "")
        return explicit;
    return join(homedir(), ".deepsweep");
}
function readDurableKey(file) {
    let text;
    try {
        text = readFileSync(file, "utf8");
    }
    catch {
        return undefined;
    }
    const material = parseKeyHex(text);
    return material === undefined ? undefined : finalize(material, true);
}
function createDurableKey(dir, file) {
    try {
        mkdirSync(dir, { recursive: true, mode: 0o700 });
        const fresh = randomBytes(32);
        // O_CREAT|O_EXCL: a concurrent creator wins the race and we re-read below.
        const fd = openSync(file, "wx", 0o600);
        try {
            writeSync(fd, `${fresh.toString("hex")}\n`);
        }
        finally {
            closeSync(fd);
        }
        return finalize(fresh, true);
    }
    catch {
        return readDurableKey(file);
    }
}
function loadOrCreate(envValue, dir) {
    if (envValue !== "") {
        const material = parseKeyHex(envValue);
        if (material === undefined) {
            throw new PinKeyError(`${PIN_KEY_ENV} must be at least ${PIN_KEY_MIN_HEX} hexadecimal characters (32 bytes) — the value itself is never echoed; unset it to use the local key store`);
        }
        return finalize(material, true);
    }
    const file = join(dir, PIN_KEY_FILE);
    return readDurableKey(file) ?? createDurableKey(dir, file) ?? finalize(randomBytes(32), false);
}
/**
 * Cache keyed by the resolution INPUTS (env value + state dir) rather than a
 * bare module singleton, so a process that changes either — a test harness, a
 * host serving several workspaces — resolves afresh without a reset hook.
 */
const cache = new Map();
export function resolvePinKey() {
    const envValue = process.env[PIN_KEY_ENV] ?? "";
    const dir = stateDir();
    const cacheKey = `${envValue}\u0000${dir}`;
    const hit = cache.get(cacheKey);
    if (hit !== undefined)
        return hit;
    const resolved = loadOrCreate(envValue, dir);
    cache.set(cacheKey, resolved);
    return resolved;
}
/**
 * The ONE pinned-identity digest. Domain-separated so an mcpServer preimage
 * can never collide with a toolDescription or agentId preimage under the same
 * key. Output shape is unchanged from the SHA-256 it replaces (64 lowercase
 * hex), so every schema, regex and store validator still holds.
 */
export function pinHash(key, domain, canonicalText) {
    return createHmac("sha256", key.material)
        .update(`${domain}\u0000${canonicalText}`, "utf8")
        .digest("hex");
}
/** Constant-time keyId comparison (the id is public; the habit is free). */
export function sameKeyId(a, b) {
    const ab = Buffer.from(a, "utf8");
    const bb = Buffer.from(b, "utf8");
    return ab.length === bb.length && timingSafeEqual(ab, bb);
}
