import { parseTolerantJson, safeRead } from "./read.js";
import { canonicalize, findDuplicateJsonKeys } from "./canonical.js";
import { asRecord, asString, redactUrl } from "./detectors/util.js";
import { PIN_DOMAIN, pinHash, resolvePinKey } from "./pinkey.js";
/** Fixed allowlist of MCP config sources pinned into the baseline (ADR-002). */
export const PIN_SOURCES = [
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".windsurf/mcp_config.json",
];
/** Fixed placeholder substituted for secret-bearing values before hashing. */
export const REDACTED_PLACEHOLDER = "<redacted>";
const ENDPOINT_SHAPED_KEY = /(^|_)(URL|URI|HOST|HOSTNAME|ENDPOINT|BASE|ADDR|ADDRESS|SERVER|TARGET)$/i;
/** Heuristic only — never inspects values beyond shape; never echoes them. */
function looksSecretShaped(arg) {
    if (/(secret|token|passw|api[-_]?key|bearer|credential)/i.test(arg))
        return true;
    if (/^(sk|pk|ghp|gho|ghu|xox[a-z])[-_]/i.test(arg))
        return true;
    return (arg.length >= 24 &&
        /^[A-Za-z0-9+/=_.-]+$/.test(arg) &&
        /[A-Za-z]/.test(arg) &&
        /\d/.test(arg));
}
/** URL-shaped by scheme, by userinfo, or by carrying a path-and-query. */
function carriesUrlShape(value) {
    return (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(value) ||
        /\/\/[^/@\s]*@/.test(value) ||
        /[^\s=]+\/[^\s=]*\?/.test(value));
}
/**
 * Redact ONE command-line argument before it reaches a hash preimage
 * (TEAM-ADR-047). The rule is deliberately value-shaped rather than
 * blanket, because args carry the drift signal that matters most — which
 * package a server runs, which transport, which flag:
 *
 *  - URL-shaped anywhere in the arg  → redactUrl (scheme+host+path survive;
 *    userinfo, query and fragment never enter the preimage);
 *  - `NAME=VALUE` / `--flag=VALUE`   → NAME kept verbatim, VALUE redacted
 *    when secret-shaped (a flag name is itself a strong drift signal);
 *  - a bare flag (`-y`, `--transport`) → kept verbatim, never a secret;
 *  - any other positional value      → redacted when secret-shaped, else
 *    kept (package specifiers, paths, transport words).
 *
 * RESIDUAL, stated rather than papered over: a positional secret with no
 * secret shape and no recognisable prefix (`hunter2`) is not detected by the
 * heuristic and stays in the preimage. That is why the digest is ALSO keyed —
 * the two defences are independent, and neither is claimed to be sufficient
 * alone.
 */
export function redactArg(arg) {
    if (typeof arg !== "string")
        return arg;
    if (carriesUrlShape(arg))
        return redactUrl(arg);
    const eq = arg.indexOf("=");
    if (eq > 0) {
        const name = arg.slice(0, eq);
        const value = arg.slice(eq + 1);
        return looksSecretShaped(value) ? `${name}=${REDACTED_PLACEHOLDER}` : arg;
    }
    if (arg.startsWith("-"))
        return arg;
    return looksSecretShaped(arg) ? REDACTED_PLACEHOLDER : arg;
}
/**
 * A hook COMMAND LINE, redacted token-wise for a rendered surface.
 *
 * WHY THIS EXISTS. `claude.ts` carried the comment "the command string is
 * config the operator wrote, not a secret (sanitized at every render choke
 * point anyway)". It was not sanitized anywhere. Measured 2026-08-23 with a
 * planted bearer token on a `.claude/settings.json` PreToolUse hook: the
 * command reached `review.md` once, `review.json` four times and
 * `studio.html` three times, verbatim. `review.md` is the artifact a founder
 * hand-delivers to a client during a paid engagement.
 *
 * The delivery runbook's answer was "hand-edit review.md and replace every
 * hook command line" — a manual step, on a deliverable, protecting someone
 * else's credential, performed under time pressure. This makes it automatic.
 *
 * The finding must stay ACTIONABLE. "A pre-tool hook pipes a bearer token to
 * an internal host" is the finding; the token itself is never the finding. So
 * this redacts token-wise via the already-audited `redactArg` rather than
 * masking the whole string — the reader still sees the binary, the flags and
 * the destination.
 *
 * Deliberately NOT a secret scanner. It reuses one predicate so there is one
 * place to improve, and it over-redacts rather than under-redacts: the literal
 * word "Bearer" is masked because `looksSecretShaped` matches it, which is
 * noise, not exposure.
 */
export function redactCommandLine(command) {
    return command
        .split(/(\s+)/)
        .map((tok) => {
        if (/^\s*$/.test(tok) || tok === "")
            return tok;
        // Strip surrounding quote characters before testing, then restore them:
        // a shell-quoted secret ("sk-live-…'") must not evade the predicate on
        // account of a trailing apostrophe.
        const lead = tok.match(/^["'`]+/)?.[0] ?? "";
        const trail = tok.match(/["'`]+$/)?.[0] ?? "";
        const core = tok.slice(lead.length, tok.length - trail.length);
        if (core === "")
            return tok;
        const red = redactArg(core);
        return typeof red === "string" ? `${lead}${red}${trail}` : tok;
    })
        .join("");
}
/**
 * Redaction-before-hashing for a pinned definition (the ONE seam; extended
 * by TEAM-ADR-047, never rewritten):
 *  - env.* / headers.* VALUES → fixed placeholder, key NAMES preserved
 *    (presence-and-key-names-only invariant, ADR-002/ADR-003) — unchanged;
 *  - url / serverUrl → scheme + host + path only, via the one audited
 *    redactUrl already applied to every report surface;
 *  - args → element-wise per redactArg above.
 * `command` is preserved verbatim: it is the strongest drift signal a stdio
 * server has, it is not a credential field, and its guessability is answered
 * by the key rather than by redaction.
 * Applied to tool records as well as server definitions — the per-tool
 * digests previously canonicalized with NO redaction pass at all.
 */
export function redactServerDefinition(def) {
    const out = { ...def };
    for (const field of ["env", "headers"]) {
        const map = asRecord(def[field]);
        if (!map)
            continue;
        const redacted = {};
        for (const key of Object.keys(map))
            redacted[key] = REDACTED_PLACEHOLDER;
        out[field] = redacted;
    }
    for (const field of ["url", "serverUrl"]) {
        const raw = asString(def[field]);
        if (raw === undefined)
            continue;
        out[field] = redactUrl(raw);
    }
    const args = def["args"];
    if (Array.isArray(args))
        out["args"] = args.map(redactArg);
    return out;
}
/** Redaction pass for any pinned JSON value (tool defs may not be records). */
function redactPinned(value) {
    const rec = asRecord(value);
    return rec === undefined ? value : redactServerDefinition(rec);
}
function definitionWarnings(name, source, def) {
    const out = [];
    for (const field of ["env", "headers"]) {
        const map = asRecord(def[field]);
        if (!map)
            continue;
        for (const key of Object.keys(map).sort()) {
            if (ENDPOINT_SHAPED_KEY.test(key)) {
                out.push({
                    source,
                    summary: `MCP server "${name}": its target appears to be configured via ${field} key "${key}" — that value is redacted before pinning, so changes to it will not raise drift. Review the value directly when re-pinning.`,
                });
            }
        }
    }
    const args = def["args"];
    if (Array.isArray(args)) {
        args.forEach((arg, i) => {
            if (typeof arg === "string" && looksSecretShaped(arg)) {
                out.push({
                    source,
                    summary: `MCP server "${name}": argument #${i + 1} matches secret-shaped patterns — its value is redacted before pinning, so changes to it will not raise drift; prefer env for secret values.`,
                });
            }
        });
    }
    // A userinfo/query-bearing URL is now stripped before it reaches the
    // preimage (TEAM-ADR-047), which means changes to those parts raise no
    // drift — the same trade env values already carry, and the user is told.
    // The value itself is never echoed.
    for (const field of ["url", "serverUrl"]) {
        const raw = asString(def[field]);
        if (raw !== undefined && urlCarriesSecrets(raw)) {
            out.push({
                source,
                summary: `MCP server "${name}": its ${field} embeds credentials or query parameters — userinfo and query are stripped before pinning, so changes to them will not raise drift (scheme, host and path still do); move secrets to env/headers.`,
            });
        }
    }
    return out;
}
/** Raised once per run when no durable key store was reachable. */
function ephemeralKeyWarning(source) {
    return {
        source,
        summary: "Pinned identities were computed under a temporary key because no durable key store was reachable — the baseline will be discarded and regenerated on the next run. Set DEEPSWEEP_PIN_KEY (or make the state directory writable) to keep pinned trust state across runs.",
    };
}
/** Shape check only — the URL value is never surfaced in any warning. */
function urlCarriesSecrets(raw) {
    try {
        const u = new URL(raw);
        return u.username !== "" || u.password !== "" || u.search !== "";
    }
    catch {
        return /\/\/[^/@]+@/.test(raw) || raw.includes("?");
    }
}
function cmpStr(a, b) {
    return a < b ? -1 : a > b ? 1 : 0;
}
/**
 * Extract pinned entities from the fixed MCP config allowlist.
 * Pure function of workspace file contents; deterministic ordering.
 */
export function extractPins(workspaceRoot, key = resolvePinKey()) {
    const entities = [];
    const warnings = [];
    const sources = [];
    for (const rel of PIN_SOURCES) {
        const text = safeRead(workspaceRoot, rel);
        if (text === undefined)
            continue;
        sources.push(rel);
        const json = parseTolerantJson(text);
        if (json === undefined)
            continue; // detectors already degrade this to a warning
        const dups = findDuplicateJsonKeys(text);
        if (dups.length > 0) {
            warnings.push({
                source: rel,
                summary: `Duplicate JSON ${dups.length === 1 ? "key" : "keys"} in ${rel} (${dups.join(", ")}) — parsing is deterministic last-wins, but duplicate definitions deserve review.`,
            });
        }
        const root = asRecord(json);
        const servers = asRecord(root?.["mcpServers"]) ?? asRecord(root?.["servers"]);
        if (!servers)
            continue;
        for (const name of Object.keys(servers).sort()) {
            const def = asRecord(servers[name]);
            if (!def)
                continue;
            entities.push({
                entityType: "mcpServer",
                logicalName: name,
                source: rel,
                contentHash: pinHash(key, PIN_DOMAIN.mcpServer, canonicalize(redactServerDefinition(def))),
            });
            warnings.push(...definitionWarnings(name, rel, def));
            // Tool descriptions declared inline in the config (hashed individually
            // in addition to the enclosing server definition, ADR-003).
            const tools = def["tools"];
            const toolsMap = asRecord(tools);
            if (toolsMap) {
                for (const toolName of Object.keys(toolsMap).sort()) {
                    const toolDef = toolsMap[toolName];
                    /* v8 ignore next -- reason: toolsMap values originate from JSON.parse (via parseTolerantJson), which can never produce an undefined property value for a key returned by Object.keys; the guard exists only to satisfy noUncheckedIndexedAccess narrowing. */
                    if (toolDef === undefined)
                        continue;
                    entities.push({
                        entityType: "toolDescription",
                        logicalName: `${name}/${toolName}`,
                        source: rel,
                        contentHash: pinHash(key, PIN_DOMAIN.toolDescription, canonicalize(redactPinned(toolDef))),
                    });
                }
            }
            else if (Array.isArray(tools)) {
                for (const t of tools) {
                    const toolRec = asRecord(t);
                    const toolName = asString(toolRec?.["name"]);
                    if (!toolRec || toolName === undefined)
                        continue;
                    entities.push({
                        entityType: "toolDescription",
                        logicalName: `${name}/${toolName}`,
                        source: rel,
                        contentHash: pinHash(key, PIN_DOMAIN.toolDescription, canonicalize(redactServerDefinition(toolRec))),
                    });
                }
            }
        }
    }
    entities.sort((a, b) => cmpStr(a.entityType, b.entityType) ||
        cmpStr(a.logicalName, b.logicalName) ||
        cmpStr(a.source, b.source));
    if (!key.durable && sources.length > 0)
        warnings.push(ephemeralKeyWarning(sources[0]));
    return { entities, warnings, sources, pinKeyId: key.keyId };
}
