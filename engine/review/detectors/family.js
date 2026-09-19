/**
 * Shared building blocks for the tool-family detectors added on 2026-08-19
 * (Kiro, Cline, Roo Code, Continue, Gemini, Amazon Q Developer, Codex, Aider —
 * the complete list of tools our users are measured in, per the founder).
 *
 * Every existing family (antigravity/trae/windsurf/…) re-implements the same
 * three reads: a JSON `mcpServers` document (workspace and user scope), a
 * rules DIRECTORY read as names only, and an instruction FILE read for
 * presence. Four of six of those copies forgot the ADR-013 credential detail
 * (TEAM-ADR-035). So the eight new families share ONE implementation of each
 * read here — same contained reader (ADR-002/ADR-014), same degrade-to-warning
 * rules, same names-only discipline — and a family added tomorrow cannot
 * quietly omit a step. Existing detectors are deliberately left as they are.
 */
import { exists, parseTolerantJson, probeDirNames, probeRead, probeReadUser, } from "../read.js";
import { isBlankDocument, malformedWarning, mcpCredentialDetail, mcpServersFrom, nameList, unreadableWarning, visibleNames, } from "./util.js";
import { countNoun } from "../text.js";
/** Emit mcpToolAccess (+ shellExecution for local launchers) for a standard mcpServers map. */
export function emitMcpServers(json, source, out, opts) {
    for (const server of mcpServersFrom(json)) {
        const transport = server.url ? "remote" : "local";
        const where = opts.scope === "user" ? `${transport}, user-scope config` : transport;
        const reach = opts.scope === "user" ? (opts.reach ?? " in EVERY workspace") : "";
        out.capabilities.push({
            kind: "mcpToolAccess",
            summary: `MCP server "${server.name}" (${where}) is available to ${opts.tool} agents${reach}`,
            resource: server.name,
            source,
            detail: {
                transport,
                ...(opts.scope === "user" ? { scope: "user" } : {}),
                ...(server.command ? { command: server.command } : {}),
                ...(server.url ? { url: server.url } : {}),
                ...mcpCredentialDetail(server),
            },
        });
        if (server.command) {
            out.capabilities.push({
                kind: "shellExecution",
                summary: `MCP server "${server.name}" launches a local process ("${server.command}")`,
                resource: server.command,
                source,
            });
        }
    }
}
/**
 * Review one JSON document that may carry an mcpServers map. `probe` is the
 * already-executed contained read (workspace or user root); `source` is the
 * label recorded in reviewedSources/warnings ("~/"-prefixed for user scope).
 * Returns the parsed document (or undefined) so a family can read extra keys.
 */
export function reviewJsonMcpSource(probe, source, out, opts) {
    if (probe.status === "unreadable") {
        out.warnings.push(unreadableWarning(source, probe.reason));
        return undefined;
    }
    if (probe.status !== "ok")
        return undefined;
    out.reviewedSources.push(source);
    const json = parseTolerantJson(probe.text);
    if (json === undefined) {
        // An empty file is nothing configured, not malformed.
        if (!isBlankDocument(probe.text))
            out.warnings.push(malformedWarning(source));
        return undefined;
    }
    emitMcpServers(json, source, out, opts);
    return json;
}
export function reviewWorkspaceMcpJson(workspaceRoot, rel, out, tool) {
    return reviewJsonMcpSource(probeRead(workspaceRoot, rel), rel, out, {
        tool,
        scope: "workspace",
    });
}
export function reviewUserMcpJson(userConfigRoot, rel, label, out, tool, reach) {
    if (userConfigRoot === undefined)
        return undefined;
    return reviewJsonMcpSource(probeReadUser(userConfigRoot, rel), label, out, {
        tool,
        scope: "user",
        ...(reach !== undefined ? { reach } : {}),
    });
}
/** Names-only review of a rules/config directory → one agentInstructions capability. */
export function reviewRulesDir(root, rel, label, out, opts) {
    const probe = probeDirNames(root, rel);
    if (probe.status === "unreadable") {
        if (!out.warnings.some((w) => w.source === label)) {
            out.warnings.push(unreadableWarning(label, probe.reason));
        }
        return [];
    }
    if (probe.status !== "ok")
        return [];
    const names = visibleNames(probe.names);
    if (names.length === 0)
        return [];
    out.reviewedSources.push(label);
    out.capabilities.push({
        kind: opts.kind ?? "agentInstructions",
        summary: `${countNoun(names.length, `${opts.tool} ${opts.noun[0]}`, `${opts.tool} ${opts.noun[1]}`)} ${opts.effect}`,
        resource: label,
        source: label,
        detail: {
            ...(opts.scope === "user" ? { scope: "user" } : {}),
            fileCount: names.length,
            fileNames: nameList(names),
        },
    });
    return names;
}
/** Presence-only review of an instruction/config FILE → one capability (content never summarised). */
export function reviewPresence(workspaceRoot, rel, out, capability) {
    if (!exists(workspaceRoot, rel))
        return false;
    out.reviewedSources.push(rel);
    out.capabilities.push({
        ...capability,
        resource: capability.resource ?? rel,
        source: rel,
    });
    return true;
}
/**
 * Minimal TOML table-header scan — NAMES only. Returns the `<id>` of every
 * `[mcp_servers.<id>]` table (Codex). No TOML parser ships in the engine
 * (zero runtime deps, ADR-002); names are all the review needs (ADR-002).
 */
export function tomlMcpServerNames(text) {
    const names = new Set();
    for (const line of text.split(/\r?\n/)) {
        const m = /^\s*\[\s*mcp_servers\.(.+?)\s*\]\s*(#.*)?$/.exec(line);
        if (!m)
            continue;
        const rest = m[1] ?? "";
        // First key segment: a quoted key runs to its closing quote (may contain
        // spaces/dots); a bare key runs to the next dot.
        let head;
        if (rest.startsWith('"')) {
            const close = rest.indexOf('"', 1);
            head = close > 1 ? rest.slice(1, close) : "";
        }
        else {
            head = rest.split(".")[0] ?? "";
        }
        if (head)
            names.add(head);
    }
    return [...names].sort();
}
/** Top-level `key = "value"` (string) from a TOML document, before the first table header. */
export function tomlTopLevelString(text, key) {
    for (const line of text.split(/\r?\n/)) {
        if (/^\s*\[/.test(line))
            break;
        const m = new RegExp(`^\\s*${key}\\s*=\\s*"([^"]*)"`).exec(line);
        if (m)
            return m[1];
    }
    return undefined;
}
/** `key: true` at the top level of a simple YAML document (aider's flat config). */
export function yamlTopLevelTrue(text, key) {
    const re = new RegExp(`^${key}\\s*:\\s*(true|yes)\\s*(#.*)?$`, "im");
    return re.test(text);
}
