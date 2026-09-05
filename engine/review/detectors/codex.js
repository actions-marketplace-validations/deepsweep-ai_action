/**
 * OpenAI Codex detector.
 * Covers well-known locations (Codex config reference, verified 2026-08-19):
 *  - .codex/config.toml    (project-scoped overrides — loaded only for trusted projects;
 *                           `[mcp_servers.<id>]` tables, approval_policy, sandbox_mode)
 *  - ~/.codex/config.toml  (USER-SCOPE config — same keys, applies in EVERY project)
 * `AGENTS.md` is deliberately NOT claimed here — the copilot detector reviews it.
 * No TOML parser ships in the engine (zero runtime deps, ADR-002): table
 * headers and two top-level string keys are scanned as NAMES/values only.
 */
import { probeRead, probeReadUser } from "../read.js";
import { emptyResult } from "./detector.js";
import { tomlMcpServerNames, tomlTopLevelString } from "./family.js";
import { isBlankDocument, unreadableWarning } from "./util.js";
const TOOL = "Codex";
const PROJECT_CONFIG = ".codex/config.toml";
const USER_CONFIG_REL = ".codex/config.toml";
const USER_CONFIG_LABEL = "~/.codex/config.toml";
function reviewToml(probe, source, out, scope) {
    if (probe.status === "unreadable") {
        out.warnings.push(unreadableWarning(source, probe.reason));
        return;
    }
    if (probe.status !== "ok")
        return;
    out.reviewedSources.push(source);
    if (isBlankDocument(probe.text))
        return;
    const reach = scope === "user" ? " in EVERY project" : "";
    for (const name of tomlMcpServerNames(probe.text)) {
        out.capabilities.push({
            kind: "mcpToolAccess",
            summary: `MCP server "${name}" is available to ${TOOL} agents${reach}`,
            resource: name,
            source,
            detail: { ...(scope === "user" ? { scope: "user" } : {}) },
        });
    }
    const approval = tomlTopLevelString(probe.text, "approval_policy");
    const sandbox = tomlTopLevelString(probe.text, "sandbox_mode");
    if (approval === "never" || sandbox === "danger-full-access") {
        const what = [
            approval === "never" ? 'approval_policy = "never"' : undefined,
            sandbox === "danger-full-access"
                ? 'sandbox_mode = "danger-full-access"'
                : undefined,
        ]
            .filter((s) => s !== undefined)
            .join(", ");
        out.capabilities.push({
            kind: "autoApproval",
            summary: `${TOOL} runs without approval gates (${what})${reach}`,
            resource: source,
            source,
            detail: {
                ...(scope === "user" ? { scope: "user" } : {}),
                ...(approval ? { approvalPolicy: approval } : {}),
                ...(sandbox ? { sandboxMode: sandbox } : {}),
            },
        });
    }
}
function detect(workspaceRoot, ctx) {
    const out = emptyResult();
    reviewToml(probeRead(workspaceRoot, PROJECT_CONFIG), PROJECT_CONFIG, out, "workspace");
    if (ctx.userConfigRoot !== undefined) {
        reviewToml(probeReadUser(ctx.userConfigRoot, USER_CONFIG_REL), USER_CONFIG_LABEL, out, "user");
    }
    return out;
}
export const codexDetector = { id: "openai-codex", detect };
