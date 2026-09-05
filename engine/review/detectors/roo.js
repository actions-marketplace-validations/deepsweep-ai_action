/**
 * Roo Code detector.
 * Covers well-known workspace locations (roocodeinc.github.io/Roo-Code, verified 2026-08-19):
 *  - .roo/rules/           (workspace-wide rules — NAMES only)
 *  - .roo/rules-<mode>/    (mode-specific rules — the `.roo/` entries whose NAME starts
 *                           with "rules-", listed, never globbed)
 *  - .roorules             (legacy single-file rules)
 *  - .roo/mcp.json         (project MCP config, standard mcpServers map)
 *  - .roomodes             (custom modes: tool groups + permissions)
 *  - .rooignore            (paths the agent may not touch — a PROTECTION)
 * Global MCP settings live in VS Code's globalStorage (outside the injected
 * user root) — not reviewed. AGENTS.md is left to the copilot detector.
 */
import { exists, probeDirNames } from "../read.js";
import { emptyResult } from "./detector.js";
import { reviewPresence, reviewRulesDir, reviewWorkspaceMcpJson, } from "./family.js";
const TOOL = "Roo Code";
const ROO_DIR = ".roo";
const RULES_DIR = ".roo/rules";
const RULES_FILE = ".roorules";
const MCP_CONFIG = ".roo/mcp.json";
const MODES_FILE = ".roomodes";
const IGNORE_FILE = ".rooignore";
function detect(workspaceRoot) {
    const out = emptyResult();
    reviewRulesDir(workspaceRoot, RULES_DIR, RULES_DIR, out, {
        tool: TOOL,
        noun: ["rule file auto-applies", "rule files auto-apply"],
        effect: "workspace instructions to agent sessions",
    });
    // Mode-specific rule dirs: list `.roo/` and take NAMES beginning with "rules-".
    const top = probeDirNames(workspaceRoot, ROO_DIR);
    if (top.status === "ok") {
        for (const name of top.names.filter((n) => n.startsWith("rules-")).sort()) {
            const rel = `${ROO_DIR}/${name}`;
            const mode = name.slice("rules-".length);
            reviewRulesDir(workspaceRoot, rel, rel, out, {
                tool: TOOL,
                noun: [
                    `"${mode}" mode rule file applies`,
                    `"${mode}" mode rule files apply`,
                ],
                effect: `instructions to ${TOOL} sessions in that mode`,
            });
        }
    }
    reviewPresence(workspaceRoot, RULES_FILE, out, {
        kind: "agentInstructions",
        summary: "Roo Code legacy rules file auto-applies workspace instructions to agent sessions",
    });
    reviewWorkspaceMcpJson(workspaceRoot, MCP_CONFIG, out, TOOL);
    reviewPresence(workspaceRoot, MODES_FILE, out, {
        kind: "agentInstructions",
        summary: "Roo Code custom modes define which tool groups and permissions each mode gets",
    });
    if (exists(workspaceRoot, IGNORE_FILE)) {
        out.reviewedSources.push(IGNORE_FILE);
        out.protections.push({
            constrains: "repositoryWrite",
            summary: ".rooignore keeps matching paths out of the agent's reach",
            resource: IGNORE_FILE,
            source: IGNORE_FILE,
        });
    }
    return out;
}
export const rooDetector = { id: "roo-code", detect };
