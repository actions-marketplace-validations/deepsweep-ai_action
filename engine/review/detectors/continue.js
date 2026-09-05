/**
 * Continue detector.
 * Covers well-known locations (docs.continue.dev, verified 2026-08-19):
 *  - .continue/config.yaml | .continue/config.json  (workspace config — presence; YAML is
 *                                                    not parsed: zero-deps engine, names only)
 *  - .continue/rules/        (workspace rules — NAMES only)
 *  - .continue/mcpServers/   (one YAML file per MCP server — file NAMES are the server names)
 *  - .continuerc.json        (legacy workspace config — presence)
 *  - ~/.continue/config.yaml (USER-SCOPE config — presence)
 * Note: Continue was reported discontinued in June 2026 (acquired by Cursor); the
 * footprint still exists in repositories and is in the user-derived toolchain.
 */
import { probeReadUser } from "../read.js";
import { emptyResult } from "./detector.js";
import { reviewPresence, reviewRulesDir } from "./family.js";
import { unreadableWarning } from "./util.js";
const TOOL = "Continue";
const CONFIG_YAML = ".continue/config.yaml";
const CONFIG_JSON = ".continue/config.json";
const RULES_DIR = ".continue/rules";
const MCP_DIR = ".continue/mcpServers";
const LEGACY_RC = ".continuerc.json";
const USER_CONFIG_REL = ".continue/config.yaml";
const USER_CONFIG_LABEL = "~/.continue/config.yaml";
function detect(workspaceRoot, ctx) {
    const out = emptyResult();
    for (const rel of [CONFIG_YAML, CONFIG_JSON, LEGACY_RC]) {
        reviewPresence(workspaceRoot, rel, out, {
            kind: "agentInstructions",
            summary: `Continue workspace config (${rel}) sets models, rules and tools for agent sessions`,
        });
    }
    reviewRulesDir(workspaceRoot, RULES_DIR, RULES_DIR, out, {
        tool: TOOL,
        noun: ["rule file auto-applies", "rule files auto-apply"],
        effect: "workspace instructions to agent sessions",
    });
    reviewRulesDir(workspaceRoot, MCP_DIR, MCP_DIR, out, {
        tool: TOOL,
        noun: [
            "MCP server definition is available to",
            "MCP server definitions are available to",
        ],
        effect: `${TOOL} agents in this workspace`,
        kind: "mcpToolAccess",
    });
    if (ctx.userConfigRoot !== undefined) {
        const probe = probeReadUser(ctx.userConfigRoot, USER_CONFIG_REL);
        if (probe.status === "unreadable") {
            out.warnings.push(unreadableWarning(USER_CONFIG_LABEL, probe.reason));
        }
        else if (probe.status === "ok") {
            out.reviewedSources.push(USER_CONFIG_LABEL);
            out.capabilities.push({
                kind: "agentInstructions",
                summary: "Continue user config sets models, rules and tools for agent sessions in EVERY workspace",
                resource: USER_CONFIG_LABEL,
                source: USER_CONFIG_LABEL,
                detail: { scope: "user" },
            });
        }
    }
    return out;
}
export const continueDetector = { id: "continue", detect };
