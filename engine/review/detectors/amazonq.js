import { emptyResult } from "./detector.js";
import { reviewRulesDir, reviewUserMcpJson, reviewWorkspaceMcpJson, } from "./family.js";
import { asRecord } from "./util.js";
const TOOL = "Amazon Q Developer";
const RULES_DIR = ".amazonq/rules";
const AGENT_CONFIG = ".amazonq/default.json";
const MCP_LEGACY = ".amazonq/mcp.json";
const USER_AGENT_REL = ".aws/amazonq/default.json";
const USER_AGENT_LABEL = "~/.aws/amazonq/default.json";
const USER_MCP_REL = ".aws/amazonq/mcp.json";
const USER_MCP_LABEL = "~/.aws/amazonq/mcp.json";
/** `allowedTools` in an agent config pre-approves tools — that is autoApproval. */
function emitAllowedTools(json, source, out, scope) {
    const allowed = asRecord(json)?.["allowedTools"];
    if (!Array.isArray(allowed) || allowed.length === 0)
        return;
    const names = allowed.map(String).sort();
    out.capabilities.push({
        kind: "autoApproval",
        summary: `${names.length} tool${names.length === 1 ? "" : "s"} pre-approved in ${TOOL} agent config — run without a prompt${scope === "user" ? " in EVERY workspace" : ""}`,
        resource: source,
        source,
        detail: {
            ...(scope === "user" ? { scope: "user" } : {}),
            toolCount: names.length,
            tools: names.slice(0, 10).join(", "),
        },
    });
}
function detect(workspaceRoot, ctx) {
    const out = emptyResult();
    reviewRulesDir(workspaceRoot, RULES_DIR, RULES_DIR, out, {
        tool: TOOL,
        noun: ["project rule auto-applies", "project rules auto-apply"],
        effect: "coding instructions to agent sessions",
    });
    const agent = reviewWorkspaceMcpJson(workspaceRoot, AGENT_CONFIG, out, TOOL);
    if (agent !== undefined)
        emitAllowedTools(agent, AGENT_CONFIG, out, "workspace");
    reviewWorkspaceMcpJson(workspaceRoot, MCP_LEGACY, out, TOOL);
    const userAgent = reviewUserMcpJson(ctx.userConfigRoot, USER_AGENT_REL, USER_AGENT_LABEL, out, TOOL);
    if (userAgent !== undefined)
        emitAllowedTools(userAgent, USER_AGENT_LABEL, out, "user");
    reviewUserMcpJson(ctx.userConfigRoot, USER_MCP_REL, USER_MCP_LABEL, out, TOOL, " in EVERY workspace, and to the Q CLI");
    return out;
}
export const amazonQDetector = { id: "amazon-q-developer", detect };
