import { emptyResult } from "./detector.js";
import { reviewRulesDir, reviewUserMcpJson, reviewWorkspaceMcpJson, } from "./family.js";
const TOOL = "Kiro";
const STEERING_DIR = ".kiro/steering";
const MCP_CONFIG = ".kiro/settings/mcp.json";
const AGENTS_DIR = ".kiro/agents";
const HOOKS_DIR = ".kiro/hooks";
const SPECS_DIR = ".kiro/specs";
const USER_MCP_REL = ".kiro/settings/mcp.json";
const USER_MCP_LABEL = "~/.kiro/settings/mcp.json";
const USER_STEERING_REL = ".kiro/steering";
const USER_STEERING_LABEL = "~/.kiro/steering";
function detect(workspaceRoot, ctx) {
    const out = emptyResult();
    reviewRulesDir(workspaceRoot, STEERING_DIR, STEERING_DIR, out, {
        tool: TOOL,
        noun: ["steering file auto-loads", "steering files auto-load"],
        effect: "workspace instructions into agent sessions",
    });
    reviewWorkspaceMcpJson(workspaceRoot, MCP_CONFIG, out, TOOL);
    reviewRulesDir(workspaceRoot, AGENTS_DIR, AGENTS_DIR, out, {
        tool: TOOL,
        noun: ["custom agent definition shapes", "custom agent definitions shape"],
        effect: "what agents in this workspace may do",
    });
    reviewRulesDir(workspaceRoot, HOOKS_DIR, HOOKS_DIR, out, {
        tool: TOOL,
        noun: ["agent hook runs", "agent hooks run"],
        effect: "automatically on workspace events, without a human in the loop",
        kind: "autoApproval",
    });
    reviewRulesDir(workspaceRoot, SPECS_DIR, SPECS_DIR, out, {
        tool: TOOL,
        noun: ["spec folder drives", "spec folders drive"],
        effect: "multi-step agent task execution",
    });
    reviewUserMcpJson(ctx.userConfigRoot, USER_MCP_REL, USER_MCP_LABEL, out, TOOL);
    if (ctx.userConfigRoot !== undefined) {
        reviewRulesDir(ctx.userConfigRoot, USER_STEERING_REL, USER_STEERING_LABEL, out, {
            tool: TOOL,
            noun: ["user steering file applies", "user steering files apply"],
            effect: "instructions to agent sessions in EVERY workspace",
            scope: "user",
        });
    }
    return out;
}
export const kiroDetector = { id: "kiro", detect };
