import { emptyResult } from "./detector.js";
import { reviewPresence, reviewUserMcpJson, reviewWorkspaceMcpJson, } from "./family.js";
const TOOL = "Gemini";
const SETTINGS = ".gemini/settings.json";
const STYLEGUIDE = ".gemini/styleguide.md";
const USER_SETTINGS_REL = ".gemini/settings.json";
const USER_SETTINGS_LABEL = "~/.gemini/settings.json";
function detect(workspaceRoot, ctx) {
    const out = emptyResult();
    reviewWorkspaceMcpJson(workspaceRoot, SETTINGS, out, TOOL);
    reviewPresence(workspaceRoot, STYLEGUIDE, out, {
        kind: "agentInstructions",
        summary: "Gemini Code Assist style guide steers automated code review in this repository",
    });
    reviewUserMcpJson(ctx.userConfigRoot, USER_SETTINGS_REL, USER_SETTINGS_LABEL, out, TOOL, " in EVERY workspace, and to the Gemini CLI");
    return out;
}
export const geminiDetector = { id: "gemini", detect };
