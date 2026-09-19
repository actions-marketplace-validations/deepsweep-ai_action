/**
 * Cline detector.
 * Covers well-known workspace locations (docs.cline.bot, verified 2026-08-19):
 *  - .clinerules/   (workspace rules DIRECTORY — all .md/.txt inside; NAMES only)
 *  - .clinerules    (legacy single rules FILE)
 *  - .clineignore   (paths Cline may not read — a PROTECTION)
 * Global rules live under the user's Documents folder (platform-specific) and
 * MCP settings inside VS Code's globalStorage — both outside the injected user
 * config root, so they are deliberately NOT reviewed (ADR-014 reads only the
 * injected root). AGENTS.md is left to the copilot detector (no double count).
 */
import { exists, probeRead } from "../read.js";
import { emptyResult } from "./detector.js";
import { reviewRulesDir } from "./family.js";
import { unreadableWarning } from "./util.js";
const TOOL = "Cline";
const RULES_PATH = ".clinerules";
const IGNORE_FILE = ".clineignore";
function detect(workspaceRoot) {
    const out = emptyResult();
    // `.clinerules` is EITHER a file (legacy) or a directory (current). A file
    // read tells the two apart: ok → file form; "not-a-file" → directory form.
    const asFile = probeRead(workspaceRoot, RULES_PATH);
    if (asFile.status === "ok") {
        out.reviewedSources.push(RULES_PATH);
        out.capabilities.push({
            kind: "agentInstructions",
            summary: "Cline rules file auto-applies workspace instructions to agent sessions",
            resource: RULES_PATH,
            source: RULES_PATH,
        });
    }
    else if (asFile.status === "unreadable" && asFile.reason === "not-a-file") {
        reviewRulesDir(workspaceRoot, RULES_PATH, RULES_PATH, out, {
            tool: TOOL,
            noun: ["rule file auto-applies", "rule files auto-apply"],
            effect: "workspace instructions to agent sessions",
        });
    }
    else if (asFile.status === "unreadable") {
        out.warnings.push(unreadableWarning(RULES_PATH, asFile.reason));
    }
    if (exists(workspaceRoot, IGNORE_FILE)) {
        out.reviewedSources.push(IGNORE_FILE);
        out.protections.push({
            constrains: "repositoryWrite",
            summary: ".clineignore keeps matching paths out of the agent's reach",
            resource: IGNORE_FILE,
            source: IGNORE_FILE,
        });
    }
    return out;
}
export const clineDetector = { id: "cline", detect };
