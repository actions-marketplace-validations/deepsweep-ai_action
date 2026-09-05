/**
 * Aider detector.
 * Covers well-known workspace locations (aider.chat/docs/config, verified 2026-08-19):
 *  - .aider.conf.yml            (config at the git root; `yes-always: true` disables confirmations)
 *  - .aider.model.settings.yml  (model settings — presence)
 *  - .aider.model.metadata.json (model metadata — presence)
 *  - .aiderignore               (paths aider may not edit — a PROTECTION)
 *  - .aider.chat.history.md / .aider.input.history / .aider.llm.history
 *                               (conversation history PERSISTED IN THE REPO TREE — PRESENCE ONLY,
 *                                never read: it may hold pasted secrets, which is the finding)
 * The home-directory `.aider.conf.yml` is outside the injected user root's
 * allowlist semantics (it is the home dir itself) and is not reviewed.
 */
import { exists, probeRead } from "../read.js";
import { emptyResult } from "./detector.js";
import { reviewPresence, yamlTopLevelTrue } from "./family.js";
import { isBlankDocument, unreadableWarning } from "./util.js";
const CONF = ".aider.conf.yml";
const MODEL_SETTINGS = ".aider.model.settings.yml";
const MODEL_METADATA = ".aider.model.metadata.json";
const IGNORE_FILE = ".aiderignore";
const HISTORY_FILES = [
    ".aider.chat.history.md",
    ".aider.input.history",
    ".aider.llm.history",
];
function detect(workspaceRoot) {
    const out = emptyResult();
    const conf = probeRead(workspaceRoot, CONF);
    if (conf.status === "unreadable") {
        out.warnings.push(unreadableWarning(CONF, conf.reason));
    }
    else if (conf.status === "ok") {
        out.reviewedSources.push(CONF);
        out.capabilities.push({
            kind: "agentInstructions",
            summary: "Aider config sets the model, edit format and conventions for agent sessions",
            resource: CONF,
            source: CONF,
        });
        if (!isBlankDocument(conf.text) &&
            (yamlTopLevelTrue(conf.text, "yes-always") ||
                yamlTopLevelTrue(conf.text, "yes"))) {
            out.capabilities.push({
                kind: "autoApproval",
                summary: "Aider answers every confirmation with yes (yes-always) — edits and commands run without a prompt",
                resource: "yes-always",
                source: CONF,
            });
        }
        if (!isBlankDocument(conf.text) &&
            yamlTopLevelTrue(conf.text, "auto-commits")) {
            out.capabilities.push({
                kind: "repositoryWrite",
                summary: "Aider auto-commits every edit to the repository",
                resource: "auto-commits",
                source: CONF,
            });
        }
    }
    for (const rel of [MODEL_SETTINGS, MODEL_METADATA]) {
        reviewPresence(workspaceRoot, rel, out, {
            kind: "agentInstructions",
            summary: `Aider model configuration (${rel}) shapes agent sessions in this repository`,
        });
    }
    if (exists(workspaceRoot, IGNORE_FILE)) {
        out.reviewedSources.push(IGNORE_FILE);
        out.protections.push({
            constrains: "repositoryWrite",
            summary: ".aiderignore keeps matching paths out of the agent's edit set",
            resource: IGNORE_FILE,
            source: IGNORE_FILE,
        });
    }
    for (const rel of HISTORY_FILES) {
        // PRESENCE ONLY — the file is the one thing a reviewer must not read.
        if (exists(workspaceRoot, rel)) {
            out.capabilities.push({
                kind: "secretsExposure",
                summary: `Aider conversation history (${rel}) is persisted in the repository tree — anything pasted into a session is at rest here`,
                resource: rel,
                source: rel,
                detail: { presenceOnly: true },
            });
        }
    }
    return out;
}
export const aiderDetector = { id: "aider", detect };
