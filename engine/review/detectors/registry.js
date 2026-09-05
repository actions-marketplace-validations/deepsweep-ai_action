import { mcpDetector } from "./mcp.js";
import { claudeDetector } from "./claude.js";
import { cursorDetector } from "./cursor.js";
import { devcontainerDetector } from "./devcontainer.js";
import { copilotDetector } from "./copilot.js";
import { windsurfDetector } from "./windsurf.js";
import { antigravityDetector } from "./antigravity.js";
import { traeDetector } from "./trae.js";
import { kiroDetector } from "./kiro.js";
import { clineDetector } from "./cline.js";
import { rooDetector } from "./roo.js";
import { continueDetector } from "./continue.js";
import { geminiDetector } from "./gemini.js";
import { amazonQDetector } from "./amazonq.js";
import { codexDetector } from "./codex.js";
import { aiderDetector } from "./aider.js";
import { envDetector, gitDetector } from "./workspace.js";
export const DETECTORS = Object.freeze([
    mcpDetector,
    claudeDetector,
    cursorDetector,
    devcontainerDetector,
    copilotDetector,
    windsurfDetector,
    // Appended, never inserted: the array order is the report's emission order,
    // so placing a new family mid-list would reshuffle every golden vector for
    // reasons unrelated to the new coverage.
    antigravityDetector,
    traeDetector,
    // 2026-08-19 — the rest of the user-derived toolchain (founder list). Appended
    // after trae, before the workspace-generic git/env pair, in the founder's order.
    kiroDetector,
    clineDetector,
    rooDetector,
    continueDetector,
    geminiDetector,
    amazonQDetector,
    codexDetector,
    aiderDetector,
    gitDetector,
    envDetector,
]);
