/**
 * Gemini (Code Assist / CLI) detector.
 * Covers well-known locations (Gemini CLI + Code Assist docs, verified 2026-08-19):
 *  - .gemini/settings.json   (workspace settings incl. mcpServers map)
 *  - .gemini/styleguide.md   (Code Assist review style guide — presence)
 *  - ~/.gemini/settings.json (USER-SCOPE settings incl. mcpServers)
 * `GEMINI.md` is deliberately NOT claimed here — the antigravity detector
 * already reviews it (and `~/.gemini/config/mcp_config.json`); two detectors
 * emitting one source would double-count it in every total.
 */
import type { Detector } from "./detector.js";
export declare const geminiDetector: Detector;
