/**
 * Kiro detector (AWS).
 * Covers well-known locations (kiro.dev/docs, verified 2026-08-19):
 *  - .kiro/steering/           (workspace steering files — NAMES only)
 *  - .kiro/settings/mcp.json   (workspace MCP config, standard mcpServers map)
 *  - .kiro/agents/             (custom agent definitions — NAMES only)
 *  - .kiro/hooks/              (agent hooks that run on workspace events — NAMES only)
 *  - .kiro/specs/              (spec-driven task folders — NAMES only)
 *  - ~/.kiro/settings/mcp.json (USER-SCOPE MCP config, merged under workspace)
 *  - ~/.kiro/steering/         (USER-SCOPE steering — NAMES only)
 * Fixed allowlist per ADR-002/ADR-014 — no globbing, names only for dirs.
 *
 * WHY: Kiro is in the measured editor list (2 of the 57 identities in the
 * 30-day PostHog window, `app/src/lib/constants.ts`) and the founder's
 * user-derived toolchain (2026-08-19). Until now a Kiro workspace reviewed as
 * "no agent configuration".
 */
import type { Detector } from "./detector.js";
export declare const kiroDetector: Detector;
