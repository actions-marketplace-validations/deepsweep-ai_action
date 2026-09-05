/**
 * Amazon Q Developer detector.
 * Covers well-known locations (docs.aws.amazon.com/amazonq, verified 2026-08-19):
 *  - .amazonq/rules/          (project rules, Markdown — NAMES only)
 *  - .amazonq/default.json    (local agent config: mcpServers map, tools, allowedTools)
 *  - .amazonq/mcp.json        (legacy local MCP config, standard mcpServers map)
 *  - ~/.aws/amazonq/default.json  (USER-SCOPE agent config)
 *  - ~/.aws/amazonq/mcp.json      (USER-SCOPE legacy MCP config — also read by the Q CLI)
 * Fixed allowlist per ADR-002/ADR-014 — no globbing, names only for dirs.
 */
import type { Detector } from "./detector.js";
export declare const amazonQDetector: Detector;
