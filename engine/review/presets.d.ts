/**
 * Autonomy presets (2026-09-17 audit, C20) — the five-word vocabulary the
 * architecture sheet promised, as validated one-file policies rather than a
 * new mechanism. Each preset is a complete PolicySet an operator can drop in
 * as `.deepsweep/policy.json` (or a surface can offer by name), and each maps
 * HONESTLY onto the existing effect ladder:
 *
 *   automatic            observe mode — record everything, forward everything.
 *                        The word "automatic" means the agent proceeds; it
 *                        never means unrecorded.
 *   prepare-only         enforce + deny default — the agent may propose (the
 *                        denial and its reason land on the ledger), a human
 *                        performs the action outside the agent's hands.
 *   approval-required    enforce + require-approval default — every call
 *                        holds for one named human (the guarded-routing
 *                        starter, DSK C01).
 *   dual-authorization   approval-required, with a catch-all rule demanding
 *                        TWO distinct named approvers (C03 quorum).
 *   human-only           enforce + deny default, and even tools/list-level
 *                        traffic earns nothing: no resumable approval path is
 *                        offered. The agent observes; humans act.
 *
 * prepare-only and human-only share an effect today (deny-all) and differ in
 * intent; both ship so an operator's policy file SAYS which posture they
 * chose. The presets are data, not code — TEAM-ADR-057's law applies.
 */
import type { PolicySet } from "./policy.js";
export type AutonomyPreset = "automatic" | "prepare-only" | "approval-required" | "dual-authorization" | "human-only";
export declare const AUTONOMY_PRESETS: Readonly<Record<AutonomyPreset, PolicySet>>;
