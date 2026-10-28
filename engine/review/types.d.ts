/**
 * Typed contracts for the Agent Environment Review engine.
 * Terminology per kb/glossary.md — "review", "capability", "boundary gap".
 */
import type { UnreadableReason } from "./read.js";
import type { GapRuleId } from "./gap-rules.js";
/**
 * CapabilityKind evolves ADDITIVELY under schemaVersion 1: new kinds may be
 * appended as detector coverage grows; existing kinds are never renamed,
 * removed, or re-meaning'd without a schemaVersion bump. (This additive
 * schema-evolution rule will be codified by ADR-003, currently in draft.)
 */
export type CapabilityKind = "shellExecution" | "repositoryWrite" | "mcpToolAccess" | "secretsExposure" | "autoApproval" | "agentInstructions" | "containerMount" | "externalDirectoryAccess" | "portExposure" | "privilegedContainer";
/**
 * "warning" was added (additively, per the ADR-003 evolution rule) for
 * baseline lifecycle findings such as baseline.regenerated (ADR-003/004).
 */
export type Severity = "critical" | "high" | "medium" | "warning" | "info";
/**
 * Epistemic class of a review output (2026-09-17 audit, C09) — additive
 * under schemaVersion 1 and TOTAL at assembly: the engine stamps every
 * emitted item, by construction rather than judgment. A capability is a
 * FACT (a configuration read: the file says this). A boundary gap is an
 * INFERENCE (reasoned from what was and was not found), and its
 * recommendation field is the RECOMMENDATION class. The review produces no
 * forecasts today; the vocabulary reserves the word so a future forecasting
 * surface cannot ship unlabeled.
 */
export type ClaimClass = "fact" | "inference" | "recommendation" | "forecast";
export interface Capability {
    /**
     * F6/ADR-020: stable content-hash id — "cap_" + sha256(canonicalize(
     * {kind, resource, source}))[0..16], with "#n" suffixes disambiguating
     * same-content duplicates in emission order. Stable across runs of the
     * same environment; additive under schemaVersion 1.
     */
    id?: string;
    kind: CapabilityKind;
    /** Human-readable statement of the power an agent holds. */
    summary: string;
    /** The resource the capability touches (server name, path, tool, branch…). */
    resource: string;
    /** Workspace-relative path of the config file that grants this capability. */
    source: string;
    /** Extra structured detail (never secret values — names/presence only). */
    detail?: Record<string, string | number | boolean>;
    /** C09: always "fact" — a capability is a configuration read. Stamped at assembly. */
    claimClass?: ClaimClass;
}
export interface BoundaryGap {
    severity: Severity;
    /** What protection is missing for a discovered capability. */
    summary: string;
    /** Recommended protection, phrased as an action. */
    recommendation: string;
    /**
     * DEPRECATED (ADR-020 deprecation window): indices into capabilities[].
     * Emitted alongside relatedCapabilityIds until consumers migrate; the
     * ids are the stable form (indices shift when detectors reorder).
     */
    relatedCapabilities: number[];
    /** F6/ADR-020: stable content-hash ids of the related capabilities. */
    relatedCapabilityIds?: string[];
    /**
     * TEAM-ADR-072: the rule that produced this gap, from the pinned table in
     * gap-rules.ts, and that rule's version. Metadata only: a gap is still one
     * aggregate inference per rule, and relatedCapabilityIds remain
     * associations, never proof that one capability is resolved on its own.
     */
    ruleId?: GapRuleId;
    ruleVersion?: number;
    /** C09: always "inference" — a gap is reasoned from presence and absence.
     * The `recommendation` field is the recommendation-class text. Stamped at
     * assembly. */
    claimClass?: ClaimClass;
}
/**
 * A protection: a configured control that CAN constrain a capability
 * (deny rule, pre-execution hook). Detected structurally — presence of the
 * config, never verified runtime efficacy (ADR-007 honest limit). A
 * protection earns posture credit ONLY when an independently-detected
 * capability of its `constrains` kind exists in the same run (ADR-007 F1,
 * capability-anchored crediting); protections themselves NEVER produce
 * capabilities, so self-anchoring is structurally impossible.
 * (Additive field under schemaVersion 1 — see CapabilityKind note above.)
 */
export interface Protection {
    /** The capability kind this protection constrains when anchored. */
    constrains: CapabilityKind;
    /** Human-readable statement of what the protection does. */
    summary: string;
    /** The rule/hook the protection is defined by (pattern, matcher…). */
    resource: string;
    /** Workspace-relative path of the config file that defines it. */
    source: string;
}
/**
 * A degraded finding: a reviewed source was present but malformed or
 * unrecognized, so capability extraction was skipped for it. The review
 * never crashes on bad input — it reports the gap in its own coverage.
 * (Additive field under schemaVersion 1 — see CapabilityKind note above.)
 */
export interface ReviewWarning {
    /** Workspace-relative path of the source that could not be understood. */
    source: string;
    summary: string;
    /**
     * TEAM-ADR-072: what kind of limitation this is, so a consumer never has to
     * parse `summary`. Optional additively; the summary wording is unchanged.
     */
    code?: ReviewWarningCode;
    /** For "unreadable" and "directory-unreadable": the reason class. */
    reason?: UnreadableReason;
}
export type ReviewWarningCode = "malformed" | "unreadable" | "directory-unreadable" | "pin-advisory";
/**
 * TEAM-ADR-072: how far one source was inspected, stamped by the detector at
 * the read itself. Only "parsed" and "blank" are positive evidence that a
 * structured reader understood the whole document; every other status is a
 * limitation, and "unknown" means the engine has no stamped observation.
 */
export type SourceInspectionStatus = "parsed" | "blank" | "parse_failed" | "unreadable" | "presence_only" | "pattern_match" | "listed" | "listed_partial" | "unknown";
export interface SourceInspection {
    /** The source label, exactly as reviewedSources/warnings spell it. */
    source: string;
    scope: "workspace" | "user";
    /** The strongest limitation recorded for this source in this review. */
    status: SourceInspectionStatus;
    /** For "unreadable": the reason class. */
    reason?: UnreadableReason;
    /** Detector ids that observed it, sorted. Empty for "unknown". */
    detectors: string[];
}
export interface ReviewReport {
    schemaVersion: 1;
    workspaceRoot: string;
    /** Config files that were found and reviewed (workspace-relative). */
    reviewedSources: string[];
    capabilities: Capability[];
    boundaryGaps: BoundaryGap[];
    /**
     * Detected protections (S2.2, ADR-007). Optional ADDITIVELY under
     * schemaVersion 1 (older snapshots lack it); the engine always sets it.
     */
    protections?: Protection[];
    /** Malformed/unrecognized sources, degraded to warnings (never a crash). */
    warnings: ReviewWarning[];
    /**
     * TEAM-ADR-072: one record per source observed, sorted by scope then
     * source. Optional additively; the engine always sets it.
     */
    sourceInspections?: SourceInspection[];
    /** Deterministic summary counts for CI thresholds. */
    totals: {
        capabilities: number;
        boundaryGaps: number;
        critical: number;
        high: number;
    };
}
