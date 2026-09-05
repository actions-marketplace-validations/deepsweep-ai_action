/**
 * Evidence summary over a compiled packet (TEAM-ADR-041) — the numbers an
 * underwriter or incident reader wants at a glance, DERIVED from the packet's
 * own timeline so they can be recomputed by anyone holding the packet:
 * decisions by outcome, by taxonomy class and by threat pattern; which packs
 * (version + signing key) governed; classification confidence; approvals;
 * tool-pin drift. Pure over the packet body; changes no contract (the packet
 * schema is frozen — this is a reader, not a writer).
 *
 * Wording discipline: this is evidence supporting the customer's own
 * compliance process. It counts what the ledger recorded; it concludes
 * nothing.
 */
import type { CompliancePacketBody, PacketIntegrity, PacketWindow } from "../compliance/packet.js";
export interface ThreatRefCounts {
    readonly allow: number;
    readonly deny: number;
    readonly "require-approval": number;
    readonly observe: number;
}
export interface ExecEvidenceSummary {
    readonly window: PacketWindow;
    /** Distinct `<id>@<version>#<bundleVersion>:<keyId>` labels seen on decisions, sorted. */
    readonly packs: readonly string[];
    readonly decisions: number;
    readonly decisionsByOutcome: Record<string, number>;
    /** Taxonomy class → decisions that carried it (a decision may carry several classes). */
    readonly decisionsByClass: Record<string, number>;
    /** Threat pattern (from the deciding rule's `P#.` prefix) → outcomes. */
    readonly decisionsByThreatRef: Record<string, ThreatRefCounts>;
    /** Decisions decided by the pack default (no rule matched — typically an unclassified tool). */
    readonly decisionsByDefault: number;
    readonly classificationConfidence: Record<string, number>;
    readonly unclassifiedDecisions: number;
    readonly gatewayActions: Record<string, number>;
    readonly approvalsGranted: number;
    readonly approvalsConsumed: number;
    readonly toolPinned: number;
    readonly toolDrift: number;
    readonly toolRepinned: number;
    readonly integrity: PacketIntegrity;
}
/** Derive the summary. Total over any packet body; unknown kinds are simply not counted. */
export declare function summarizeExecEvidence(packet: CompliancePacketBody): ExecEvidenceSummary;
