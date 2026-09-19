import { type Hex } from "./merkle.js";
export declare const EVIDENCE_SCHEMA_VERSION = 2;
/**
 * The review a `review-run` record attests (TEAM-ADR-054). Counts plus the
 * baseline hash — the discriminator that makes an empty folder and a real
 * repository export DIFFERENT bytes. Before this block existed, every
 * discriminating slot of a review-run record was a constant, and a person
 * with `mkdir` could produce a byte-identical, timestampable "evidence"
 * record for a codebase they had never seen.
 */
export interface EvidenceReviewFacts {
    readonly baselineSha256: Hex;
    readonly findingCount: number;
    readonly criticalCount: number;
    readonly highCount: number;
    readonly capabilityCount: number;
    readonly boundaryGapCount: number;
}
/** Outcomes an evidence record may attest (ADR-009 vocabulary). */
export type EvidenceOutcome = "allow" | "deny" | "require-approval" | "observe";
/** Why the outcome happened, as a closed vocabulary (never free text). */
export type EvidenceReason = "rule-matched" | "default-effect" | "policy-refused" | "review-run"
/** A non-decision, non-review ledger kind (gateway calls, approvals,
 * tamper events). v1 exported ALL of these as "review-run" with constant
 * tuple slots — misattribution the v2 vocabulary ends (TEAM-ADR-054). */
 | "ledger-event";
export interface EvidenceRecordInput {
    readonly occurredAt: string;
    /** Workspace BASENAME only (ADR-003) — never an absolute path. */
    readonly workspace: string;
    readonly outcome: EvidenceOutcome;
    readonly reason: EvidenceReason;
    /** Raw decision tuple — hashed here, never stored or emitted. */
    readonly principal: string | null;
    readonly action: string;
    readonly resource: string;
    /** Deciding rule name (operator-authored) or null for a default effect. */
    readonly ruleName: string | null;
    readonly policyMode: string;
    readonly policyLayers: readonly string[];
    readonly matchedRuleCount: number;
    /** Required for reason "review-run", must be null otherwise — enforced by
     * the constructor because JSON Schema cannot express the coupling. */
    readonly review: EvidenceReviewFacts | null;
}
export interface EvidenceRecord {
    readonly schemaVersion: typeof EVIDENCE_SCHEMA_VERSION;
    readonly occurredAt: string;
    readonly workspace: string;
    readonly outcome: EvidenceOutcome;
    readonly reason: EvidenceReason;
    /** SHA-256 of the principal, or of "" when unattributed. */
    readonly principalHash: Hex;
    readonly actionHash: Hex;
    readonly resourceHash: Hex;
    readonly ruleName: string | null;
    readonly policyMode: string;
    readonly policyLayers: readonly string[];
    readonly matchedRuleCount: number;
    readonly review: EvidenceReviewFacts | null;
}
/** Build the record — the ONLY place raw tuple values are touched.
 *
 * REFUSES the two shapes that lie (TEAM-ADR-054, a data-shape invariant
 * rather than a convention): a review-run record WITHOUT review facts is the
 * forgery shape the tripwire pinned, and a policy-decision record WITH them
 * is fabrication. Both throw; neither is repairable by a default.
 */
export declare function buildEvidenceRecord(input: EvidenceRecordInput): EvidenceRecord;
/** RFC 8785 canonical serialization of a record (the bytes that get hashed). */
export declare function serializeEvidenceRecord(record: EvidenceRecord): string;
/** The record's Merkle leaf hash: RFC 6962 leaf hashing over JCS bytes. */
export declare function evidenceLeafHash(record: EvidenceRecord): Hex;
