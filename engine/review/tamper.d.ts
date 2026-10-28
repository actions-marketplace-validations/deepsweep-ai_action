import type { BoundaryGap, ReviewReport, Severity } from "./types.js";
import type { LedgerVerdict } from "./ledger-sign.js";
import type { AnchorVerdict } from "./ledger.js";
import { type AgentLifecycleRecord, type TransitionDecision } from "../identity/lifecycle.js";
/** The event name. Frozen: additive, never renamed in place. */
export declare const TAMPER_EVENT = "ledger:tamper_detected";
export declare const TAMPER_EVENT_SCHEMA_VERSION = 1;
export type TamperDetector = "chain" | "signature" | "tree-head" | "anchor";
/** A normalized tamper finding, independent of which verifier produced it. */
export interface TamperAssessment {
    readonly tampered: boolean;
    readonly detector: TamperDetector;
    /** The verifier's own status word (e.g. "forged", "truncated", "replaced"). */
    readonly tamperClass: string;
    readonly entryCount: number;
    readonly signedEntries: number;
    /** Chain head HASH — a hash is metadata, the entries it covers are not. */
    readonly chainHead: string | null;
    readonly detail: string;
}
/**
 * Normalize a `verifyLedger` verdict. `unsigned` is NOT tamper — it is the
 * honest "nothing attests to this" state, and reporting it as an attack would
 * train operators to ignore the alarm.
 */
export declare function assessLedger(verdict: LedgerVerdict): TamperAssessment;
/** Normalize an ADR-018 anchor verdict. `verified` and `verified-appended`
 * are both honest growth; everything else is tamper. */
export declare function assessAnchor(verdict: AnchorVerdict, facts: {
    readonly entryCount: number;
    readonly signedEntries: number;
    readonly chainHead: string | null;
}): TamperAssessment;
/**
 * The telemetry payload. Every field is a count, a hash, a closed-vocabulary
 * class, or a derived (inert) agent id. There is deliberately NO field that
 * can carry a path, a payload value, or a filename.
 */
export interface TamperEvent {
    readonly event: typeof TAMPER_EVENT;
    readonly schemaVersion: typeof TAMPER_EVENT_SCHEMA_VERSION;
    readonly occurredAt: string;
    readonly detector: TamperDetector;
    readonly tamperClass: string;
    readonly entryCount: number;
    readonly signedEntries: number;
    /** SHA-256 hex of the current chain head, or null for an empty ledger. */
    readonly chainHeadHash: string | null;
    /** ADR-005 derived agent id (inert hex) or null when unattributed. */
    readonly attributedAgentId: string | null;
    readonly quarantined: boolean;
}
export declare function buildTamperEvent(a: TamperAssessment, attributedAgentId: string | null, quarantined: boolean, nowIso: string): TamperEvent;
export declare const TAMPER_GAP_SEVERITY: Severity;
/** The CRITICAL boundary gap. Copy is user-facing: it states the impact and
 * the action, and never names a mechanism the operator cannot act on. */
export declare function tamperBoundaryGap(a: TamperAssessment): BoundaryGap;
/** Fold a tamper gap into a report, keeping the report's own totals honest. */
export declare function mergeTamperGap(report: ReviewReport, gap: BoundaryGap): ReviewReport;
/**
 * A quarantine mark keyed on the DERIVATION INPUTS, not only the id — see the
 * module header on evasion.
 */
export interface QuarantineMark {
    readonly agentId: string;
    /** ADR-005 derivation input; null when the agent type could not be derived. */
    readonly agentType: string | null;
    /** The surface the identity was derived from (a config source label). */
    readonly source: string;
    readonly quarantinedAt: string;
    readonly reason: string;
}
export interface QuarantineCandidate {
    readonly agentId: string;
    readonly agentType: string | null;
    readonly source: string;
}
export interface EvasionVerdict {
    readonly evaded: boolean;
    /** The already-quarantined id this candidate is judged to be. */
    readonly matchedAgentId: string | null;
    readonly why: string;
}
/**
 * Does this registration re-enter under a new name? Fail-closed on a forged
 * candidate shape: an unparseable registration is treated as evasion, because
 * "I could not tell who this is" must never resolve to "let them in".
 */
export declare function checkQuarantineEvasion(candidate: QuarantineCandidate, marks: readonly QuarantineMark[]): EvasionVerdict;
export interface TamperResponse {
    readonly detected: boolean;
    readonly event: TamperEvent | null;
    readonly gap: BoundaryGap | null;
    /** The ADR-019 transition decision. null when there was no agent to act on. */
    readonly quarantine: TransitionDecision | null;
    readonly mark: QuarantineMark | null;
    /** who / what / why / policy / outcome (Principle 5). */
    readonly explanation: {
        readonly who: string;
        readonly what: string;
        readonly why: string;
        readonly policy: string;
        readonly outcome: "quarantined" | "quarantine-refused" | "no-attributed-agent" | "no-action";
    };
}
export declare const TAMPER_POLICY_ID = "ledger.tamper-response";
export interface TamperResponseInput {
    readonly assessment: TamperAssessment;
    /** The agent the tamper is attributed to, if any. */
    readonly agent?: AgentLifecycleRecord | undefined;
    /** ADR-005 derivation inputs for the mark. */
    readonly derivation?: {
        readonly agentType: string | null;
        readonly source: string;
    } | undefined;
    readonly nowIso: string;
}
/**
 * Detect -> emit -> raise -> quarantine, as one decision.
 *
 * A clean assessment produces NO event and NO gap: this path must not cry
 * wolf. A tamper with no attributable agent still emits and still raises —
 * the evidence failing is the finding, whether or not we can name a culprit.
 */
export declare function respondToTamper(input: TamperResponseInput): TamperResponse;
/**
 * The ONLY sanctioned quarantine exit. Requires explicit human approval AND
 * clears the derivation-keyed mark, so an approved return cannot leave a stale
 * mark that would re-quarantine the agent on its next registration. Refuses
 * without approval — `transition` enforces that, and this wrapper never
 * supplies the flag itself.
 */
export declare function reactivateQuarantinedAgent(agent: AgentLifecycleRecord, marks: readonly QuarantineMark[], opts: {
    readonly approved?: boolean;
    readonly actor?: string;
}): {
    readonly decision: TransitionDecision;
    readonly marks: readonly QuarantineMark[];
};
