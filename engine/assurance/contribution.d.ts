/** The one schema version this encoder can produce. */
export declare const CONTRIBUTION_SCHEMA_VERSION: 1;
/** Length of the fixed-width wire form, in bytes. */
export declare const CONTRIBUTION_BYTES: 11;
/**
 * Upper bound of `epoch`: a caller-supplied u16, non-normative. What a window
 * is (its length and origin) is not decided here; it must be coarse and the
 * same for every contributor, and the producer decision fixes it. This module
 * reads no clock.
 */
export declare const EPOCH_MAX = 65535;
/**
 * Release lineage of a detector GROUP's rules: one value per group per release,
 * never per detector and never a client identity (G14).
 */
export declare const GROUP_VERSION_MAX = 65535;
/** Per-call clip for `count` (schema v1 parameter; changing it is a schema change). */
export declare const COUNT_CLIP = 16;
/**
 * Detector-group codes: the ONLY detector information that reaches the wire
 * (G14). Codes are stable data: a new group APPENDS a new code, and a code is
 * never reused or renumbered.
 */
export declare const DETECTOR_GROUP_CODES: Readonly<{
    readonly mcp: 1;
    readonly "agent-config": 2;
    readonly container: 3;
    readonly "vcs-env": 4;
}>;
export type DetectorGroup = keyof typeof DETECTOR_GROUP_CODES;
/**
 * Local-only classification of every detector id in the compile-time detector
 * registry (src/review/detectors/registry.ts) into its group. The test asserts
 * the binding in both directions, so a detector added to the registry without
 * a group fails the suite instead of reaching the wire unclassified. This
 * table never leaves the machine; only the group's code does.
 */
export declare const DETECTOR_GROUP_OF: Readonly<{
    readonly mcp: "mcp";
    readonly claude: "agent-config";
    readonly cursor: "agent-config";
    readonly devcontainer: "container";
    readonly copilot: "agent-config";
    readonly windsurf: "agent-config";
    readonly antigravity: "agent-config";
    readonly trae: "agent-config";
    readonly kiro: "agent-config";
    readonly cline: "agent-config";
    readonly "roo-code": "agent-config";
    readonly continue: "agent-config";
    readonly gemini: "agent-config";
    readonly "amazon-q-developer": "agent-config";
    readonly "openai-codex": "agent-config";
    readonly aider: "agent-config";
    readonly git: "vcs-env";
    readonly env: "vcs-env";
}>;
/**
 * The wire code of the group a registered detector belongs to, or `undefined`
 * for anything that is not a registered detector id. Own properties only: a
 * prototype name such as "toString" or "__proto__" is not a detector. Only a
 * string: `Object.hasOwn` would convert an array or an object to a key and
 * call its toString.
 */
export declare function detectorGroupCode(detectorId: unknown): number | undefined;
/**
 * Technique codes: what kind of power a fact is about. A technique is one
 * CapabilityKind, except where one kind alone would name the agent (G14 fix
 * pass 1): `fileReach` (2) holds repositoryWrite (only Aider's detector emits
 * it from an agent's configuration) and externalDirectoryAccess (only Claude
 * Code's). Code 2 was `repositoryWrite` before; every record that meant it
 * still holds under `fileReach`. Code 8 was `externalDirectoryAccess`; it is
 * RETIRED and never reused. Codes append and are never renumbered.
 */
export declare const TECHNIQUE_CODES: Readonly<{
    readonly shellExecution: 1;
    readonly fileReach: 2;
    readonly mcpToolAccess: 3;
    readonly secretsExposure: 4;
    readonly autoApproval: 5;
    readonly agentInstructions: 6;
    readonly containerMount: 7;
    readonly portExposure: 9;
    readonly privilegedContainer: 10;
}>;
export type Technique = keyof typeof TECHNIQUE_CODES;
/**
 * Local-only classification of every CapabilityKind the detectors emit into
 * its technique; `satisfies` refuses a missing or an extra kind at compile
 * time. Like DETECTOR_GROUP_OF, this table never leaves the machine; only the
 * technique's code does. tests/assurance/contribution-detector-groups.test.ts
 * derives what each detector can emit from source and fails if any
 * (group, technique) pair could come from exactly one agent-named detector.
 */
export declare const TECHNIQUE_OF: Readonly<{
    readonly shellExecution: "shellExecution";
    readonly repositoryWrite: "fileReach";
    readonly mcpToolAccess: "mcpToolAccess";
    readonly secretsExposure: "secretsExposure";
    readonly autoApproval: "autoApproval";
    readonly agentInstructions: "agentInstructions";
    readonly containerMount: "containerMount";
    readonly externalDirectoryAccess: "fileReach";
    readonly portExposure: "portExposure";
    readonly privilegedContainer: "privilegedContainer";
}>;
/**
 * The wire code of the technique a capability kind belongs to, or `undefined`
 * for anything that is not a CapabilityKind. Own properties only, and only a
 * string: an array or an object that stringifies to a kind is not a kind.
 */
export declare function techniqueCode(kind: unknown): number | undefined;
/** Action classes named by the architecture's schema table. */
export declare const ACTION_CODES: Readonly<{
    readonly read: 1;
    readonly write: 2;
    readonly execute: 3;
    readonly network: 4;
    readonly credential: 5;
}>;
/** Decisions named by the architecture's schema table. */
export declare const DECISION_CODES: Readonly<{
    readonly detected: 1;
    readonly blocked: 2;
    readonly allowed: 3;
    readonly corrected: 4;
    readonly dismissed: 5;
}>;
/**
 * The four finding severities. "warning" is the baseline/identity lifecycle
 * severity (baseline.regenerated, identity.regenerated), not a threat
 * severity, so it has no code and cannot be encoded.
 */
export declare const SEVERITY_CODES: Readonly<{
    readonly critical: 1;
    readonly high: 2;
    readonly medium: 3;
    readonly info: 4;
}>;
export declare const SHARED_THREAT_INTELLIGENCE_PURPOSE: "shared-threat-intelligence";
/** The only consent shape that yields bytes: this purpose, literally granted. */
export interface SharedThreatIntelligenceConsent {
    readonly purpose: typeof SHARED_THREAT_INTELLIGENCE_PURPOSE;
    readonly granted: true;
}
/** The nine fields, in wire order. */
export declare const CONTRIBUTION_FIELDS: readonly ["schemaVersion", "epoch", "detectorGroup", "groupVersion", "technique", "action", "decision", "severity", "count"];
export type ContributionField = (typeof CONTRIBUTION_FIELDS)[number];
/** What a caller supplies. Every field is an integer code or count. */
export interface ContributionInput {
    readonly schemaVersion: typeof CONTRIBUTION_SCHEMA_VERSION;
    readonly epoch: number;
    readonly detectorGroup: number;
    readonly groupVersion: number;
    readonly technique: number;
    readonly action: number;
    readonly decision: number;
    readonly severity: number;
    readonly count: number;
}
/** The encoded fact: the input with `count` clipped, frozen. */
export type EncodedContribution = Readonly<ContributionInput>;
export type RefusalReason = "consent-required" | "consent-purpose-mismatch" | "consent-not-granted" | "input-not-plain-object" | "unknown-key" | "missing-field" | "field-not-data-property" | "field-not-integer" | "field-out-of-range" | "enum-unsupported" | "schema-version-unsupported" | "input-inspection-failed";
/** A refusal names a reason and at most one of OUR field names — never payload data. */
export interface ContributionRefusal {
    readonly ok: false;
    readonly reason: RefusalReason;
    readonly field?: ContributionField;
}
export interface ContributionAccepted {
    readonly ok: true;
    readonly contribution: EncodedContribution;
    /** Fixed-width big-endian layout: u8 u16 u8 u16 u8 u8 u8 u8 u8 — eleven bytes. */
    readonly bytes: Uint8Array;
}
export type EncodeResult = ContributionAccepted | ContributionRefusal;
/**
 * Encode one threat contribution, or refuse.
 *
 * Order is the contract: consent first (the payload is not touched until
 * consent passes), then shape, then each field. Any exception raised while
 * inspecting consent or the payload — only a Proxy trap can raise one — is
 * refused without its message: `consent-required` for consent,
 * `input-inspection-failed` for the payload. Pure and deterministic: the same
 * arguments always produce the same bytes.
 */
export declare function encodeContribution(consent: unknown, input: unknown): EncodeResult;
