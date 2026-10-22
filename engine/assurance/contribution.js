/** The one schema version this encoder can produce. */
export const CONTRIBUTION_SCHEMA_VERSION = 1;
/** Length of the fixed-width wire form, in bytes. */
export const CONTRIBUTION_BYTES = 11;
/**
 * Upper bound of `epoch`: a caller-supplied u16, non-normative. What a window
 * is (its length and origin) is not decided here; it must be coarse and the
 * same for every contributor, and the producer decision fixes it. This module
 * reads no clock.
 */
export const EPOCH_MAX = 0xffff;
/**
 * Release lineage of a detector GROUP's rules: one value per group per release,
 * never per detector and never a client identity (G14).
 */
export const GROUP_VERSION_MAX = 0xffff;
/** Per-call clip for `count` (schema v1 parameter; changing it is a schema change). */
export const COUNT_CLIP = 16;
/**
 * Detector-group codes: the ONLY detector information that reaches the wire
 * (G14). Codes are stable data: a new group APPENDS a new code, and a code is
 * never reused or renumbered.
 */
export const DETECTOR_GROUP_CODES = Object.freeze({
    mcp: 1,
    "agent-config": 2,
    container: 3,
    "vcs-env": 4,
});
/**
 * Local-only classification of every detector id in the compile-time detector
 * registry (src/review/detectors/registry.ts) into its group. The test asserts
 * the binding in both directions, so a detector added to the registry without
 * a group fails the suite instead of reaching the wire unclassified. This
 * table never leaves the machine; only the group's code does.
 */
export const DETECTOR_GROUP_OF = Object.freeze({
    mcp: "mcp",
    claude: "agent-config",
    cursor: "agent-config",
    devcontainer: "container",
    copilot: "agent-config",
    windsurf: "agent-config",
    antigravity: "agent-config",
    trae: "agent-config",
    kiro: "agent-config",
    cline: "agent-config",
    "roo-code": "agent-config",
    continue: "agent-config",
    gemini: "agent-config",
    "amazon-q-developer": "agent-config",
    "openai-codex": "agent-config",
    aider: "agent-config",
    git: "vcs-env",
    env: "vcs-env",
});
/**
 * The wire code of the group a registered detector belongs to, or `undefined`
 * for anything that is not a registered detector id. Own properties only: a
 * prototype name such as "toString" or "__proto__" is not a detector. Only a
 * string: `Object.hasOwn` would convert an array or an object to a key and
 * call its toString.
 */
export function detectorGroupCode(detectorId) {
    if (typeof detectorId !== "string" || !Object.hasOwn(DETECTOR_GROUP_OF, detectorId))
        return undefined;
    return DETECTOR_GROUP_CODES[DETECTOR_GROUP_OF[detectorId]];
}
/**
 * Technique codes: what kind of power a fact is about. A technique is one
 * CapabilityKind, except where one kind alone would name the agent (G14 fix
 * pass 1): `fileReach` (2) holds repositoryWrite (only Aider's detector emits
 * it from an agent's configuration) and externalDirectoryAccess (only Claude
 * Code's). Code 2 was `repositoryWrite` before; every record that meant it
 * still holds under `fileReach`. Code 8 was `externalDirectoryAccess`; it is
 * RETIRED and never reused. Codes append and are never renumbered.
 */
export const TECHNIQUE_CODES = Object.freeze({
    shellExecution: 1,
    fileReach: 2,
    mcpToolAccess: 3,
    secretsExposure: 4,
    autoApproval: 5,
    agentInstructions: 6,
    containerMount: 7,
    portExposure: 9,
    privilegedContainer: 10,
});
/**
 * Local-only classification of every CapabilityKind the detectors emit into
 * its technique; `satisfies` refuses a missing or an extra kind at compile
 * time. Like DETECTOR_GROUP_OF, this table never leaves the machine; only the
 * technique's code does. tests/assurance/contribution-detector-groups.test.ts
 * derives what each detector can emit from source and fails if any
 * (group, technique) pair could come from exactly one agent-named detector.
 */
export const TECHNIQUE_OF = Object.freeze({
    shellExecution: "shellExecution",
    repositoryWrite: "fileReach",
    mcpToolAccess: "mcpToolAccess",
    secretsExposure: "secretsExposure",
    autoApproval: "autoApproval",
    agentInstructions: "agentInstructions",
    containerMount: "containerMount",
    externalDirectoryAccess: "fileReach",
    portExposure: "portExposure",
    privilegedContainer: "privilegedContainer",
});
/**
 * The wire code of the technique a capability kind belongs to, or `undefined`
 * for anything that is not a CapabilityKind. Own properties only, and only a
 * string: an array or an object that stringifies to a kind is not a kind.
 */
export function techniqueCode(kind) {
    if (typeof kind !== "string" || !Object.hasOwn(TECHNIQUE_OF, kind))
        return undefined;
    return TECHNIQUE_CODES[TECHNIQUE_OF[kind]];
}
/** Action classes named by the architecture's schema table. */
export const ACTION_CODES = Object.freeze({
    read: 1,
    write: 2,
    execute: 3,
    network: 4,
    credential: 5,
});
/** Decisions named by the architecture's schema table. */
export const DECISION_CODES = Object.freeze({
    detected: 1,
    blocked: 2,
    allowed: 3,
    corrected: 4,
    dismissed: 5,
});
/**
 * The four finding severities. "warning" is the baseline/identity lifecycle
 * severity (baseline.regenerated, identity.regenerated), not a threat
 * severity, so it has no code and cannot be encoded.
 */
export const SEVERITY_CODES = Object.freeze({
    critical: 1,
    high: 2,
    medium: 3,
    info: 4,
});
export const SHARED_THREAT_INTELLIGENCE_PURPOSE = "shared-threat-intelligence";
/** The nine fields, in wire order. */
export const CONTRIBUTION_FIELDS = Object.freeze([
    "schemaVersion",
    "epoch",
    "detectorGroup",
    "groupVersion",
    "technique",
    "action",
    "decision",
    "severity",
    "count",
]);
const codes = (registry) => new Set(Object.values(registry));
const RULES = Object.freeze({
    schemaVersion: { kind: "exact", value: CONTRIBUTION_SCHEMA_VERSION },
    epoch: { kind: "range", min: 0, max: EPOCH_MAX },
    detectorGroup: { kind: "enum", codes: codes(DETECTOR_GROUP_CODES) },
    groupVersion: { kind: "range", min: 0, max: GROUP_VERSION_MAX },
    technique: { kind: "enum", codes: codes(TECHNIQUE_CODES) },
    action: { kind: "enum", codes: codes(ACTION_CODES) },
    decision: { kind: "enum", codes: codes(DECISION_CODES) },
    severity: { kind: "enum", codes: codes(SEVERITY_CODES) },
    count: { kind: "clipped", min: 1, clip: COUNT_CLIP },
});
const FIELD_SET = new Set(CONTRIBUTION_FIELDS);
const refuse = (reason, field) => Object.freeze(field === undefined ? { ok: false, reason } : { ok: false, reason, field });
const isPlainObject = (value) => {
    if (typeof value !== "object" || value === null)
        return false;
    const proto = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
};
/** Reads an own DATA property without invoking accessors. `undefined` = absent or accessor. */
const ownDataValue = (target, key) => {
    const descriptor = Object.getOwnPropertyDescriptor(target, key);
    if (descriptor === undefined)
        return { present: false, data: false, value: undefined };
    if ("get" in descriptor || "set" in descriptor)
        return { present: true, data: false, value: undefined };
    return { present: true, data: true, value: descriptor.value };
};
/**
 * Consent is validated FIRST and on its own: a plain object with exactly the
 * keys `purpose` and `granted`, both own data properties, `purpose` equal to
 * the shared-threat-intelligence purpose and `granted` literally `true`.
 */
const checkConsent = (consent) => {
    if (!isPlainObject(consent))
        return refuse("consent-required");
    const keys = Reflect.ownKeys(consent);
    if (keys.length !== 2 || !keys.includes("purpose") || !keys.includes("granted")) {
        return refuse("consent-required");
    }
    const purpose = ownDataValue(consent, "purpose");
    const granted = ownDataValue(consent, "granted");
    if (!purpose.data || !granted.data)
        return refuse("consent-required");
    if (purpose.value !== SHARED_THREAT_INTELLIGENCE_PURPOSE)
        return refuse("consent-purpose-mismatch");
    if (granted.value !== true)
        return refuse("consent-not-granted");
    return null;
};
/**
 * The consent error boundary. Inspecting consent can only raise through a
 * Proxy trap (getPrototypeOf, ownKeys, getOwnPropertyDescriptor); a consent
 * that cannot be read is not consent, so the failure is refused as
 * `consent-required` without the thrown message, and the payload is never
 * reached. (Review round 1, 2026-09-24: this call sat outside any boundary and
 * a throwing consent Proxy escaped with its message.)
 */
const safeConsent = (consent) => {
    try {
        return checkConsent(consent);
    }
    catch {
        return refuse("consent-required");
    }
};
const checkField = (field, value) => {
    if (typeof value !== "number" || !Number.isSafeInteger(value))
        return refuse("field-not-integer", field);
    const rule = RULES[field];
    switch (rule.kind) {
        case "exact":
            return value === rule.value ? value : refuse("schema-version-unsupported", field);
        case "range":
            return value >= rule.min && value <= rule.max ? value : refuse("field-out-of-range", field);
        case "enum":
            return rule.codes.has(value) ? value : refuse("enum-unsupported", field);
        case "clipped":
            return value >= rule.min ? Math.min(value, rule.clip) : refuse("field-out-of-range", field);
    }
};
const inspect = (input) => {
    if (!isPlainObject(input))
        return refuse("input-not-plain-object");
    for (const key of Reflect.ownKeys(input)) {
        if (!FIELD_SET.has(key))
            return refuse("unknown-key");
    }
    const values = {};
    for (const field of CONTRIBUTION_FIELDS) {
        const own = ownDataValue(input, field);
        if (!own.present)
            return refuse("missing-field", field);
        if (!own.data)
            return refuse("field-not-data-property", field);
        const checked = checkField(field, own.value);
        if (typeof checked !== "number")
            return checked;
        values[field] = checked;
    }
    return values;
};
const serialize = (fact) => {
    const bytes = new Uint8Array(CONTRIBUTION_BYTES);
    const view = new DataView(bytes.buffer);
    view.setUint8(0, fact.schemaVersion);
    view.setUint16(1, fact.epoch);
    view.setUint8(3, fact.detectorGroup);
    view.setUint16(4, fact.groupVersion);
    view.setUint8(6, fact.technique);
    view.setUint8(7, fact.action);
    view.setUint8(8, fact.decision);
    view.setUint8(9, fact.severity);
    view.setUint8(10, fact.count);
    return bytes;
};
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
export function encodeContribution(consent, input) {
    const consentRefusal = safeConsent(consent);
    if (consentRefusal !== null)
        return consentRefusal;
    let inspected;
    try {
        inspected = inspect(input);
    }
    catch {
        return refuse("input-inspection-failed");
    }
    if ("ok" in inspected)
        return inspected;
    const contribution = Object.freeze({
        schemaVersion: CONTRIBUTION_SCHEMA_VERSION,
        epoch: inspected.epoch,
        detectorGroup: inspected.detectorGroup,
        groupVersion: inspected.groupVersion,
        technique: inspected.technique,
        action: inspected.action,
        decision: inspected.decision,
        severity: inspected.severity,
        count: inspected.count,
    });
    return Object.freeze({ ok: true, contribution, bytes: serialize(inspected) });
}
