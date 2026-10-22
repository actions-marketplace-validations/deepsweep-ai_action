/**
 * TEAM-ADR-072: the stable identity of every boundary-gap rule.
 *
 * A gap is ONE aggregate inference per rule (engine.ts deriveBoundaryGaps),
 * so the rule is its identity. An id is never reused or re-meaning'd; a
 * change to what a rule fires on, its severity or its wording bumps that
 * rule's version. The table is pinned by tests/source-inspections.test.ts.
 *
 * What this does NOT establish: that a gap is resolved per capability.
 * Several rules are co-occurrences (secrets with shell or MCP; repository
 * write with shell), and capability ids change with their resource and
 * duplicate order, so relatedCapabilityIds stay associations (Codex X-580).
 */
export declare const GAP_RULES: {
    readonly "secrets-with-agent-reach": {
        readonly version: 1;
        readonly shape: "co-occurrence";
    };
    readonly "mcp-arg-credential": {
        readonly version: 1;
        readonly shape: "direct";
    };
    readonly "mcp-cleartext-http": {
        readonly version: 1;
        readonly shape: "direct";
    };
    readonly "broad-preapproval": {
        readonly version: 1;
        readonly shape: "direct";
    };
    readonly "container-host-control": {
        readonly version: 1;
        readonly shape: "direct";
    };
    readonly "shell-without-approval": {
        readonly version: 1;
        readonly shape: "direct";
    };
    readonly "repo-write-with-shell": {
        readonly version: 1;
        readonly shape: "co-occurrence";
    };
    readonly "external-directory-access": {
        readonly version: 1;
        readonly shape: "direct";
    };
    readonly "container-bind-mount": {
        readonly version: 1;
        readonly shape: "direct";
    };
    readonly "unreviewed-agent-instructions": {
        readonly version: 1;
        readonly shape: "direct";
    };
    readonly "mcp-without-tool-policy": {
        readonly version: 1;
        readonly shape: "direct";
    };
    readonly "forwarded-port": {
        readonly version: 1;
        readonly shape: "direct";
    };
    readonly "ledger-tamper-detected": {
        readonly version: 1;
        readonly shape: "direct";
    };
};
export type GapRuleId = keyof typeof GAP_RULES;
/** The two metadata fields a gap carries for its rule. */
export declare function gapRule(id: GapRuleId): {
    ruleId: GapRuleId;
    ruleVersion: number;
};
