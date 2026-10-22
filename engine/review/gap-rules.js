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
export const GAP_RULES = {
    "secrets-with-agent-reach": { version: 1, shape: "co-occurrence" },
    "mcp-arg-credential": { version: 1, shape: "direct" },
    "mcp-cleartext-http": { version: 1, shape: "direct" },
    "broad-preapproval": { version: 1, shape: "direct" },
    "container-host-control": { version: 1, shape: "direct" },
    "shell-without-approval": { version: 1, shape: "direct" },
    "repo-write-with-shell": { version: 1, shape: "co-occurrence" },
    "external-directory-access": { version: 1, shape: "direct" },
    "container-bind-mount": { version: 1, shape: "direct" },
    "unreviewed-agent-instructions": { version: 1, shape: "direct" },
    "mcp-without-tool-policy": { version: 1, shape: "direct" },
    "forwarded-port": { version: 1, shape: "direct" },
    "ledger-tamper-detected": { version: 1, shape: "direct" },
};
/** The two metadata fields a gap carries for its rule. */
export function gapRule(id) {
    return { ruleId: id, ruleVersion: GAP_RULES[id].version };
}
