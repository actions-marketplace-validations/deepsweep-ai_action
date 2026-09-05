const THREAT_REF_IN_RULE = /(?:^|[/:])(P[1-9])\./;
function bump(map, key) {
    map[key] = (map[key] ?? 0) + 1;
}
/** Derive the summary. Total over any packet body; unknown kinds are simply not counted. */
export function summarizeExecEvidence(packet) {
    const packs = new Set();
    const byOutcome = {};
    const byClass = {};
    const byThreat = {};
    const confidence = {};
    const gatewayActions = {};
    let decisions = 0;
    let byDefault = 0;
    let unclassified = 0;
    let granted = 0;
    let consumed = 0;
    let pinned = 0;
    let drift = 0;
    let repinned = 0;
    for (const row of packet.timeline) {
        const pl = row.payload;
        switch (row.kind) {
            case "policy.decision": {
                decisions += 1;
                const outcome = String(pl["outcome"]);
                bump(byOutcome, outcome);
                const packLabel = pl["packs"];
                if (typeof packLabel === "string" && packLabel.length > 0)
                    for (const p of packLabel.split(","))
                        packs.add(p);
                const classes = pl["classes"];
                if (typeof classes === "string" && classes.length > 0) {
                    for (const c of classes.split(","))
                        bump(byClass, c);
                    bump(confidence, String(pl["classification"]));
                }
                else {
                    unclassified += 1;
                }
                const rule = String(pl["rule"]);
                const m = THREAT_REF_IN_RULE.exec(rule);
                if (m !== null) {
                    const ref = m[1];
                    const cur = byThreat[ref] ?? { allow: 0, deny: 0, "require-approval": 0, observe: 0 };
                    const key = (outcome === "allow" || outcome === "deny" || outcome === "require-approval" || outcome === "observe" ? outcome : "observe");
                    byThreat[ref] = { ...cur, [key]: cur[key] + 1 };
                }
                else if (rule.startsWith("(none")) {
                    byDefault += 1;
                }
                break;
            }
            case "gateway.tool_call":
                bump(gatewayActions, String(pl["action"]));
                break;
            case "approval.granted":
                granted += 1;
                break;
            case "approval.consumed":
                consumed += 1;
                break;
            case "gateway.tool_pinned":
                pinned += 1;
                break;
            case "gateway.tool_drift":
                drift += 1;
                break;
            case "gateway.tool_repinned":
                repinned += 1;
                break;
            default:
                break;
        }
    }
    return {
        window: packet.window,
        packs: [...packs].sort(),
        decisions,
        decisionsByOutcome: byOutcome,
        decisionsByClass: byClass,
        decisionsByThreatRef: byThreat,
        decisionsByDefault: byDefault,
        classificationConfidence: confidence,
        unclassifiedDecisions: unclassified,
        gatewayActions,
        approvalsGranted: granted,
        approvalsConsumed: consumed,
        toolPinned: pinned,
        toolDrift: drift,
        toolRepinned: repinned,
        integrity: packet.integrity,
    };
}
