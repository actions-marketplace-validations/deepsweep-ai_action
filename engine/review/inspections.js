/** Strongest limitation first. Only the last two are positive evidence. */
export const INSPECTION_PRECEDENCE = [
    "unreadable",
    "parse_failed",
    "unknown",
    "listed_partial",
    "presence_only",
    "pattern_match",
    "listed",
    "blank",
    "parsed",
];
/**
 * The statuses that are evidence a structured reader understood the whole
 * document. Anything else can never make a source comparable across reviews.
 */
export const COMPARABLE_INSPECTIONS = new Set(["parsed", "blank"]);
const rank = (s) => INSPECTION_PRECEDENCE.indexOf(s);
export function mergeInspections(observed, legacySources) {
    const byKey = new Map();
    for (const { detector, inspection } of observed) {
        const key = `${inspection.scope}\u0000${inspection.source}`;
        const prior = byKey.get(key);
        if (prior === undefined) {
            byKey.set(key, { ...inspection, detectors: [detector] });
            continue;
        }
        if (!prior.detectors.includes(detector))
            prior.detectors.push(detector);
        if (rank(inspection.status) < rank(prior.status)) {
            prior.status = inspection.status;
            if (inspection.reason !== undefined)
                prior.reason = inspection.reason;
            else
                delete prior.reason;
        }
    }
    for (const source of legacySources) {
        const scope = source.startsWith("~/") ? "user" : "workspace";
        const key = `${scope}\u0000${source}`;
        if (!byKey.has(key))
            byKey.set(key, { source, scope, status: "unknown", detectors: [] });
    }
    const out = [...byKey.values()];
    for (const r of out)
        r.detectors.sort();
    return out.sort((a, b) => (a.scope === b.scope ? cmp(a.source, b.source) : a.scope === "workspace" ? -1 : 1));
}
/** Sources are unique within a scope (merged by key above), so never equal here. */
function cmp(a, b) {
    return a < b ? -1 : 1;
}
