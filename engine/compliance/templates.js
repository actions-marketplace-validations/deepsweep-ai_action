/**
 * Compliance templates (TEAM-ADR-038) — the clause maps that turn a timeline
 * into a regulator-shaped annex. Shipped as JSON under contracts/templates/
 * and embedded here at build time by import so the compiled engine needs no
 * filesystem lookup (and no path can be attacker-influenced).
 *
 * EVERY template is DRAFT until counsel review; `reviewStatus` travels into
 * the packet verbatim. A wrong regulatory mapping in an evidence product is
 * not a bug — it is a credibility event with the exact target buyer.
 */
import { TEMPLATE_DATA } from "./template-data.js";
export const TEMPLATE_IDS = [
    "incident-nis2-24h",
    "incident-gdpr-72h",
    "incident-aiact-15d",
    "article-50-transparency",
    "nist-ai-rmf",
    "iso-42001",
    // TEAM-ADR-041 (EXEC-1): the executive-assistant incident spine and the
    // underwriting summary. Additive; DRAFT until counsel review like the rest.
    "exec-incident-packet",
    "insurer-evidence-summary",
    // US/Canada clocks (2026-08-26): 5 of the 20 T2 outreach drafts promise
    // HIPAA/NYDFS/OSFI clocks that had NO template — the promised deliverable
    // could not map the buyer's own regime. DRAFT until counsel review, like
    // every other template; the OSFI one carries an extra confirm-before-use
    // caveat because the advisory is guidance, not regulation.
    "incident-hipaa-60d",
    "incident-nydfs-72h",
    "incident-osfi-24h",
];
const TEMPLATES = TEMPLATE_DATA;
export function isTemplateId(v) {
    return typeof v === "string" && TEMPLATE_IDS.includes(v);
}
export function loadTemplate(id) {
    return TEMPLATES[id];
}
