/** Live Stripe identifiers (2026-07-27). Enterprise monthly is a $0 "contact sales" placeholder. */
export const STRIPE_PRICES = {
    free: { productId: "", monthly: null, annual: null },
    pro: { productId: "prod_TUo9W5meTIaTh0", monthly: "price_1TlpH0LLFqn3U97Pr0PQGF5l", annual: "price_1TlpH0LLFqn3U97PlxLWu691" },
    team: { productId: "prod_TcMnNP3zmF1Vwe", monthly: "price_1TlpJ0LLFqn3U97Pg98wBQ9t", annual: "price_1TlpJ0LLFqn3U97PgnlWNs7c" },
    enterprise: { productId: "prod_TcN2M4wgsxKYku", monthly: "price_1Sf8IkLLFqn3U97PfNhn38Lw", annual: null },
};
// `exactLocations` is FREE: the file and line a finding came from ship in the free local
// runtime (platform PLAT-ADR-185/192, `services/desktop/entitlement_features.py`, and #800
// "Entitlements say file and line are free"). This table said Pro; Studio vendors it by
// digest, so the stale claim would have gated free locations behind Pro (backlog row 134).
const FREE_F = ["review", "identity", "authorization", "protect", "auditLocal", "governanceScore", "exactLocations"];
const PRO_F = [...FREE_F, "oneClickRemediation", "mcpPinning", "verifiedBadge"];
const TEAM_F = [...PRO_F, "teamPolicyBundles", "delegatedApprovals", "ciCdGating", "restApi", "auditLogs90", "seats10"];
const ENT_F = [...TEAM_F, "complianceEvidence", "ssoScim", "orgPolicyDistribution", "airGap", "sla", "dedicatedSupport"];
export const PLANS = {
    free: { tier: "free", displayName: "Free", monthlyCents: 0, annualCents: 0, seats: 1, features: FREE_F, blurb: "The full local runtime. Free forever." },
    pro: { tier: "pro", displayName: "Pro", monthlyCents: 1900, annualCents: 19000, seats: 1, features: PRO_F, blurb: "Exact fixes + your badge, for the individual builder." },
    team: { tier: "team", displayName: "Team", monthlyCents: 9900, annualCents: 99900, seats: 10, features: TEAM_F, popular: true, blurb: "Shared governance for teams shipping agent code." },
    enterprise: { tier: "enterprise", displayName: "Enterprise", monthlyCents: null, annualCents: null, seats: Number.POSITIVE_INFINITY, features: ENT_F, blurb: "Org-wide governance, compliance evidence & control." },
};
export function entitlementsFor(tier, seats) {
    const plan = PLANS[tier];
    return { tier, seats: seats ?? plan.seats, features: new Set(plan.features) };
}
export function isEntitled(e, feature) { return e.features.has(feature); }
export function requireFeature(e, feature) {
    if (!isEntitled(e, feature)) {
        const needed = (Object.values(PLANS).find((p) => p.features.includes(feature)) ?? PLANS.team).displayName;
        throw new EntitlementError(feature, e.tier, needed);
    }
}
export class EntitlementError extends Error {
    feature;
    currentTier;
    requiredTier;
    constructor(feature, currentTier, requiredTier) {
        super(`Feature "${feature}" requires the ${requiredTier} plan (current: ${currentTier}).`);
        this.feature = feature;
        this.currentTier = currentTier;
        this.requiredTier = requiredTier;
        this.name = "EntitlementError";
    }
}
/** Deterministic monthly revenue (USD dollars) for a seat mix; custom tiers excluded (null price). */
export function monthlyRevenueUsd(seatMix) {
    let cents = 0;
    for (const tier of Object.keys(PLANS)) {
        const m = PLANS[tier].monthlyCents;
        if (m != null)
            cents += (seatMix[tier] ?? 0) * m;
    }
    return cents / 100;
}
/** Display helper: "$19" / "$99" / "Custom". */
export function priceLabel(tier, cycle = "monthly") {
    const c = cycle === "monthly" ? PLANS[tier].monthlyCents : PLANS[tier].annualCents;
    return c == null ? "Custom" : c === 0 ? "$0" : `$${(c / 100).toLocaleString()}`;
}
