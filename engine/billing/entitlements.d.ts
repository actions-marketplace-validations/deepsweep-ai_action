/**
 * Revenue layer — entitlements & tier gates.
 * SYNCED TO STRIPE (source of truth, pulled 2026-07-27, account acct_1S2EsWLLFqn3U97P).
 * Tiers: Free / Pro / Team / Enterprise. Flat per-seat, no usage metering (answers PP-3).
 *
 * Stripe IDs are the single source of truth shared by the pricing page, checkout, and these
 * gates — do not hardcode prices in the UI; read STRIPE_PRICES here.
 */
export type Tier = "free" | "pro" | "team" | "enterprise";
/**
 * WHAT IS DELIBERATELY ABSENT, and why it is absent rather than merely unbuilt.
 *
 * REPLAY. `replay30` (Pro), `replayUnlimited` (Enterprise) and
 * `replayRetentionDays` were removed 2026-09-19. Deterministic replay is
 * STRUCTURALLY IMPOSSIBLE against the evidence record we ship: `record.ts`
 * hashes principal, action and resource at build time and the v2 schema
 * declares only the hashed forms, so there is nothing to recompute a decision
 * from. TEAM-ADR-036 and TEAM-ADR-054 chose that shape on purpose;
 * ADR-RGOV-007 designed replay and it was never built.
 *
 * The flags had ZERO consumers. A priced feature flag with no reader is how an
 * unsupportable sentence reaches a pricing page: someone greps the tier table,
 * finds "replay" in Pro, and writes it into a sales asset. Removing the flag
 * removes the raw material. Restoring replay means a superseding ADR that
 * changes the record shape FIRST, and the flag comes back after, never before.
 */
export type Feature = "review" | "identity" | "authorization" | "protect" | "auditLocal" | "governanceScore" | "exactLocations" | "oneClickRemediation" | "mcpPinning" | "verifiedBadge" | "teamPolicyBundles" | "delegatedApprovals" | "ciCdGating" | "restApi" | "auditLogs90" | "seats10" | "complianceEvidence" | "ssoScim" | "orgPolicyDistribution" | "airGap" | "sla" | "dedicatedSupport";
export interface StripePrice {
    productId: string;
    monthly: string | null;
    annual: string | null;
}
/** Live Stripe identifiers (2026-07-27). Enterprise monthly is a $0 "contact sales" placeholder. */
export declare const STRIPE_PRICES: Record<Tier, StripePrice>;
export interface Plan {
    tier: Tier;
    displayName: string;
    /** Display cents (USD). null = custom / contact sales. */
    monthlyCents: number | null;
    annualCents: number | null;
    seats: number;
    features: Feature[];
    popular?: boolean;
    blurb: string;
}
export declare const PLANS: Record<Tier, Plan>;
export interface Entitlements {
    tier: Tier;
    seats: number;
    features: Set<Feature>;
}
export declare function entitlementsFor(tier: Tier, seats?: number): Entitlements;
export declare function isEntitled(e: Entitlements, feature: Feature): boolean;
export declare function requireFeature(e: Entitlements, feature: Feature): void;
export declare class EntitlementError extends Error {
    readonly feature: Feature;
    readonly currentTier: Tier;
    readonly requiredTier: string;
    constructor(feature: Feature, currentTier: Tier, requiredTier: string);
}
/** Deterministic monthly revenue (USD dollars) for a seat mix; custom tiers excluded (null price). */
export declare function monthlyRevenueUsd(seatMix: Partial<Record<Tier, number>>): number;
/** Display helper: "$19" / "$99" / "Custom". */
export declare function priceLabel(tier: Tier, cycle?: "monthly" | "annual"): string;
