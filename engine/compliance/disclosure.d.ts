import type { LedgerEntry } from "../review/ledger.js";
export type DisclosureField = "server" | "tool" | "principal" | "args" | "result";
export interface SelectiveDisclosure {
    /** entryHash of the ledger entry the value belongs to (a tool_call for server/tool/principal/args, a tool_result for result). */
    readonly entryHash: string;
    readonly field: DisclosureField;
    /** The plaintext the customer chooses to disclose. */
    readonly value: unknown;
}
export type DisclosureVerdict = "verified" | "mismatch" | "unknown-entry" | "field-not-recorded" | "malformed";
export interface VerifiedDisclosure {
    readonly entryHash: string;
    readonly field: DisclosureField;
    readonly value: unknown;
    readonly recordedHash: string;
}
export interface RefusedDisclosure {
    readonly entryHash: string;
    readonly field: string;
    readonly verdict: Exclude<DisclosureVerdict, "verified">;
}
export interface DisclosureReport {
    readonly verified: readonly VerifiedDisclosure[];
    readonly refused: readonly RefusedDisclosure[];
}
/** The digest the gateway would have recorded for this field and value. */
export declare function disclosureHash(field: DisclosureField, value: unknown): string | undefined;
export declare function verifyDisclosures(entries: readonly LedgerEntry[], disclosures: readonly unknown[]): DisclosureReport;
