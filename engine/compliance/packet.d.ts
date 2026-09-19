import { type TrustedKey } from "../review/bundle.js";
import type { SignedTreeHead } from "../evidence/treehead.js";
import { type DisclosureReport } from "./disclosure.js";
import { type ComplianceTemplate, type TemplateId } from "./templates.js";
export declare const PACKET_SCHEMA_VERSION = "compliance-packet.v1";
/** The standing every packet carries. Wording is contract (tests pin it). */
export declare const PACKET_STANDING: string;
export interface PacketWindow {
    readonly fromIso: string;
    readonly toIso: string;
}
export interface TimelineRow {
    readonly seq: number;
    readonly occurredAt: string;
    readonly kind: string;
    readonly entryHash: string;
    /** Metadata-only payload as recorded (hashes, enumerated codes, counts, rule labels). */
    readonly payload: Record<string, string | number | boolean>;
    /** Verified disclosures for this entry, keyed by field. */
    readonly disclosed?: Record<string, unknown>;
}
export interface PacketCounts {
    readonly entries: number;
    readonly decisions: Record<string, number>;
    readonly gatewayActions: Record<string, number>;
    readonly approvalsGranted: number;
    readonly approvalsConsumed: number;
    readonly principals: number;
    readonly servers: number;
    readonly tools: number;
    readonly rulesFired: readonly string[];
}
export interface PacketIntegrity {
    readonly chainIntact: boolean;
    readonly ledgerEntries: number;
    readonly signedEntries: number;
    readonly signatureCoverage: "full" | "partial" | "none";
    readonly treeSize: number | null;
    readonly root: string | null;
    readonly signedTreeHead: SignedTreeHead | null;
    readonly verifyInstructions: string;
}
export interface CompliancePacketBody {
    readonly schemaVersion: typeof PACKET_SCHEMA_VERSION;
    readonly template: ComplianceTemplate;
    readonly standing: string;
    readonly generatedAt: string;
    readonly workspace: string;
    readonly window: PacketWindow;
    readonly counts: PacketCounts;
    readonly timeline: readonly TimelineRow[];
    readonly disclosures: DisclosureReport;
    readonly integrity: PacketIntegrity;
}
export interface CompliancePacket {
    readonly packet: CompliancePacketBody;
    /** Ed25519 over canonicalize(packet); absent = unsigned (recorded honestly). */
    readonly signature?: string;
    readonly keyId?: string;
}
export interface CompileParams {
    readonly workspaceRoot: string;
    readonly templateId: TemplateId;
    readonly window: PacketWindow;
    readonly disclosures?: readonly unknown[];
    readonly nowIso: string;
    /** Ed25519 PKCS8 PEM; signs BOTH the evidence export's tree head and the packet. */
    readonly signWithPem?: string;
    /**
     * TEAM-ADR-048 — the client's neutral engagement label for this packet and
     * the evidence export compiled inside it. Absent:
     * `DEEPSWEEP_WORKSPACE_LABEL`, then the salted-hash default. The workspace
     * basename never reaches the packet either way.
     */
    readonly workspaceLabel?: string;
}
export type CompileResult = {
    readonly status: "ok";
    readonly packet: CompliancePacket;
    readonly exitCode: 0;
} | {
    readonly status: "unverifiable";
    readonly reason: string;
    readonly exitCode: 3;
};
/** Build the packet body. Pure given the ledger; never throws on evidence grounds. */
/** May throw EvidenceMaterialError when `signWithPem` is not a readable Ed25519 key (same contract as `export`). */
export declare function compilePacket(p: CompileParams): CompileResult;
export type PacketVerdict = {
    readonly ok: true;
    readonly keyId: string;
} | {
    readonly ok: false;
    readonly reason: "malformed-envelope" | "unsigned" | "unknown-key" | "malformed-key" | "bad-signature";
};
/** The auditor's side: is this packet the one the pinned key signed? Fail-closed. */
export declare function verifyPacket(doc: unknown, trustedKeys: readonly TrustedKey[]): PacketVerdict;
