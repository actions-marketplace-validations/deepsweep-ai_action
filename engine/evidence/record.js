/**
 * ADR-DS-005 + TEAM-ADR-054 — canonical evidence records (schema
 * contracts/schemas/evidence-record.v2.json; v1 stays frozen beside it,
 * describing the records that already exist in the wild).
 *
 * An evidence record is the auditable projection of one governed decision:
 * WHO / WHAT / WHY / POLICY / OUTCOME (invariant 6) expressed entirely as
 * hashes, enumerated codes, counts, and operator-authored rule names
 * (invariant 1). It carries NO principal string, NO resource path, NO file
 * content, NO secret — the tuple travels as SHA-256 digests, so an auditor
 * can prove "this exact decision happened" by re-hashing their own copy of
 * the tuple.
 *
 * CORRECTED 2026-08-22 (TEAM-ADR-047): this header used to end "while the
 * record itself discloses nothing". That over-claims and is struck. A digest
 * over a GUESSABLE preimage confirms a guess for anyone who holds the record,
 * not only for an auditor who already holds the plaintext, and these tuples
 * are short closed vocabularies (`tool.invoke`, `mcp/<server>/<tool>`). The
 * record carries no plaintext; its digests are a COMMITMENT, not a
 * confidentiality control, and the disclosure boundary is what the exporter
 * emits. These digests are deliberately left UNKEYED — evidence-format.md
 * publishes them as a third-party recompute contract and
 * contracts/vectors/tool-call-vectors.v1.json freezes them — unlike the review
 * pins in src/review/pins.ts, which nothing outside this engine recomputes and
 * which TEAM-ADR-047 therefore keys.
 *
 * Canonicalization is RFC 8785 (JCS) via the engine's existing
 * `canonicalize` — the ADR-003 hashing contract already specifies JCS
 * semantics (UTF-16 code-unit key order, ECMAScript number form, minimal
 * escaping); this module reuses it rather than minting a second
 * canonicalizer, and tests/evidence-record.test.ts pins the JCS behaviors
 * that matter (key order, number forms, nesting, byte preservation).
 *
 * Pure and deterministic: nowIso is injected, output is byte-stable.
 */
import { canonicalize, sha256Hex } from "../review/canonical.js";
import { hashLeaf } from "./merkle.js";
export const EVIDENCE_SCHEMA_VERSION = 2;
/** Build the record — the ONLY place raw tuple values are touched.
 *
 * REFUSES the two shapes that lie (TEAM-ADR-054, a data-shape invariant
 * rather than a convention): a review-run record WITHOUT review facts is the
 * forgery shape the tripwire pinned, and a policy-decision record WITH them
 * is fabrication. Both throw; neither is repairable by a default.
 */
export function buildEvidenceRecord(input) {
    if (input.reason === "review-run" && input.review === null) {
        throw new Error("a review-run evidence record must carry the review it attests (TEAM-ADR-054) — refusing to build the forgery shape");
    }
    if (input.reason !== "review-run" && input.review !== null) {
        throw new Error(`review facts on a "${input.reason}" record would attest a review that did not produce it (TEAM-ADR-054) — refusing`);
    }
    return {
        schemaVersion: EVIDENCE_SCHEMA_VERSION,
        occurredAt: input.occurredAt,
        workspace: input.workspace,
        outcome: input.outcome,
        reason: input.reason,
        principalHash: sha256Hex(input.principal ?? ""),
        actionHash: sha256Hex(input.action),
        resourceHash: sha256Hex(input.resource),
        ruleName: input.ruleName,
        policyMode: input.policyMode,
        policyLayers: [...input.policyLayers].sort(),
        matchedRuleCount: input.matchedRuleCount,
        review: input.review === null ? null : { ...input.review },
    };
}
/** RFC 8785 canonical serialization of a record (the bytes that get hashed). */
export function serializeEvidenceRecord(record) {
    return canonicalize(record);
}
/** The record's Merkle leaf hash: RFC 6962 leaf hashing over JCS bytes. */
export function evidenceLeafHash(record) {
    return hashLeaf(serializeEvidenceRecord(record));
}
