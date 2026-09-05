/**
 * ADR-DS-005 — evidence export: the local hash-chained ledger (ADR-018)
 * projected into an RFC 6962 Merkle log, with inclusion and consistency
 * proofs a third party can verify against nothing but the published root.
 *
 * The two structures answer different questions and BOTH ship:
 *  - hash CHAIN (ADR-018): "was this file edited?" — cheap, append-time.
 *  - Merkle LOG (RFC 6962): "is entry k in the log committed to by root R,
 *    and is log R2 an append-only extension of R1?" — the property a
 *    transparency auditor, a regulator, or a court can check offline.
 *
 * Fail-closed: a malformed ledger OR a broken hash chain yields a refusal
 * bundle (status "unverifiable"), never a partial or fabricated proof set —
 * and never a SIGNED tree head over edited history (TEAM-ADR-046).
 */
import { readLedger, verifyChain } from "../review/ledger.js";
import { buildEvidenceRecord, evidenceLeafHash, } from "./record.js";
import { signTreeHead } from "./treehead.js";
import { consistencyProof, inclusionProof, merkleRoot, verifyConsistency, verifyInclusion, } from "./merkle.js";
/**
 * Map one ledger entry to its evidence record (metadata-only by shape).
 *
 * THROWS for a `review.run` entry whose payload lacks a valid
 * `baselineSha256` (TEAM-ADR-054): the facts the record must attest are
 * missing, and zeroing them would put a fabricated all-clear inside the one
 * artifact whose job is to be unfabricatable. `exportEvidence` turns the
 * throw into a refusal bundle, the TEAM-ADR-046 posture.
 */
export function recordFromLedgerEntry(entry, workspace) {
    const p = entry.payload;
    const str = (k) => (typeof p[k] === "string" ? String(p[k]) : "");
    const num = (k) => (typeof p[k] === "number" ? Number(p[k]) : 0);
    const isDecision = entry.kind === "policy.decision";
    const outcome = str("outcome");
    let review = null;
    if (entry.kind === "review.run") {
        const baselineSha256 = str("baselineSha256");
        if (!/^[0-9a-f]{64}$/.test(baselineSha256)) {
            throw new Error("review.run ledger entry carries no valid baselineSha256 — refusing to export a review record without the review it attests (TEAM-ADR-054)");
        }
        review = {
            baselineSha256,
            findingCount: num("findingCount"),
            criticalCount: num("critical"),
            highCount: num("high"),
            capabilityCount: num("capabilities"),
            boundaryGapCount: num("boundaryGaps"),
        };
    }
    return buildEvidenceRecord({
        occurredAt: entry.occurredAt,
        workspace,
        outcome: outcome === "allow" || outcome === "deny" || outcome === "require-approval"
            ? outcome
            : "observe",
        reason: isDecision
            ? str("rule") === "" || str("rule").startsWith("(none")
                ? "default-effect"
                : "rule-matched"
            : entry.kind === "review.run"
                ? "review-run"
                : "ledger-event",
        // The ledger already stores the tuple as hashes (ADR-021 privacy rule):
        // re-hashing a hash is still a stable, value-free commitment, and for
        // review.run entries the tuple slots are empty by construction.
        principal: str("principalHash") === "" ? null : str("principalHash"),
        action: isDecision ? str("actionHash") : entry.kind,
        resource: isDecision ? str("resourceHash") : str("workspace"),
        ruleName: isDecision && str("rule") !== "" ? str("rule") : null,
        policyMode: str("mode") === "" ? "observe" : str("mode"),
        policyLayers: [],
        matchedRuleCount: num("matchedRules"),
        review,
    });
}
/**
 * Build the evidence bundle for a workspace: every ledger entry as a
 * canonical record, the Merkle root, an inclusion proof per record, and a
 * consistency proof from `sinceSize` when supplied.
 */
export function exportEvidence(workspaceRoot, opts) {
    const entries = readLedger(workspaceRoot);
    if (entries === undefined) {
        return {
            status: "unverifiable",
            reason: "ledger.jsonl is malformed — refusing to export proofs over damaged evidence",
        };
    }
    if (!verifyChain(entries)) {
        // TEAM-ADR-046: exporting (and above all SIGNING) proofs over an edited
        // ledger would attest tampered history — the exact over-claim the moat
        // cannot survive. verifyLedger() names the tamper class for forensics.
        return {
            status: "unverifiable",
            reason: "ledger hash chain does not verify — an entry was edited or removed; refusing to export or sign proofs over tampered evidence",
        };
    }
    let records;
    try {
        records = entries.map((e) => recordFromLedgerEntry(e, opts.workspace));
    }
    catch (err) {
        // TEAM-ADR-054: a review.run entry without the facts it must attest is a
        // refusal, never a zeroed record — same posture as a broken chain.
        return { status: "unverifiable", reason: err.message };
    }
    const leaves = records.map(evidenceLeafHash);
    const root = merkleRoot(leaves);
    const limit = Math.min(opts.maxInclusion ?? leaves.length, leaves.length);
    const inclusion = [];
    for (let i = 0; i < limit; i++) {
        const proof = inclusionProof(leaves, i);
        inclusion.push({
            leafIndex: i,
            leafHash: leaves[i],
            treeSize: leaves.length,
            proof,
            selfVerified: verifyInclusion(leaves[i], i, leaves.length, proof, root),
        });
    }
    const consistency = [];
    const since = opts.sinceSize;
    if (since !== undefined && Number.isInteger(since) && since > 0 && since <= leaves.length) {
        const firstRoot = merkleRoot(leaves.slice(0, since));
        const proof = consistencyProof(leaves, since);
        consistency.push({
            firstSize: since,
            firstRoot,
            secondSize: leaves.length,
            secondRoot: root,
            proof,
            selfVerified: verifyConsistency(since, leaves.length, firstRoot, root, proof),
        });
    }
    const signed = opts.signTreeHeadWith !== undefined
        ? signTreeHead(leaves.length, root, opts.generatedAt, opts.signTreeHeadWith)
        : undefined;
    return {
        status: "ok",
        schemaVersion: 1,
        workspace: opts.workspace,
        generatedAt: opts.generatedAt,
        treeSize: leaves.length,
        root,
        chainIntact: true,
        records,
        inclusion,
        consistency,
        ...(signed !== undefined ? { signedTreeHead: signed } : {}),
    };
}
