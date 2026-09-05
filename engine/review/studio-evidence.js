/**
 * TEAM-ADR-052 — what the Studio artifact's embedded verifier is allowed to
 * check.
 *
 * THE DEFECT THIS REPLACES. `.deepsweep/studio.html` is "a file that travels".
 * Its embedded verifier recomputed `sha256(canon(entry-minus-entryHash))` per
 * row and re-linked `prevHash`, then printed "chain intact". That check
 * verifies the file AGAINST ITSELF: an editor who alters a row, recomputes
 * that row's `entryHash` and cascades the new `prevHash` forward gets the same
 * verdict. Reproduced, not assumed (tests/studio-inclusion.test.ts).
 *
 * THE DECISION. Stop recomputing entry hashes from payloads. Verify INCLUSION
 * of each row's `entryHash` in the RFC 6962 tree the operator SIGNED — the
 * same tree `ledgerTreeHead()` builds, that `exportAnchor` anchors, and that
 * `tools/anchor-head.ts` records into the committed heads registry and stamps
 * with external timestamps (TEAM-ADR-050). Nothing here mints a second tree,
 * a second leaf rule or a second signing routine: `ledgerTreeHead`,
 * `proveLedgerInclusion` (src/review/ledger.ts) and `signTreeHead`
 * (src/evidence/treehead.ts) are the only implementations, and this module
 * calls them.
 *
 * That single change resolves the second half of issue #65 too. The verifier
 * no longer needs `argsHash`/`resultHash` present, so the Studio can withhold
 * them under the same emission rule as the compliance packet
 * (`oracleWithheldKeys`) without breaking any check.
 *
 * WHAT IT STILL DOES NOT PROVE — stated here because the UI states it too:
 *  1. The signing key travels in the file so the check RUNS offline. That is
 *     not what makes it trustworthy: an editor can re-sign a rewritten log
 *     under their OWN key. What they cannot do is keep the `keyId`. The reader
 *     compares the printed key id against the key they hold.
 *  2. Inclusion binds each entry's HASH. Because the projection withholds
 *     payload keys, the row's DISPLAYED fields are not re-derivable from that
 *     hash inside this file. Binding displayed values needs the signed
 *     evidence export or a compliance packet, where a disclosed field travels
 *     with its preimage.
 */
import { createPrivateKey, createPublicKey } from "node:crypto";
import { signTreeHead } from "../evidence/treehead.js";
import { ledgerTreeHead, proveLedgerInclusion, verifyChain, } from "./ledger.js";
/**
 * The sentence the artifact prints when it carries no commitment. Wording is
 * contract (a test pins it) for the same reason the packet's `standing` is:
 * this is the sentence a reader of an UNSIGNED file sees, and it must not be
 * mistakable for authenticity.
 *
 * `no-signing-key` is the TRUE case today — the Ed25519 signing ceremony has
 * not happened, so every artifact the engine writes right now lands here.
 * TEAM-ADR-050 anchors heads externally WITHOUT a key, which binds bytes to
 * time; attribution is the separate property this sentence says is missing.
 */
export const STUDIO_UNSIGNED_NOTE = {
    "no-signing-key": "UNSIGNED — this file carries no signed tree head, so nothing in it can be verified here. " +
        "Its rows are a snapshot: anyone who can edit this file can make its contents agree with each other. " +
        "No signing key has been generated for this log yet, so no artifact it writes can be attributed to anyone.",
    "empty-ledger": "UNSIGNED — the ledger is empty, so there is nothing to commit to and nothing to verify.",
    "malformed-ledger": "UNSIGNED — the ledger on disk is malformed, so no tree head was built over it. " +
        "The damage is left in place to stay verifiable against your latest anchor.",
    "chain-broken": "UNSIGNED — the ledger's own hash chain does not verify, so this file refuses to carry a signed tree head " +
        "over edited history. Nothing here can be verified; treat the log as tampered until an anchor says otherwise.",
    "unreadable-key": "UNSIGNED — the supplied signing material is not a readable Ed25519 private key, so no tree head was signed. " +
        "Nothing in this file can be verified.",
};
/**
 * Build the Studio's commitment block, or say precisely why there is none.
 *
 * Refuses to sign over a broken chain (TEAM-ADR-046: a signed tree head over
 * edited history attests the tampering). Total over its inputs — an operator
 * error becomes a printed refusal, never a thrown stack and never a silently
 * unsigned file that looks the same as a deliberate one.
 */
export function buildStudioEvidence(entries, nowIso, signWithPem) {
    if (entries === undefined)
        return { status: "unsigned", reason: "malformed-ledger" };
    if (entries.length === 0)
        return { status: "unsigned", reason: "empty-ledger" };
    if (!verifyChain(entries))
        return { status: "unsigned", reason: "chain-broken" };
    if (signWithPem === undefined)
        return { status: "unsigned", reason: "no-signing-key" };
    let privateKey;
    try {
        privateKey = createPrivateKey(signWithPem);
    }
    catch {
        // Deliberately generic: never echoes key bytes or a path (the
        // EvidenceMaterialError discipline in src/api/evidence.ts).
        return { status: "unsigned", reason: "unreadable-key" };
    }
    // A readable key of the WRONG algorithm is refused here rather than signed
    // with. `crypto.sign(null, …)` happily produces an RSA signature, which
    // would travel in an envelope the browser reads as Ed25519 — and the browser
    // would then report "this browser cannot check Ed25519 signatures", blaming
    // the reader's browser for the operator's key. Refuse at the source.
    if (privateKey.asymmetricKeyType !== "ed25519") {
        return { status: "unsigned", reason: "unreadable-key" };
    }
    const signedTreeHead = signTreeHead(entries.length, ledgerTreeHead(entries), nowIso, privateKey);
    const publicKey = createPublicKey(privateKey).export({
        type: "spki",
        format: "der",
    }).toString("base64");
    return {
        status: "signed",
        evidence: {
            signedTreeHead,
            publicKey,
            inclusion: entries.map((_, i) => proveLedgerInclusion(entries, i)),
        },
    };
}
