/**
 * The compliance compiler (TEAM-ADR-038): ledger + signed evidence export +
 * customer disclosures → one regulator-ready packet, deterministic and
 * signed.
 *
 * WHAT A PACKET IS. Evidence supporting the customer's OWN compliance
 * process. It is not a certification, an attestation, an audit opinion or a
 * legal conclusion, and every packet says so in `standing` — that wording is
 * the same shield that lets DeepSweep hold the record where an incumbent's
 * general counsel would not. Templates are DRAFT until counsel review; the
 * packet carries the template's `reviewStatus` verbatim so no consumer can
 * mistake a draft mapping for a reviewed one.
 *
 * WHAT IT CONTAINS. (1) the window; (2) counts — decisions, gateway actions,
 * approvals, distinct principals/servers/tools as hashes; (3) the timeline:
 * every ledger entry in the window, metadata only, with any VERIFIED
 * disclosure inlined next to the entry it reproduces; (4) refused
 * disclosures, listed; (5) the signed tree head + chain/signature coverage
 * facts a third party needs to verify the underlying export offline;
 * (6) the template's clause map. Signed Ed25519 over the canonical bytes.
 *
 * Determinism: `nowIso` injected; the same inputs produce the same bytes.
 */
import { createPublicKey, sign as edSign, verify as edVerify, createPrivateKey } from "node:crypto";
import { canonicalize } from "../review/canonical.js";
import { oracleWithheldKeys, readLedger, redactLedgerEntry, verifyChain } from "../review/ledger.js";
import { readLedgerSignatures } from "../review/ledger-sign.js";
import { keyIdFor } from "../review/bundle.js";
import { exportEvidenceBundle } from "../api/evidence.js";
import { verifyDisclosures } from "./disclosure.js";
import { loadTemplate } from "./templates.js";
export const PACKET_SCHEMA_VERSION = "compliance-packet.v1";
/** The standing every packet carries. Wording is contract (tests pin it). */
export const PACKET_STANDING = "This packet is evidence supporting the deploying organisation's own compliance process. " +
    "It is not a certification, attestation, audit opinion or legal conclusion, and DeepSweep makes no " +
    "representation as to regulatory outcome. Regulatory mappings carry their review status verbatim.";
function count(map, k) {
    map[k] = (map[k] ?? 0) + 1;
}
const VERIFY_INSTRUCTIONS = "Verify offline: run the DeepSweep `verify` capability on the evidence export with the pinned public key " +
    "(keyId above); recompute any disclosed value's SHA-256 (RFC 8785 canonical JSON for args/result) and compare " +
    "to the recorded digest in the timeline row.";
/** Build the packet body. Pure given the ledger; never throws on evidence grounds. */
/** May throw EvidenceMaterialError when `signWithPem` is not a readable Ed25519 key (same contract as `export`). */
export function compilePacket(p) {
    const entries = readLedger(p.workspaceRoot);
    if (entries === undefined)
        return { status: "unverifiable", reason: "ledger malformed — refusing to compile a packet over unreadable evidence", exitCode: 3 };
    const chainIntact = verifyChain(entries);
    const inWindow = entries.filter((e) => e.occurredAt >= p.window.fromIso && e.occurredAt <= p.window.toIso);
    const disclosures = verifyDisclosures(inWindow, p.disclosures ?? []);
    const disclosedByEntry = new Map();
    for (const d of disclosures.verified) {
        const cur = disclosedByEntry.get(d.entryHash) ?? {};
        cur[d.field] = d.value;
        disclosedByEntry.set(d.entryHash, cur);
    }
    const decisions = {};
    const gatewayActions = {};
    const principals = new Set();
    const servers = new Set();
    const tools = new Set();
    const rules = new Set();
    let granted = 0;
    let consumed = 0;
    const timeline = inWindow.map((e) => {
        const pl = e.payload;
        if (e.kind === "policy.decision") {
            count(decisions, String(pl["outcome"]));
            rules.add(String(pl["rule"]));
            principals.add(String(pl["principalHash"]));
        }
        if (e.kind === "gateway.tool_call") {
            count(gatewayActions, String(pl["action"]));
            servers.add(String(pl["serverHash"]));
            tools.add(String(pl["toolHash"]));
        }
        if (e.kind === "approval.granted")
            granted += 1;
        if (e.kind === "approval.consumed")
            consumed += 1;
        const disclosed = disclosedByEntry.get(e.entryHash);
        // TEAM-ADR-048 — EMISSION is the disclosure boundary, and this is where it
        // is applied rather than merely asserted (TEAM-ADR-047 §4 claimed this
        // control; `payload: pl` was a blanket passthrough of the raw payload,
        // which is how the workspace basename reached this packet once per row).
        //
        // `argsHash` is SHA-256 over the UNREDACTED tool arguments, and it must
        // stay that way: selective disclosure (disclosure.ts) recomputes the
        // digest from the customer's own plaintext, so a redacted preimage would
        // refuse every args disclosure as a mismatch. What changes is that the
        // digest is emitted only for a row whose args the customer CHOSE to
        // disclose — where the preimage is already in the reader's hands and the
        // digest is the thing that proves it. On every other row a guessable
        // argument list ({"path":"/etc/passwd"}) would be confirmable on the
        // first try, so the digest is withheld.
        // `resultHash` gets the SAME rule (issue #65, packet half): it is the
        // unkeyed digest of raw tool RESULT content, "result" is a disclosable
        // field (disclosure.ts), and a result with guessable shape ("", "ok",
        // an empty JSON object) is confirmable on the first try exactly like a
        // guessable argument list. Withholding was applied to argsHash alone —
        // the same oracle class, the same rationale, not applied.
        // TEAM-ADR-052: the rule itself now lives in ONE place (`oracleWithheldKeys`)
        // because the Studio emitter needs the same one, and two copies of a
        // withholding rule are two rules that can disagree.
        const withheld = oracleWithheldKeys(disclosed === undefined ? [] : Object.keys(disclosed));
        const projected = redactLedgerEntry(e, withheld);
        const row = { seq: e.seq, occurredAt: e.occurredAt, kind: e.kind, entryHash: e.entryHash, payload: projected.payload };
        return disclosed === undefined ? row : { ...row, disclosed };
    });
    const sigs = readLedgerSignatures(p.workspaceRoot);
    const signedEntries = sigs === undefined ? 0 : sigs.length;
    const bundle = exportEvidenceBundle({
        workspaceRoot: p.workspaceRoot,
        nowIso: p.nowIso,
        ...(p.signWithPem !== undefined ? { signWithPem: p.signWithPem } : {}),
        ...(p.workspaceLabel !== undefined ? { workspaceLabel: p.workspaceLabel } : {}),
    }).bundle;
    const ok = bundle.status === "ok";
    const integrity = {
        chainIntact,
        ledgerEntries: entries.length,
        signedEntries,
        signatureCoverage: signedEntries === 0 ? "none" : signedEntries >= entries.length ? "full" : "partial",
        treeSize: ok ? bundle.treeSize : null,
        root: ok ? bundle.root : null,
        signedTreeHead: ok && bundle.signedTreeHead !== undefined ? bundle.signedTreeHead : null,
        verifyInstructions: VERIFY_INSTRUCTIONS,
    };
    const body = {
        schemaVersion: PACKET_SCHEMA_VERSION,
        template: loadTemplate(p.templateId),
        standing: PACKET_STANDING,
        generatedAt: p.nowIso,
        workspace: ok ? bundle.workspace : "",
        window: p.window,
        counts: {
            entries: inWindow.length,
            decisions,
            gatewayActions,
            approvalsGranted: granted,
            approvalsConsumed: consumed,
            principals: principals.size,
            servers: servers.size,
            tools: tools.size,
            rulesFired: [...rules].sort(),
        },
        timeline,
        disclosures,
        integrity,
    };
    if (p.signWithPem === undefined)
        return { status: "ok", packet: { packet: body }, exitCode: 0 };
    // exportEvidenceBundle above already refused unreadable material with EvidenceMaterialError.
    const priv = createPrivateKey(p.signWithPem);
    const pub = createPublicKey(priv);
    return {
        status: "ok",
        exitCode: 0,
        packet: {
            packet: body,
            signature: edSign(null, Buffer.from(canonicalize(body), "utf8"), priv).toString("base64"),
            keyId: keyIdFor(pub),
        },
    };
}
function parsePinned(material) {
    try {
        return material.includes("BEGIN PUBLIC KEY")
            ? createPublicKey(material)
            : createPublicKey({ key: Buffer.from(material, "base64"), format: "der", type: "spki" });
    }
    catch {
        return undefined;
    }
}
/** The auditor's side: is this packet the one the pinned key signed? Fail-closed. */
export function verifyPacket(doc, trustedKeys) {
    if (typeof doc !== "object" || doc === null || Array.isArray(doc))
        return { ok: false, reason: "malformed-envelope" };
    const d = doc;
    const body = d["packet"];
    if (typeof body !== "object" || body === null)
        return { ok: false, reason: "malformed-envelope" };
    if (typeof d["signature"] !== "string" || typeof d["keyId"] !== "string")
        return { ok: false, reason: "unsigned" };
    const pinned = trustedKeys.find((k) => k.keyId === d["keyId"]);
    if (pinned === undefined)
        return { ok: false, reason: "unknown-key" };
    const key = parsePinned(pinned.publicKey);
    if (key === undefined)
        return { ok: false, reason: "malformed-key" };
    let good = false;
    try {
        good = edVerify(null, Buffer.from(canonicalize(body), "utf8"), key, Buffer.from(d["signature"], "base64"));
    }
    catch {
        good = false;
    }
    return good ? { ok: true, keyId: d["keyId"] } : { ok: false, reason: "bad-signature" };
}
