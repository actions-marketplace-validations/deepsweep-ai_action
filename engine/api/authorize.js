/**
 * Engine library — `authorize` capability (TEAM-ADR-027).
 *
 * MOVED here from the `deepsweep authorize` command layer, where the layered
 * policy load, the evaluation, the ADR-010 enforcement mapping and the
 * ADR-018 ledger append used to live inline. The Studio (over Tauri IPC), the
 * headless sidecar and the legacy CLI shim now share this one implementation,
 * so an explained decision cannot drift between surfaces.
 *
 * Identity discipline (ADR-005): `principal` is a neutral identifier carried
 * through to the evaluator. It is never compared to a magic value here — the
 * CLI's "none" sentinel is parsed at its composition root and arrives as null.
 */
import { resolve } from "node:path";
import { loadLayeredPolicy } from "../review/policy.js";
import { evaluate } from "../review/evaluate.js";
import { enforcementEffectFor } from "../review/enforce.js";
import { appendLedgerEntry } from "../review/ledger.js";
import { sha256Hex } from "../review/canonical.js";
import { appendLedgerSignature, signLedgerEntry } from "../review/ledger-sign.js";
import { resolveClasses } from "../packs/bindings.js";
/** Marker used when no rule matched and the policy's defaultEffect decided. */
export const DEFAULT_EFFECT_RULE_LABEL = "(none — defaultEffect)";
/**
 * Evaluate ONE policy decision and record it. Deterministic: posture,
 * attestation and drift enter at their bases so the answer is a pure function
 * of the policy layers and the query — never of transient workspace state.
 *
 * May throw PolicyRefusalError / LedgerRefusalError on `.deepsweep/`
 * containment violations (ADR-003 refusal class → exit 3 at the edges).
 */
export function authorizeAction(params) {
    const root = resolve(params.workspaceRoot);
    const layered = loadLayeredPolicy(root, params.userConfigRoot !== undefined ? { userConfigRoot: params.userConfigRoot } : {});
    const refusals = layered.refusals.map((r) => ({
        layer: r.layer,
        source: r.source,
        reason: r.reasons[0] ?? "nonconforming",
    }));
    // TEAM-ADR-041: classify the tool through the installed packs' bindings.
    // Bindings travel INSIDE the signed pack, so a classification is exactly as
    // trustworthy as the rules it makes effective.
    const bindings = layered.packs.flatMap((p) => [...p.bindings]);
    const classification = params.tool !== undefined && bindings.length > 0
        ? resolveClasses(bindings, params.tool.toolName, params.tool.descriptionHash)
        : null;
    const decision = evaluate(layered.policy, {
        principal: params.principal,
        agentType: null,
        action: params.action,
        resource: params.resource,
        // A pure policy query: posture/attestation/drift enter at their bases.
        postureScore: 100,
        attestation: "claimed",
        driftOutstanding: false,
        ...(classification !== null ? { resourceAliases: classification.aliases } : {}),
    });
    // A refused PRIMARY layer (org/workspace) poisons the whole evaluation:
    // ADR-010 maps it to the safe default, never to allow.
    const primaryRefused = layered.refusals.some((r) => r.layer !== "user");
    const acted = enforcementEffectFor(decision.outcome, primaryRefused ? "invalid" : "ok");
    const ruleLabel = decision.policyRef === null ? DEFAULT_EFFECT_RULE_LABEL : decision.policyRef.name;
    const packLabels = layered.packs.map((p) => `${p.packId}@${p.version}#${p.bundleVersion}:${p.keyId}`);
    // ADR-018/ADR-021: HASHES + outcome only — a cloud-bound record never
    // carries principal/action/resource VALUES (metadata-first invariant).
    // TEAM-ADR-041 adds, ONLY when present, closed-enum labels (taxonomy classes,
    // classification confidence, pack provenance) — the same kind of metadata as
    // `rule` and `mode`, never a name, argument or content; the payload is
    // byte-identical to pre-041 when no pack is installed. Binding IDS stay
    // in-process (AuthorizeResult.classification.bindings): they would name the
    // vendor class the customer runs, which the hash-only record never did.
    const appended = appendLedgerEntry(root, "policy.decision", {
        principalHash: sha256Hex(decision.principal ?? ""),
        actionHash: sha256Hex(decision.action),
        resourceHash: sha256Hex(decision.resource),
        outcome: decision.outcome,
        rule: ruleLabel,
        mode: layered.mode,
        ...(packLabels.length > 0 ? { packs: packLabels.join(",") } : {}),
        ...(classification !== null ? { classes: classification.classes.join(","), classification: classification.confidence } : {}),
    }, params.nowIso);
    if (appended !== "corrupt" && params.key !== undefined) {
        appendLedgerSignature(root, signLedgerEntry(appended, params.key));
    }
    const enforcing = layered.mode === "enforce";
    return {
        principal: decision.principal,
        action: decision.action,
        resource: decision.resource,
        explanation: decision.explanation,
        layersLoaded: layered.layersLoaded,
        mode: layered.mode,
        ruleLabel,
        outcome: decision.outcome,
        actedOn: enforcing ? acted : null,
        refusals,
        ledgerAppended: appended !== "corrupt",
        exitCode: enforcing ? (acted === "allow" ? 0 : acted === "require-approval" ? 3 : 4) : 0,
        classification,
        packs: packLabels,
    };
}
