/**
 * The kill switch — one file stops every governed tool call (2026-09-17).
 *
 * The sales-claim audit of 2026-09-17 found no mechanism behind the brief's
 * "a kill switch you hold stops every agent" — the only switches were
 * network/telemetry. This module is that mechanism, scoped honestly: it
 * stops every tool call that flows through a DeepSweep gateway. An agent
 * whose traffic is not routed through the gateway is not stopped by it,
 * and no copy may say otherwise.
 *
 * Mechanics, chosen for the operator under pressure:
 *   - Activation is a FILE (`.deepsweep/killswitch`), not a network call —
 *     it works with the vendor unreachable, which is the point of holding
 *     it yourself. The workspace file stops one workspace; the user-config
 *     file stops every workspace that gateway serves for this user.
 *   - FAIL CLOSED: a killswitch file that exists but cannot be read counts
 *     as ACTIVE (the pin-store precedent: an unreadable safety store never
 *     degrades to permissive).
 *   - State transitions land on the ledger (`gateway.killswitch`), so the
 *     evidence bundle shows when the switch was thrown and by whom (named,
 *     unauthenticated — the TEAM-ADR-053 honesty discipline applies).
 *   - The switch is a file the agent's own OS user can create or delete, so
 *     a transition can happen without either command. At every decision the
 *     gateway compares the state it observes with the last state the ledger
 *     recorded and, when they differ, records the observed state first
 *     (TEAM-ADR-069 Decision 3): `via: "observed"`, no actor, because nobody
 *     is known to have done it. It is recorded when observed, not when it
 *     happened, and a change undone between two decisions is not seen.
 *   - The DRILL activates, proves a synthetic call is actually refused,
 *     restores the prior state, and writes `gateway.killswitch_drill` with
 *     the measured outcome — evidence that the switch works, dated, in the
 *     exportable ledger. A drill that fails to get a refusal says so and
 *     exits non-zero; it never records success it did not observe.
 */
import { existsSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { appendSignedEntry } from "./record.js";
export const KILLSWITCH_RELPATH = join(".deepsweep", "killswitch");
function probeFile(path) {
    try {
        if (!existsSync(path))
            return "absent";
        statSync(path);
        readFileSync(path);
        return "present";
    }
    catch {
        // It exists (or existence itself is unknowable) and cannot be read:
        // fail toward stopped, never toward forwarding.
        return "unreadable";
    }
}
/** Pure read of the switch. Workspace file or user-config file — either stops the gateway. */
export function killswitchState(workspaceRoot, userConfigRoot) {
    const ws = probeFile(join(workspaceRoot, KILLSWITCH_RELPATH));
    if (ws === "unreadable")
        return { active: true, source: "unreadable" };
    if (ws === "present")
        return { active: true, source: "workspace" };
    if (userConfigRoot !== undefined) {
        const us = probeFile(join(userConfigRoot, "killswitch"));
        if (us === "unreadable")
            return { active: true, source: "unreadable" };
        if (us === "present")
            return { active: true, source: "user" };
    }
    return { active: false };
}
function record(workspaceRoot, kind, payload, nowIso, key) {
    return appendSignedEntry(workspaceRoot, kind, payload, nowIso, key);
}
/**
 * The switch state the ledger last recorded, given its newest
 * `gateway.killswitch` entry (command or observed). No entry means "off",
 * because the switch starts off (TEAM-ADR-069 Decision 3). A state this
 * engine never writes is "unrecognised", which matches no observed state, so
 * the gateway records what it actually observes.
 */
export function recordedKillswitchState(newest) {
    if (newest === undefined)
        return "off";
    const state = newest.payload["state"];
    return state === "on" || state === "off" ? state : "unrecognised";
}
/**
 * The payload of a state change the gateway OBSERVED rather than performed
 * (TEAM-ADR-069 Decision 3). Closed codes only: the state, `via: "observed"`,
 * and which switch file holds it ("none" when off). No `actor`: a command
 * entry names the actor it was given, and an observed change has none, so it
 * can never read as an operator's command.
 */
export function observedKillswitchPayload(state) {
    return state.active
        ? { state: "on", via: "observed", switchFile: state.source }
        : { state: "off", via: "observed", switchFile: "none" };
}
/** Throw the switch. Idempotent; the ledger records every throw. */
export function activateKillswitch(workspaceRoot, actor, nowIso, key) {
    writeFileSync(join(workspaceRoot, KILLSWITCH_RELPATH), `${JSON.stringify({ activatedAt: nowIso, actor })}\n`);
    return record(workspaceRoot, "gateway.killswitch", { state: "on", actor }, nowIso, key);
}
/** Resume. Removing the file is the ONLY way back — there is no override flag. */
export function deactivateKillswitch(workspaceRoot, actor, nowIso, key) {
    rmSync(join(workspaceRoot, KILLSWITCH_RELPATH), { force: true });
    return record(workspaceRoot, "gateway.killswitch", { state: "off", actor }, nowIso, key);
}
/**
 * Prove the switch works, with evidence. `probe` is the caller-supplied
 * check that a governed call is refused while the switch is active — the
 * host wires it to a real `decideFrame` on a synthetic tools/call so the
 * drill exercises the exact production refusal path, not a lookalike.
 */
export function runKillswitchDrill(workspaceRoot, actor, nowIso, probe, elapse, key) {
    const wasActive = killswitchState(workspaceRoot).active;
    const started = elapse();
    activateKillswitch(workspaceRoot, `${actor} (drill)`, nowIso, key);
    const refused = probe();
    const elapsedMs = Math.max(0, elapse() - started);
    if (!wasActive)
        deactivateKillswitch(workspaceRoot, `${actor} (drill)`, nowIso, key);
    const outcome = refused ? "refused" : "NOT_REFUSED";
    const ledger = record(workspaceRoot, "gateway.killswitch_drill", { outcome, elapsedMs, actor, restored: wasActive ? "left-active" : "inactive" }, nowIso, key);
    return { outcome, elapsedMs, restored: wasActive ? "left-active" : "inactive", ledger, exitCode: refused ? 0 : 5 };
}
