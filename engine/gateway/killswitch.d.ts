import { type LedgerEntry } from "../review/ledger.js";
import { type LedgerSigningKey } from "../review/ledger-sign.js";
export declare const KILLSWITCH_RELPATH: string;
export type KillswitchState = {
    readonly active: false;
} | {
    readonly active: true;
    readonly source: "workspace" | "user" | "unreadable";
};
/** Pure read of the switch. Workspace file or user-config file — either stops the gateway. */
export declare function killswitchState(workspaceRoot: string, userConfigRoot?: string): KillswitchState;
/**
 * The switch state the ledger last recorded, given its newest
 * `gateway.killswitch` entry (command or observed). No entry means "off",
 * because the switch starts off (TEAM-ADR-069 Decision 3). A state this
 * engine never writes is "unrecognised", which matches no observed state, so
 * the gateway records what it actually observes.
 */
export declare function recordedKillswitchState(newest: LedgerEntry | undefined): "on" | "off" | "unrecognised";
/**
 * The payload of a state change the gateway OBSERVED rather than performed
 * (TEAM-ADR-069 Decision 3). Closed codes only: the state, `via: "observed"`,
 * and which switch file holds it ("none" when off). No `actor`: a command
 * entry names the actor it was given, and an observed change has none, so it
 * can never read as an operator's command.
 */
export declare function observedKillswitchPayload(state: KillswitchState): Record<string, string>;
/** Throw the switch. Idempotent; the ledger records every throw. */
export declare function activateKillswitch(workspaceRoot: string, actor: string, nowIso: string, key?: LedgerSigningKey): LedgerEntry | "corrupt";
/** Resume. Removing the file is the ONLY way back — there is no override flag. */
export declare function deactivateKillswitch(workspaceRoot: string, actor: string, nowIso: string, key?: LedgerSigningKey): LedgerEntry | "corrupt";
export interface DrillResult {
    readonly outcome: "refused" | "NOT_REFUSED";
    readonly elapsedMs: number;
    readonly restored: "inactive" | "left-active";
    readonly ledger: LedgerEntry | "corrupt";
    readonly exitCode: 0 | 5;
}
/**
 * Prove the switch works, with evidence. `probe` is the caller-supplied
 * check that a governed call is refused while the switch is active — the
 * host wires it to a real `decideFrame` on a synthetic tools/call so the
 * drill exercises the exact production refusal path, not a lookalike.
 */
export declare function runKillswitchDrill(workspaceRoot: string, actor: string, nowIso: string, probe: () => boolean, elapse: () => number, key?: LedgerSigningKey): DrillResult;
