/**
 * The workspace LABEL — the one derivation of the value that identifies a
 * workspace in anything this engine emits (TEAM-ADR-048).
 *
 * WHY THIS MODULE EXISTS. Until now every surface re-derived
 * `basename(resolve(workspaceRoot))` at its own call site — eight independent
 * derivations plus a ninth inside the review.run ledger payload — and shipped
 * that basename in CLEARTEXT into artifacts a customer hands to a third
 * party: the evidence bundle (top level AND every record), the compliance
 * packet (once per timeline row), the Governance Studio artifact, the
 * `--watch --json` drift-event stream. A repo basename is the client's
 * product name. A regulated buyer — a hospital EHR vendor, a claims
 * processor, a licensed money transmitter — reads that as information
 * disclosure and stops reading.
 *
 * Deleting the field would not have closed it: for a `review.run` record the
 * evidence exporter feeds the SAME basename into `resourceHash`, so the
 * digest and its plaintext preimage were published side by side. There was no
 * oracle to attack. Changing the VALUE is what closes both.
 *
 * THE TWO PATHS.
 *  1. CLIENT-SUPPLIED LABEL. The neutral engagement name the customer wants
 *     on the artifact ("engagement-4417"). Supplied per call, or through
 *     `DEEPSWEEP_WORKSPACE_LABEL` for every surface at once. Shape-validated
 *     and REFUSED loudly when it is not a bare label — never silently
 *     replaced with the derived value, because a silent fallback is how a
 *     basename reaches a published artifact while an operator believes it
 *     cannot.
 *  2. SALTED-HASH DEFAULT. With no label supplied, the value is
 *     `ws_` + HMAC-SHA256(salt, domain || basename), truncated to 16 hex.
 *
 * THE SALT, and why it is the pin key. The salt is the out-of-workspace key
 * material `pinkey.ts` already resolves (`DEEPSWEEP_PIN_KEY`, else
 * `<state dir>/pin-key`, else per-process ephemeral). It is RECORDED — as its
 * non-secret `pinKeyId` in `.deepsweep/baseline.json` and
 * `.deepsweep/identity.json`, which is how a run knows the stored labels are
 * its own — and it is never itself published. Consequences, which are the
 * properties this fix owes:
 *  - STABLE within an artifact, and across the artifacts of one installation,
 *    so records still correlate to each other and to the packet and event
 *    stream compiled beside them.
 *  - UNCORRELATABLE across clients: two installations hold independent
 *    256-bit keys, so the same basename yields unrelated labels.
 *  - NOT an oracle. The salt is never emitted, so a holder of the artifact
 *    cannot confirm a guessed basename — which a salt PUBLISHED beside the
 *    digest would let them do on the first try. That is the whole reason the
 *    salt is a key rather than a nonce carried in the bundle.
 *
 * WHAT THIS IS NOT. It is not anonymity: a client who tells a buyer which
 * engagement a bundle belongs to has disclosed it, deliberately, which is the
 * point. It is not a tamper control. And it is not a confidentiality claim
 * over anything else in the artifact — `sanitize.ts` remains an INJECTION
 * control (strip set + length cap) and has never redacted anything.
 *
 * Determinism: no clock, no randomness of its own. Same key + same basename
 * (or same supplied label) → same bytes, which the byte-stable export
 * contract requires.
 */
import { basename, resolve } from "node:path";
import { PIN_DOMAIN, pinHash, resolvePinKey } from "./pinkey.js";
/** Environment variable carrying an explicit label for every surface. */
export const WORKSPACE_LABEL_ENV = "DEEPSWEEP_WORKSPACE_LABEL";
/** Prefix that marks a DERIVED label, so a reader never mistakes it for a name. */
export const WORKSPACE_LABEL_PREFIX = "ws_";
/** Hex characters kept from the HMAC (64 bits — a label, not a digest). */
export const WORKSPACE_LABEL_HEX_LENGTH = 16;
/** Maximum accepted length of a client-supplied label. */
export const WORKSPACE_LABEL_MAX_LENGTH = 64;
/**
 * Accepted shape for a client-supplied label: letters, digits, dot, dash,
 * underscore, first character alphanumeric. Deliberately excludes `/`, `\`,
 * `:` and whitespace, so a supplied label can never be a path, a URL
 * authority, or a value that changes how any renderer frames it.
 */
export const WORKSPACE_LABEL_SHAPE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
/** Raised only for a supplied label that cannot be used as given. */
export class WorkspaceLabelError extends Error {
    constructor(message) {
        super(message);
        this.name = "WorkspaceLabelError";
    }
}
/**
 * Validate a client-supplied label, or REFUSE. Never falls back to the
 * derived value: an operator who typed a label wrong must find out, not
 * discover later that the artifact carries a hash they did not expect.
 */
export function checkWorkspaceLabel(supplied) {
    const label = supplied.trim();
    if (label.length > WORKSPACE_LABEL_MAX_LENGTH || !WORKSPACE_LABEL_SHAPE.test(label)) {
        throw new WorkspaceLabelError(`workspace label must be 1-${WORKSPACE_LABEL_MAX_LENGTH} characters of letters, digits, dot, dash or underscore, starting alphanumeric — a path, URL or blank value is refused rather than silently replaced`);
    }
    return label;
}
/**
 * The salted-hash default. Exported so a test can assert the artifact's value
 * IS this function's output and nothing else.
 */
export function derivedWorkspaceLabel(workspaceRoot) {
    const digest = pinHash(resolvePinKey(), PIN_DOMAIN.workspaceLabel, basename(resolve(workspaceRoot)));
    return `${WORKSPACE_LABEL_PREFIX}${digest.slice(0, WORKSPACE_LABEL_HEX_LENGTH)}`;
}
/**
 * THE derivation. Every surface that needs to name a workspace calls this and
 * nothing else — the count of `basename(` calls outside this module is the
 * regression guard (tests/workspace-label-gate.test.ts).
 *
 * @param workspaceRoot absolute or relative workspace root.
 * @param supplied optional client label; falls back to
 *   `DEEPSWEEP_WORKSPACE_LABEL`, then to the salted hash.
 */
export function workspaceLabel(workspaceRoot, supplied) {
    const explicit = (supplied ?? process.env[WORKSPACE_LABEL_ENV] ?? "").trim();
    return explicit === "" ? derivedWorkspaceLabel(workspaceRoot) : checkWorkspaceLabel(explicit);
}
