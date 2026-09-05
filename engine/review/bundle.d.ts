/**
 * ADR-016 — policy-bundle signing and verification (Ed25519, node:crypto
 * only — zero third-party packages, per the runtime-dependency invariant).
 *
 * A SEALED bundle is the distribution envelope for policy:
 *   { bundle: { schemaVersion, bundleVersion, policy }, signature, keyId }
 * The signature is Ed25519 over the CANONICAL bytes of `bundle`
 * (canonicalize() — the same total, sorted, deterministic serialization the
 * pin/identity hashing already uses), so byte-stability is inherited and
 * re-serialization cannot break verification.
 *
 * FAIL-CLOSED CONTRACT: verifyBundle returns ok:false on ANY failure — bad
 * signature, unknown keyId, malformed envelope, malformed key, downgraded
 * (replayed) bundleVersion — and callers must land in the same posture as
 * an invalid policy: zero rules contributed, whole-set refusal surfaced
 * loudly, advisory default-observe, acted-on require-approval/deny
 * (ADR-009/ADR-010). Refusal reasons carry SHAPE ONLY: key ids, version
 * numbers, and failure classes — never key material or bundle content.
 *
 * Replay protection: `bundleVersion` is a strictly-monotonic integer. A
 * verifier refuses any bundle whose version is BELOW the floor it is given —
 * the floor is the LOWEST ACCEPTABLE version: the last ACCEPTED bundle (the
 * caller persists that high-water mark) or the operator's `minBundleVersion`
 * in the trusted-keys config, whichever is higher; the config floor holds
 * even if the agent-writable high-water store is destroyed. Re-reading the
 * currently accepted bundle is NOT a replay (TEAM-ADR-041 amendment to
 * ADR-016 §5: the original `<=` made every sealed policy refuse on its
 * second load, and ADR-016's own rotation runbook — "raise minBundleVersion
 * to that version" — only works with an inclusive floor).
 *
 * Sync API choice: the KeyObject sign/verify API (crypto.sign(null, …)) is
 * used rather than webcrypto.subtle — same Ed25519 curve, but synchronous
 * (the engine is synchronous throughout) and stable since Node 12, while
 * subtle's Ed25519 was still stabilizing across Node 18–20. Both live in
 * node:crypto; nothing third-party.
 */
import { type KeyObject } from "node:crypto";
export declare const BUNDLE_SCHEMA_VERSION = 1;
/** The signed payload. `policy` is validated separately AFTER verification. */
export interface PolicyBundle {
    readonly schemaVersion: typeof BUNDLE_SCHEMA_VERSION;
    /** Strictly monotonic release counter — the replay floor input. */
    readonly bundleVersion: number;
    /** The policy document (ADR-009 schema; validated post-verification). */
    readonly policy: unknown;
}
/** The distribution envelope. */
export interface SealedBundle {
    readonly bundle: PolicyBundle;
    /** Ed25519 signature over canonicalize(bundle), base64. */
    readonly signature: string;
    /** "dsk_" + first 16 hex of SHA-256(SPKI DER) of the signing public key. */
    readonly keyId: string;
}
/** A trusted verification key as pinned in workspace config. */
export interface TrustedKey {
    readonly keyId: string;
    /** SPKI PEM (or base64 DER) Ed25519 public key. */
    readonly publicKey: string;
}
export type BundleRefusalReason = "malformed-envelope" | "unknown-key" | "malformed-key" | "key-id-mismatch" | "bad-signature" | "replayed-version";
export type BundleVerification = {
    readonly ok: true;
    readonly bundle: PolicyBundle;
    readonly keyId: string;
} | {
    readonly ok: false;
    readonly reason: BundleRefusalReason;
    readonly detail: string;
};
/**
 * Pinned trust config — the SHAPE `policy-keys.json` (ADR-016) and
 * `pack-keys.json` (TEAM-ADR-041) share: `{ schemaVersion: 1, keys: [{keyId,
 * publicKey}], minBundleVersion? }`. Parsed in ONE place so the two trust
 * files can never drift in what they accept. `minBundleVersion` is the
 * operator-managed replay floor that survives destruction of the
 * agent-writable high-water store.
 */
export interface TrustConfig {
    readonly keys: readonly TrustedKey[];
    readonly minBundleVersion: number;
}
/** Parse trust-config TEXT. `"malformed"` is a typed refusal — callers must fail closed on it. */
export declare function parseTrustConfig(text: string): TrustConfig | "malformed";
/** Derive the pinnable key id from a public key. */
export declare function keyIdFor(publicKey: KeyObject): string;
/** Seal a bundle: sign its canonical bytes, attach signature + keyId. */
export declare function sealBundle(bundle: PolicyBundle, privateKey: KeyObject): SealedBundle;
/**
 * Verify a sealed bundle against the pinned trust set and the replay floor.
 * Total over arbitrary runtime input; EVERY failure is a typed refusal.
 * `floor` is the lowest acceptable bundleVersion (0 = nothing accepted yet):
 * a verified bundle must be AT OR ABOVE it — the currently accepted bundle
 * re-verifies; anything older is a replay.
 */
export declare function verifyBundle(sealed: unknown, trustedKeys: readonly TrustedKey[], floor: number): BundleVerification;
