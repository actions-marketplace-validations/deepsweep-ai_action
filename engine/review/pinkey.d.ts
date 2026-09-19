/** Environment variable carrying explicit key material (hex). */
export declare const PIN_KEY_ENV = "DEEPSWEEP_PIN_KEY";
/** Environment variable overriding the out-of-workspace state directory. */
export declare const PIN_STATE_DIR_ENV = "DEEPSWEEP_STATE_DIR";
/** File name of the generated key inside the state directory. */
export declare const PIN_KEY_FILE = "pin-key";
/** Minimum accepted key length in hex characters (32 bytes). */
export declare const PIN_KEY_MIN_HEX = 64;
/** Domain-separation labels — one namespace per pinned identity kind. */
export declare const PIN_DOMAIN: {
    readonly mcpServer: "deepsweep/pin/mcpServer/v1";
    readonly toolDescription: "deepsweep/pin/toolDescription/v1";
    readonly agentId: "deepsweep/pin/agentId/v1";
    /** TEAM-ADR-048 — the workspace LABEL that replaces the published basename. */
    readonly workspaceLabel: "deepsweep/pin/workspaceLabel/v1";
};
export interface PinKey {
    /** 32 raw bytes. NEVER rendered, logged, exported, or hashed into output. */
    readonly material: Buffer;
    /** Non-secret 16-hex label recorded in the baseline / identity store. */
    readonly keyId: string;
    /** false when no durable key store was reachable (ephemeral, per-process). */
    readonly durable: boolean;
}
/** Raised only for an operator-supplied key that cannot be used as given. */
export declare class PinKeyError extends Error {
    constructor(message: string);
}
export declare function resolvePinKey(): PinKey;
/**
 * The ONE pinned-identity digest. Domain-separated so an mcpServer preimage
 * can never collide with a toolDescription or agentId preimage under the same
 * key. Output shape is unchanged from the SHA-256 it replaces (64 lowercase
 * hex), so every schema, regex and store validator still holds.
 */
export declare function pinHash(key: PinKey, domain: string, canonicalText: string): string;
/** Constant-time keyId comparison (the id is public; the habit is free). */
export declare function sameKeyId(a: string, b: string): boolean;
