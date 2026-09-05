import { type StudioInput } from "./studio.js";
import { type SurfaceContext } from "./surface.js";
/** The sanctioned cloud-plane bases (founder directive; health-verified). */
export declare const API_BASE = "https://api.deepsweep.ai/v1";
export declare const API_BASE_DEV = "https://api-dev.deepsweep.ai/v1";
export interface StudioServerOptions {
    initialRoot: string;
    toolVersion: string;
    userConfigRoot?: string;
    /** Injectable for deterministic tests; defaults to a random session token. */
    token?: string;
    /** Injectable clock (determinism in tests). */
    now?: () => Date;
    port?: number;
    /**
     * TEAM-ADR-030 — the surface this server renders FOR, resolved once by the
     * composition root that started it (`resolveSurface`). Omitted → 'web',
     * which is correct for the served Studio and is the fail-closed default
     * everywhere else. This server never resolves the surface itself: it has
     * no access to the client's bootstrap signals, and `serve` mode is NOT a
     * surface signal — the desktop app serves too.
     */
    surfaceContext?: SurfaceContext;
    /**
     * TEAM-ADR-052 — Ed25519 PKCS8 PEM the served artifact's tree head is signed
     * with. Absent = an UNSIGNED artifact that says so, which is the true state
     * until the signing ceremony happens.
     */
    signWithPem?: string;
}
export interface StudioServer {
    readonly url: string;
    readonly port: number;
    readonly token: string;
    close(): Promise<void>;
}
/** Assemble a StudioInput by running one review over `root` (appends one
 * ledger entry — callers cache the result; see GET idempotence above).
 *
 * TEAM-ADR-052: `signWithPem` is the Ed25519 material the artifact's tree head
 * is signed with. Absent — the true state today, the signing ceremony has not
 * happened — the artifact is UNSIGNED and says so; it never downgrades to a
 * self-consistency check dressed up as verification. */
export declare function assembleStudioInput(root: string, toolVersion: string, userConfigRoot: string | undefined, now: (() => Date) | undefined, signWithPem?: string): StudioInput;
export declare function startStudioServer(options: StudioServerOptions): Promise<StudioServer>;
