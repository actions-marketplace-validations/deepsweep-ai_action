/**
 * The gateway's ONE bare-stream plumbing site (TEAM-ADR-036; census in
 * tests/sanitize.test.ts pins its exact text, exactly as watch.ts's writeLine
 * is pinned).
 *
 * WHY THIS IS NOT A RENDER SURFACE. The S1.9 render-boundary guard exists
 * because every string the engine WRITES for a human or a machine to read is
 * a place attacker-influenced content could escape unsanitized. A transparent
 * proxy is different in kind: it RELAYS bytes it received from one party to
 * the other party, unchanged. Sanitizing a relayed JSON-RPC frame would be
 * mutation — precisely the behaviour the gateway must never exhibit (an
 * observe/enforce/record layer that alters agent or tool traffic is a
 * different legal and product posture, see the ADR). So the relay writes RAW,
 * and the guard's protection is preserved by construction: this is the only
 * module allowed a bare `.write(`, and every write is a frame that was
 * already on the wire (or a gateway error frame built by frames.ts from
 * static text + shape-only data). Nothing here is ever a review finding.
 */
import type { Writable } from "node:stream";
/** Relay one already-received line, newline-terminated. Back-pressure is left to the stream (frames are small). */
export declare function relayLine(stream: Writable, line: string): void;
/** Relay an already-received body buffer VERBATIM (no newline) — the HTTP transport's request/response bytes.
 *  Same contract as relayLine: bytes we received from one party, passed to the other unchanged. */
export declare function relayChunk(stream: Writable, chunk: Buffer): void;
