/** Relay one already-received line, newline-terminated. Back-pressure is left to the stream (frames are small). */
export function relayLine(stream, line) {
    stream.write(`${line}\n`);
}
/** Relay an already-received body buffer VERBATIM (no newline) — the HTTP transport's request/response bytes.
 *  Same contract as relayLine: bytes we received from one party, passed to the other unchanged. */
export function relayChunk(stream, chunk) {
    stream.write(chunk);
}
