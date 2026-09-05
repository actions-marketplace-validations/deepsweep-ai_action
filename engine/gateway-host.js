/**
 * DeepSweep evidence gateway — process entrypoint (TEAM-ADR-036).
 *
 * Coverage note (vitest.config.ts): like src/engine-host.ts this file is
 * argv/stdin/stdout/exit plumbing and the ONE sanctioned ambient-clock read
 * for the gateway; every behavioural decision lives in src/gateway/*, which
 * is unit-tested. Covered at the real process boundary by tests/gateway/.
 *
 * Usage:
 *   deepsweep-gateway stdio --name <server> [--workspace <dir>] [--principal <id>] -- <command> [args…]
 *   deepsweep-gateway approve <token> [--workspace <dir>] [--approver <who>]
 *   deepsweep-gateway revoke <token> [--workspace <dir>] [--revoker <who>]
 *   deepsweep-gateway repin --name <server> --tool <tool> [--workspace <dir>] [--approver <who>]
 *   deepsweep-gateway http --name <server> --upstream <url> [--host 127.0.0.1] [--port 0] [--workspace <dir>] [--principal <id>] [--key-file <pem>]
 * Key: --key-file <path to Ed25519 PKCS8 PEM> → per-entry signatures; absent =
 * unsigned (recorded honestly as such). The path is host-provided and MUST
 * live outside `.deepsweep/` (the store is where the agent already is); the
 * engine never reads its own environment (ADR-005 F1 guard).
 */
import { createPrivateKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { renderCanonicalJson, renderNoticeLine } from "./review/report.js";
import { approveToken, revokeToken } from "./gateway/approval.js";
import { startStdioGateway } from "./gateway/stdio.js";
import { startHttpGateway } from "./gateway/http.js";
import { repinTool } from "./gateway/toolpins.js";
import { hostInjectedKey } from "./review/ledger-sign.js";
function flag(argv, name) {
    const i = argv.indexOf(name);
    return i >= 0 ? argv[i + 1] : undefined;
}
function keyFromArgv(argv) {
    const file = flag(argv, "--key-file");
    if (file === undefined)
        return undefined;
    return hostInjectedKey(createPrivateKey(readFileSync(resolve(file), "utf8")), "host-injected");
}
const argv = process.argv.slice(2);
const verb = argv[0];
const workspace = resolve(flag(argv, "--workspace") ?? process.cwd());
if (verb === "stdio") {
    const sep = argv.indexOf("--");
    const cmd = sep >= 0 ? argv.slice(sep + 1) : [];
    const name = flag(argv, "--name");
    if (name === undefined || cmd.length === 0) {
        process.stderr.write("usage: deepsweep-gateway stdio --name <server> [--workspace <dir>] [--principal <id>] -- <command> [args...]\n");
        process.exit(1);
    }
    const gw = startStdioGateway({
        workspaceRoot: workspace,
        serverName: name,
        command: cmd[0],
        args: cmd.slice(1),
        principal: flag(argv, "--principal") ?? null,
        agentIn: process.stdin,
        agentOut: process.stdout,
        now: () => new Date(),
        key: keyFromArgv(argv),
        diag: (l) => console.error(renderNoticeLine(l)),
    });
    void gw.done.then((code) => process.exit(code ?? 0));
}
else if (verb === "http") {
    const name = flag(argv, "--name");
    const upstream = flag(argv, "--upstream");
    if (name === undefined || upstream === undefined) {
        process.stderr.write("usage: deepsweep-gateway http --name <server> --upstream <url> [--host 127.0.0.1] [--port 0] [--workspace <dir>] [--principal <id>] [--key-file <pem>]\n");
        process.exit(1);
    }
    const portStr = flag(argv, "--port");
    void startHttpGateway({
        workspaceRoot: workspace,
        serverName: name,
        upstreamUrl: upstream,
        principal: flag(argv, "--principal") ?? null,
        host: flag(argv, "--host") ?? "127.0.0.1",
        port: portStr !== undefined ? Number(portStr) : 0,
        now: () => new Date(),
        key: keyFromArgv(argv),
        diag: (l) => console.error(renderNoticeLine(l)),
    }).then((gw) => console.error(renderNoticeLine(`gateway listening ${gw.url} -> ${upstream}`)));
}
else if (verb === "approve") {
    const token = argv[1];
    if (token === undefined) {
        process.stderr.write("usage: deepsweep-gateway approve <token> [--workspace <dir>] [--approver <who>]\n");
        process.exit(1);
    }
    const r = approveToken(workspace, token, flag(argv, "--approver") ?? "operator", new Date().toISOString(), keyFromArgv(argv));
    console.log(renderCanonicalJson({ ok: r.ok, status: r.status }));
    process.exitCode = r.ok ? 0 : 4;
}
else if (verb === "revoke") {
    const token = argv[1];
    if (token === undefined) {
        process.stderr.write("usage: deepsweep-gateway revoke <token> [--workspace <dir>] [--revoker <who>]\n");
        process.exit(1);
    }
    const r = revokeToken(workspace, token, flag(argv, "--revoker") ?? "operator", new Date().toISOString(), keyFromArgv(argv));
    console.log(renderCanonicalJson({ ok: r.ok, status: r.status }));
    process.exitCode = r.ok ? 0 : 4;
}
else if (verb === "repin") {
    const name = flag(argv, "--name");
    const tool = flag(argv, "--tool");
    if (name === undefined || tool === undefined) {
        process.stderr.write("usage: deepsweep-gateway repin --name <server> --tool <tool> [--workspace <dir>] [--approver <who>]\n");
        process.exit(1);
    }
    const r = repinTool(workspace, name, tool, flag(argv, "--approver") ?? "operator", new Date().toISOString(), keyFromArgv(argv));
    console.log(renderCanonicalJson(r));
    process.exitCode = r.ok ? 0 : 4;
}
else {
    process.stderr.write("usage: deepsweep-gateway <stdio|http|approve|revoke|repin> ...\n");
    process.exit(1);
}
