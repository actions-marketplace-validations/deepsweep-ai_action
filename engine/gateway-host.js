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
 *   deepsweep-gateway approve <token> --approver <who> [--workspace <dir>]
 *   deepsweep-gateway kill [--workspace <dir>] [--actor <who>]
 *   deepsweep-gateway resume [--workspace <dir>] [--actor <who>]
 *   deepsweep-gateway drill [--workspace <dir>] [--actor <who>]
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
import { approveByHash, approveToken, listPendingApprovals, revokeToken } from "./gateway/approval.js";
import { activateKillswitch, deactivateKillswitch, runKillswitchDrill } from "./gateway/killswitch.js";
import { decideFrame } from "./gateway/decide.js";
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
    const approver = (flag(argv, "--approver") ?? "").trim();
    if (approver.length === 0) {
        process.stderr.write("usage: deepsweep-gateway approve <token> --approver <who> [--workspace <dir>]\n--approver is REQUIRED: a grant with no named grantor is not a grant.\n");
        process.exit(1);
    }
    const r = approveToken(workspace, token, approver, new Date().toISOString(), keyFromArgv(argv));
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
    const repinApprover = (flag(argv, "--approver") ?? "").trim();
    if (repinApprover.length === 0) {
        process.stderr.write("usage: deepsweep-gateway repin --name <server> --tool <tool> --approver <who> [--workspace <dir>]\n--approver is REQUIRED: re-trusting a drifted tool is a grant, and a grant with no named grantor is not a grant.\n");
        process.exit(1);
    }
    const r = repinTool(workspace, name, tool, repinApprover, new Date().toISOString(), keyFromArgv(argv));
    console.log(renderCanonicalJson(r));
    process.exitCode = r.ok ? 0 : 4;
}
else if (verb === "approvals") {
    // The approval card's read: pending records, hashes only.
    console.log(renderCanonicalJson({ pending: listPendingApprovals(workspace, new Date().toISOString()) }));
    process.exitCode = 0;
}
else if (verb === "grant") {
    // The approval card's write: grant BY TOKEN HASH. Only the agent holding
    // the one-time plaintext token can redeem, so this releases exactly the
    // bound call. Same integrity gate as approve (named, never the proposer).
    const th = argv[1];
    const approver = (flag(argv, "--approver") ?? "").trim();
    if (th === undefined || approver.length === 0) {
        process.stderr.write("usage: deepsweep-gateway grant <tokenHash> --approver <who> [--workspace <dir>]\n");
        process.exit(1);
    }
    const r = approveByHash(workspace, th, approver, new Date().toISOString(), keyFromArgv(argv));
    console.log(renderCanonicalJson({ ok: r.ok, status: r.status }));
    process.exitCode = r.ok ? 0 : 4;
}
else if (verb === "kill" || verb === "resume") {
    const actor = flag(argv, "--actor") ?? "operator";
    const r = verb === "kill"
        ? activateKillswitch(workspace, actor, new Date().toISOString(), keyFromArgv(argv))
        : deactivateKillswitch(workspace, actor, new Date().toISOString(), keyFromArgv(argv));
    console.log(renderCanonicalJson({ killswitch: verb === "kill" ? "on" : "off", ledger: r === "corrupt" ? "corrupt" : "recorded" }));
    process.exitCode = r === "corrupt" ? 2 : 0;
}
else if (verb === "drill") {
    // The drill proves the PRODUCTION refusal path: a synthetic tools/call
    // through the real decideFrame while the switch is thrown. A drill that
    // does not observe a refusal reports NOT_REFUSED and exits 5.
    const actor = flag(argv, "--actor") ?? "operator";
    // The probe's refusal is recorded like any other (TEAM-ADR-069), so it is
    // signed with the same key as the drill's own entries: an unsigned entry
    // between signed ones would read as a signature gap.
    const key = keyFromArgv(argv);
    const probe = () => {
        const d = decideFrame({ method: "tools/call", id: "drill-1", params: { name: "__deepsweep_drill__", arguments: {} } }, { workspaceRoot: workspace, serverName: "__drill__", principal: null, nowIso: new Date().toISOString(), key });
        return d.kind === "reject" && d.reason === "killed";
    };
    const r = runKillswitchDrill(workspace, actor, new Date().toISOString(), probe, () => Date.now(), key);
    console.log(renderCanonicalJson({ outcome: r.outcome, elapsedMs: r.elapsedMs, restored: r.restored }));
    process.exitCode = r.exitCode;
}
else {
    process.stderr.write("usage: deepsweep-gateway <stdio|http|approve|grant|approvals|revoke|repin|kill|resume|drill> ...\n");
    process.exit(1);
}
