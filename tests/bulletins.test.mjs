// Run with: node --test tests/*.test.mjs
// No dependencies: node:test, node:assert and node:http only.
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  FEED_URL,
  fetchFeed,
  detectEcosystems,
  selectBulletins,
  renderSummary,
  renderAnnotation,
  cleanText,
  safeUrl,
  run,
} from "../bulletins/bulletins.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const FEED = JSON.parse(fs.readFileSync(path.join(HERE, "fixtures", "feed.json"), "utf8"));
const FEED_BODY = JSON.stringify(FEED);
// One day after the fixture entry was published.
const NOW = new Date("2026-10-22T22:50:00Z");
const DAY = 24 * 60 * 60 * 1000;

function tmpRepo(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ds-bulletins-"));
  for (const [rel, body] of Object.entries(files)) {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, body);
  }
  return dir;
}

function entry(overrides = {}) {
  return { ...FEED.entries[0], ...overrides };
}

function feedWith(entries) {
  return { ...FEED, entries };
}

// ---------------------------------------------------------------------------
// A local server, so the guards are tested against real HTTP behaviour.
// ---------------------------------------------------------------------------
let server;
let base;
before(async () => {
  server = http.createServer((req, res) => {
    switch (req.url) {
      case "/ok":
        res.writeHead(200, { "content-type": "application/json" });
        return res.end(FEED_BODY);
      case "/ok-charset":
        res.writeHead(200, { "content-type": "application/json; charset=utf-8" });
        return res.end(FEED_BODY);
      case "/404":
        res.writeHead(404, { "content-type": "application/json" });
        return res.end(FEED_BODY);
      case "/html":
        // What the site returned before the feed existed: its HTML shell.
        res.writeHead(200, { "content-type": "text/html" });
        return res.end("<!doctype html><html></html>");
      case "/v2":
        res.writeHead(200, { "content-type": "application/json" });
        return res.end(JSON.stringify({ ...FEED, version: 2 }));
      case "/not-json":
        res.writeHead(200, { "content-type": "application/json" });
        return res.end("{not json");
      case "/redirect":
        res.writeHead(302, { location: "/ok" });
        return res.end();
      case "/slow":
        // Headers after 1.5 s; the test passes a shorter timeout.
        setTimeout(() => {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(FEED_BODY);
        }, 1500);
        return;
      default:
        res.writeHead(500);
        return res.end();
    }
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => {
  server.closeAllConnections?.();
  server.close();
});

describe("fetch guards", () => {
  test("the feed address is the public v1 document", () => {
    assert.equal(FEED_URL, "https://deepsweep.ai/advisories/v1/feed.json");
  });

  test("status 200 with application/json and version 1 returns the document", async () => {
    const doc = await fetchFeed({ url: `${base}/ok` });
    assert.equal(doc.version, 1);
    assert.equal(doc.entries.length, 1);
  });

  test("a content type with parameters is accepted", async () => {
    const doc = await fetchFeed({ url: `${base}/ok-charset` });
    assert.equal(doc.version, 1);
  });

  test("a non-200 status returns null", async () => {
    assert.equal(await fetchFeed({ url: `${base}/404` }), null);
  });

  test("a non-JSON content type returns null", async () => {
    assert.equal(await fetchFeed({ url: `${base}/html` }), null);
  });

  test("a version other than 1 returns null", async () => {
    assert.equal(await fetchFeed({ url: `${base}/v2` }), null);
  });

  test("a body that does not parse returns null", async () => {
    assert.equal(await fetchFeed({ url: `${base}/not-json` }), null);
  });

  test("a redirect is not followed and returns null", async () => {
    assert.equal(await fetchFeed({ url: `${base}/redirect` }), null);
  });

  test("a response slower than the timeout returns null", async () => {
    const started = Date.now();
    assert.equal(await fetchFeed({ url: `${base}/slow`, timeoutMs: 200 }), null);
    assert.ok(Date.now() - started < 1400, "gave up at the timeout, not when the server answered");
  });

  test("the default timeout is 5 seconds", async () => {
    let seen;
    const fake = async (_url, init) => {
      seen = init;
      throw new Error("offline");
    };
    assert.equal(await fetchFeed({ fetchImpl: fake }), null);
    assert.equal(seen.redirect, "manual");
    assert.ok(seen.signal, "a timeout signal is passed");
    assert.equal(seen.signal.aborted, false);
  });

  test("a network error returns null", async () => {
    const fake = async () => {
      throw new Error("ECONNREFUSED");
    };
    assert.equal(await fetchFeed({ fetchImpl: fake }), null);
  });
});

describe("the 30-day window and severity", () => {
  const php = new Set(["php"]);

  test("a critical entry published 1 day ago is selected", () => {
    assert.equal(selectBulletins(FEED, php, NOW).length, 1);
  });

  test("29 days old is selected, exactly 30 and 31 days old are not", () => {
    const at = (days) => new Date(NOW.getTime() - days * DAY).toISOString();
    assert.equal(selectBulletins(feedWith([entry({ published_at: at(29) })]), php, NOW).length, 1);
    assert.equal(selectBulletins(feedWith([entry({ published_at: at(30) })]), php, NOW).length, 0);
    assert.equal(selectBulletins(feedWith([entry({ published_at: at(31) })]), php, NOW).length, 0);
  });

  test("an unparseable publication date is skipped", () => {
    assert.equal(selectBulletins(feedWith([entry({ published_at: "yesterday" })]), php, NOW).length, 0);
  });

  test("high, unknown and missing severities are skipped", () => {
    for (const severity of ["high", "medium", "catastrophic", undefined]) {
      assert.equal(selectBulletins(feedWith([entry({ severity })]), php, NOW).length, 0, String(severity));
    }
  });

  test("an entry without a usable title is skipped", () => {
    for (const title of ["", "   ", "\n\t\u2028", undefined, 42]) {
      assert.equal(selectBulletins(feedWith([entry({ title })]), php, NOW).length, 0, JSON.stringify(title));
    }
  });

  test("unknown fields are ignored", () => {
    const doc = feedWith([entry({ something_new: { nested: true } })]);
    doc.another_new_field = 1;
    assert.equal(selectBulletins(doc, php, NOW).length, 1);
  });

  test("at most three bulletins are shown", () => {
    const many = Array.from({ length: 5 }, (_, i) => entry({ id: `e${i}` }));
    assert.equal(selectBulletins(feedWith(many), php, NOW).length, 3);
  });

  test("a document without an entries array selects nothing", () => {
    assert.deepEqual(selectBulletins({ version: 1 }, php, NOW), []);
    assert.deepEqual(selectBulletins(null, php, NOW), []);
  });
});

describe("ecosystem matching on fixture repositories", () => {
  test("composer.json marks a PHP repository", () => {
    assert.ok(detectEcosystems(tmpRepo({ "composer.json": "{}" })).has("php"));
  });

  test(".php-version marks a PHP repository", () => {
    assert.ok(detectEcosystems(tmpRepo({ ".php-version": "8.3\n" })).has("php"));
  });

  test("a Dockerfile built on a php image marks a PHP repository", () => {
    for (const from of [
      "FROM php:8.3-fpm",
      "FROM --platform=linux/amd64 php:8.2-apache AS base",
      "from docker.io/library/php:8.4-cli",
    ]) {
      const dir = tmpRepo({ Dockerfile: `# build\n${from}\nRUN true\n` });
      assert.ok(detectEcosystems(dir).has("php"), from);
    }
  });

  test("a PHP project one directory down is found", () => {
    assert.ok(detectEcosystems(tmpRepo({ "api/composer.json": "{}" })).has("php"));
    assert.ok(detectEcosystems(tmpRepo({ "docker/Dockerfile.web": "FROM php:8.3\n" })).has("php"));
  });

  test("a repository without PHP markers has no php ecosystem", () => {
    const dir = tmpRepo({
      "package.json": "{}",
      Dockerfile: "FROM node:20\n# php is mentioned here but not the image\nFROM phpmyadmin:5\n",
      "README.md": "composer.json is not here",
    });
    assert.equal(detectEcosystems(dir).has("php"), false);
  });

  test("dependency and git directories are not searched", () => {
    const dir = tmpRepo({
      "node_modules/x/composer.json": "{}",
      "vendor/composer.json": "{}",
      ".git/composer.json": "{}",
    });
    assert.equal(detectEcosystems(dir).has("php"), false);
  });

  test("a missing directory yields no ecosystems and does not throw", () => {
    assert.equal(detectEcosystems(path.join(os.tmpdir(), "does-not-exist-ds-bulletins")).size, 0);
  });

  test("an entry for an ecosystem the repository does not use is silent", () => {
    assert.equal(selectBulletins(FEED, new Set(), NOW).length, 0);
    const npmOnly = feedWith([entry({ affected: [{ ecosystem: "npm", package: "x", kind: "package", versions: [] }] })]);
    assert.equal(selectBulletins(npmOnly, new Set(["php"]), NOW).length, 0);
  });

  test("ecosystem names match without regard to case", () => {
    const upper = feedWith([entry({ affected: [{ ecosystem: "PHP" }] })]);
    assert.equal(selectBulletins(upper, new Set(["php"]), NOW).length, 1);
  });
});

describe("summary and annotation text", () => {
  const e = FEED.entries[0];

  test("the summary names the title, the fix and the link", () => {
    const md = renderSummary(e);
    assert.equal(
      md,
      [
        "",
        `### Security bulletin: ${e.title}`,
        "",
        "This repository uses PHP, which this bulletin covers.",
        "",
        `**Fix:** ${e.actions[0]}`,
        "",
        `Details and sources: ${e.url}`,
        "",
      ].join("\n"),
    );
  });

  test("the annotation is one notice with the title, the fix and the link", () => {
    assert.equal(
      renderAnnotation(e),
      `::notice title=Security bulletin::${e.title}. Fix: ${e.actions[0]}. ${e.url}`,
    );
  });

  test("an entry without actions renders without a fix line", () => {
    const bare = entry({ actions: [] });
    assert.equal(renderSummary(bare).includes("**Fix:**"), false);
    assert.equal(renderAnnotation(bare), `::notice title=Security bulletin::${bare.title}. ${bare.url}`);
  });

  test("feed text cannot start a second workflow command", () => {
    const hostile = entry({ title: "a\n::error::b %", actions: ["c\r\n::warning::d"] });
    const line = renderAnnotation(hostile);
    assert.equal(line.split("\n").length, 1);
    assert.ok(line.includes("a ::error::b %25"));
    assert.ok(line.includes("c ::warning::d"));
  });
});

describe("run", () => {
  function fakeFetch(doc, calls) {
    return async () => {
      calls.n++;
      return new Response(JSON.stringify(doc), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    };
  }

  test("a PHP repository gets one summary block and one notice", async () => {
    const calls = { n: 0 };
    const out = [];
    const summary = path.join(tmpRepo({}), "summary.md");
    const shown = await run({
      enabled: "true",
      root: tmpRepo({ "composer.json": "{}" }),
      summaryPath: summary,
      now: NOW,
      fetchImpl: fakeFetch(FEED, calls),
      write: (s) => out.push(s),
    });
    assert.equal(calls.n, 1);
    assert.deepEqual(shown, ["2026-10-21-php2shell"]);
    assert.equal(out.length, 1);
    assert.ok(out[0].startsWith("::notice title=Security bulletin::PHP2Shell"));
    assert.ok(fs.readFileSync(summary, "utf8").includes("### Security bulletin: PHP2Shell"));
  });

  test("a repository without PHP prints nothing and writes no summary", async () => {
    const out = [];
    const summary = path.join(tmpRepo({}), "summary.md");
    const shown = await run({
      enabled: "true",
      root: tmpRepo({ "package.json": "{}" }),
      summaryPath: summary,
      now: NOW,
      fetchImpl: fakeFetch(FEED, { n: 0 }),
      write: (s) => out.push(s),
    });
    assert.deepEqual(shown, []);
    assert.deepEqual(out, []);
    assert.equal(fs.existsSync(summary), false);
  });

  test("with the input off, the feed is never fetched", async () => {
    for (const enabled of ["false", "FALSE", "no", "0", ""]) {
      const calls = { n: 0 };
      const out = [];
      await run({
        enabled,
        root: tmpRepo({ "composer.json": "{}" }),
        now: NOW,
        fetchImpl: fakeFetch(FEED, calls),
        write: (s) => out.push(s),
      });
      assert.equal(calls.n, 0, `enabled=${JSON.stringify(enabled)}`);
      assert.deepEqual(out, []);
    }
  });

  test("a failed fetch prints nothing about bulletins", async () => {
    const out = [];
    const shown = await run({
      enabled: "true",
      root: tmpRepo({ "composer.json": "{}" }),
      now: NOW,
      fetchImpl: async () => {
        throw new Error("offline");
      },
      write: (s) => out.push(s),
    });
    assert.deepEqual(shown, []);
    assert.deepEqual(out, []);
  });

  test("an unwritable summary file does not throw", async () => {
    const out = [];
    const dirAsFile = tmpRepo({});
    await assert.doesNotReject(
      run({
        enabled: "true",
        root: tmpRepo({ "composer.json": "{}" }),
        summaryPath: dirAsFile,
        now: NOW,
        fetchImpl: fakeFetch(FEED, { n: 0 }),
        write: (s) => out.push(s),
      }),
    );
  });

  test("a throwing writer does not throw", async () => {
    await assert.doesNotReject(
      run({
        enabled: "true",
        root: tmpRepo({ "composer.json": "{}" }),
        now: NOW,
        fetchImpl: fakeFetch(FEED, { n: 0 }),
        write: () => {
          throw new Error("stdout closed");
        },
      }),
    );
  });
});

describe("the step never fails the job", () => {
  test("the script exits 0 with the input off and prints nothing", () => {
    const r = spawnSync(process.execPath, [path.join(ROOT, "bulletins", "bulletins.mjs")], {
      env: { ...process.env, DS_BULLETINS: "false", GITHUB_STEP_SUMMARY: "" },
      encoding: "utf8",
    });
    assert.equal(r.status, 0);
    assert.equal(r.stdout, "");
  });

  test("the script exits 0 when the target path does not exist", () => {
    const r = spawnSync(process.execPath, [path.join(ROOT, "bulletins", "bulletins.mjs")], {
      env: { ...process.env, DS_BULLETINS: "false", DS_PATH: "/does/not/exist" },
      encoding: "utf8",
    });
    assert.equal(r.status, 0);
  });
});

describe("action.yml and README declare the input and the step", () => {
  const yml = fs.readFileSync(path.join(ROOT, "action.yml"), "utf8");
  const readme = fs.readFileSync(path.join(ROOT, "README.md"), "utf8");

  test("the bulletins input defaults to true", () => {
    const m = yml.match(/\n  bulletins:\n((?: {4}.*\n)+)/);
    assert.ok(m, "inputs.bulletins is declared");
    assert.match(m[1], /default: 'true'/);
  });

  test("the bulletins step is gated on the input, runs after the review and cannot fail the job", () => {
    const steps = yml.split(/\n    - name: /).slice(1);
    const names = steps.map((s) => s.split("\n")[0].trim());
    const i = names.findIndex((n) => /bulletin/i.test(n));
    assert.ok(i >= 0, "a bulletins step exists");
    assert.ok(i > names.indexOf("Run the review"), "it comes after the review");
    const step = steps[i];
    assert.match(step, /inputs\.bulletins == 'true'/);
    assert.match(step, /!cancelled\(\)/);
    assert.match(step, /continue-on-error: true/);
    assert.match(step, /bulletins\/bulletins\.mjs/);
    assert.match(step, /\|\| true/);
  });

  test("README documents the input and the request it makes", () => {
    assert.match(readme, /\| `bulletins` \| `true` \|/);
    assert.match(readme, /advisories\/v1\/feed\.json/);
    assert.doesNotMatch(readme, /makes no outbound calls of its own/);
  });
});

// ---------------------------------------------------------------------------
// Feed text is data. Whatever an entry carries, it renders as one capped,
// escaped line, and a link only to https on deepsweep.ai.
// ---------------------------------------------------------------------------
describe("feed text is untrusted", () => {
  const php = new Set(["php"]);
  const one = (overrides) => {
    const picked = selectBulletins(feedWith([entry(overrides)]), php, NOW);
    assert.equal(picked.length, 1, "the entry is kept");
    return picked[0];
  };
  const MULTILINE = "Real title\n::set-output name=x::pwned\r\n# heading\n> quote";
  const BIDI = "safe \u202Etxt.exe\u202C and \u2066isolate\u2069 \u2028sep\u2029 end";

  test("control, separator and bidi characters are stripped and whitespace collapsed", () => {
    assert.equal(cleanText("a\r\nb\tc\u2028d\u2029e", 100), "a b c d e");
    assert.equal(cleanText(BIDI, 100), "safe txt.exe and isolate sep end");
    for (const cp of [0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069]) {
      assert.equal(cleanText(`x${String.fromCodePoint(cp)}y`, 10), "xy", cp.toString(16));
    }
    assert.equal(cleanText("a\u0000b\u0007c\u007fd", 10), "abcd");
    assert.equal(cleanText("  lots   of\n\n space  ", 100), "lots of space");
  });

  test("a multi-line title with ::set-output and # heading renders as one escaped line", () => {
    const e = one({ title: MULTILINE });
    const md = renderSummary(e);
    const heading = md.split("\n").find((l) => l.startsWith("### Security bulletin: "));
    assert.ok(heading.includes("Real title ::set-output name=x::pwned \\# heading \\> quote"), heading);
    assert.equal(md.split("\n").filter((l) => /^\s*(#|>)/.test(l)).length, 1, "only our own heading starts a line with # or >");
    const note = renderAnnotation(e);
    assert.equal(note.split("\n").length, 1);
    assert.ok(note.startsWith("::notice title=Security bulletin::Real title ::set-output name=x::pwned # heading > quote."));
  });

  test("a bidi title renders without bidi controls anywhere", () => {
    const e = one({ title: BIDI, actions: [BIDI] });
    const bidi = /[\u202A-\u202E\u2066-\u2069\u2028\u2029]/;
    assert.doesNotMatch(renderSummary(e), bidi);
    assert.doesNotMatch(renderAnnotation(e), bidi);
  });

  test("the title is capped at 160 characters and the fix at 300", () => {
    const e = one({ title: "T".repeat(500), actions: ["F".repeat(10 * 1024)] });
    const note = renderAnnotation(e);
    const title = note.slice(note.indexOf("::", 2) + 2).split(". Fix: ")[0];
    assert.equal(title.length, 160);
    assert.ok(title.endsWith("\u2026"));
    const fix = note.split(". Fix: ")[1].split(". https://")[0];
    assert.equal(fix.length, 300);
    assert.ok(fix.endsWith("\u2026"));
    const md = renderSummary(e);
    assert.ok(md.length < 1000, `summary block is ${md.length} characters`);
    assert.ok(md.includes(`**Fix:** ${"F".repeat(299)}\u2026`));
  });

  test("markdown that could inject is escaped in title and fix", () => {
    const e = one({
      title: "<img src=x onerror=alert(1)> [click](https://evil.example) `code` ![i](x)",
      actions: ["- list item <b>bold</b> [x](y)"],
    });
    const md = renderSummary(e);
    assert.doesNotMatch(md, /(^|[^\\])[<>`\[\]]/m, "no unescaped < > ` [ ]");
    assert.ok(md.includes("\\<img src=x onerror=alert(1)\\>"));
    assert.ok(md.includes("\\[click\\](https://evil.example)"));
    assert.ok(md.includes("\\`code\\`"));
    assert.ok(md.includes("**Fix:** \\- list item \\<b\\>bold\\</b\\> \\[x\\](y)"));
  });

  test("leading #, >, - and * are escaped so a value cannot open a block", () => {
    for (const lead of ["#", ">", "-", "*"]) {
      const md = renderSummary(one({ title: `${lead} start`, actions: [`${lead} fix`] }));
      assert.ok(md.includes(`### Security bulletin: \\${lead} start`), `${lead} title`);
      assert.ok(md.includes(`**Fix:** \\${lead} fix`), `${lead} fix`);
    }
  });

  test("a javascript: url is never rendered; the text still is", () => {
    const e = one({ url: "javascript:alert(1)" });
    const md = renderSummary(e);
    assert.doesNotMatch(md, /javascript/i);
    assert.ok(md.includes("### Security bulletin: PHP2Shell"));
    assert.doesNotMatch(md, /Details and sources/);
    assert.doesNotMatch(renderAnnotation(e), /javascript/i);
  });

  test("an http url, or https off deepsweep.ai, is never rendered", () => {
    for (const url of [
      "http://deepsweep.ai/blog/x",
      "https://evil.example/x",
      "https://deepsweep.ai.evil.example/x",
      "https://user@deepsweep.ai/x",
      "https://deepsweep.ai:8443/x",
    ]) {
      const e = one({ url });
      assert.doesNotMatch(renderSummary(e), /Details and sources|evil|http:|8443|user@/, url);
      assert.ok(renderAnnotation(e).endsWith(`Fix: ${FEED.entries[0].actions[0]}.`), url);
    }
  });

  test("safeUrl keeps https links on deepsweep.ai only", () => {
    assert.equal(safeUrl("https://deepsweep.ai/blog/x"), "https://deepsweep.ai/blog/x");
    assert.equal(safeUrl("https://www.deepsweep.ai/a?b=c"), "https://www.deepsweep.ai/a?b=c");
    for (const bad of ["javascript:alert(1)", "http://deepsweep.ai/", "https://evil.example/", "data:text/html,x", "", null, 7, "https://deepsweep.ai/a b\nc"]) {
      assert.equal(safeUrl(bad), "", JSON.stringify(bad));
    }
  });

  test("one malformed entry is dropped and the others still show", () => {
    const good = entry({ id: "good" });
    const bad = [
      entry({ id: "no-title", title: "\n\u202E\t" }),
      entry({ id: "actions-not-array", actions: "x" }),
      entry({ id: "affected-weird", affected: [null, 5, { ecosystem: { x: 1 } }, { ecosystem: "php" }] }),
      Object.defineProperty(entry({ id: "throws" }), "title", {
        get() {
          throw new Error("boom");
        },
        enumerable: true,
      }),
    ];
    const ids = selectBulletins(feedWith([...bad, good]), php, NOW).map((e) => e.id);
    assert.ok(ids.includes("good"));
    assert.ok(!ids.includes("no-title"));
    assert.ok(!ids.includes("throws"));
  });

  test("run with every hostile fixture still writes single-line notices and exits cleanly", async () => {
    const out = [];
    const summary = path.join(tmpRepo({}), "summary.md");
    const doc = feedWith([
      entry({ id: "a", title: MULTILINE }),
      entry({ id: "b", title: BIDI, actions: ["F".repeat(10 * 1024)] }),
      entry({ id: "c", url: "javascript:alert(1)" }),
    ]);
    const shown = await run({
      enabled: "true",
      root: tmpRepo({ "composer.json": "{}" }),
      summaryPath: summary,
      now: NOW,
      fetchImpl: async () =>
        new Response(JSON.stringify(doc), { status: 200, headers: { "content-type": "application/json" } }),
      write: (s) => out.push(s),
    });
    assert.deepEqual(shown, ["a", "b", "c"]);
    for (const line of out) {
      assert.equal(line.split(/[\r\n]/).length, 1);
      assert.ok(line.length < 700, `notice is ${line.length} characters`);
    }
    const md = fs.readFileSync(summary, "utf8");
    assert.doesNotMatch(md, /javascript|[\u202A-\u202E\u2066-\u2069]/);
    assert.equal(md.split("\n").filter((l) => /^\s*#/.test(l)).length, 3, "three headings, all ours");
  });
});
