// Security bulletins for the DeepSweep action.
//
// After the review, the action reads the public advisories document once and,
// when a critical bulletin from the last 30 days covers something this
// repository uses, writes one notice to the job summary and one annotation.
//
// It never fails the job. Every failure (network, status, content type,
// version, parse, file access) ends silently with exit code 0, and nothing
// about bulletins is printed. The request carries nothing about the
// repository: it is one anonymous GET of a public file.
//
// Node built-ins only. Runs on the Node the action already sets up.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const FEED_URL = "https://deepsweep.ai/advisories/v1/feed.json";
const TIMEOUT_MS = 5000;
const MAX_BYTES = 1024 * 1024;
const WINDOW_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_SHOWN = 3;
const SEARCH_DEPTH = 2;
const SKIP_DIRS = new Set(["node_modules", "vendor", "dist", "build", "target"]);

/**
 * Fetch the document. Returns the parsed document, or null on any failure:
 * a timeout, a redirect, a status other than 200, a content type without
 * application/json, a body over 1 MB, a body that does not parse, or a
 * version other than 1.
 */
export async function fetchFeed({ url = FEED_URL, timeoutMs = TIMEOUT_MS, fetchImpl = globalThis.fetch } = {}) {
  try {
    const res = await fetchImpl(url, {
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
      headers: { accept: "application/json" },
    });
    if (res.status !== 200) return null;
    const type = (res.headers.get("content-type") || "").toLowerCase();
    if (!type.includes("application/json")) return null;
    const declared = Number(res.headers.get("content-length"));
    if (Number.isFinite(declared) && declared > MAX_BYTES) return null;
    const text = await res.text();
    if (text.length > MAX_BYTES) return null;
    const doc = JSON.parse(text);
    if (!doc || typeof doc !== "object" || doc.version !== 1) return null;
    return doc;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Ecosystem matching. Each ecosystem a bulletin can name in affected[] maps to
// a label and the file checks that show a repository uses it. An ecosystem
// with no entry here never matches, so a new kind of bulletin stays silent
// until a check for it is added.
// ---------------------------------------------------------------------------

const DOCKER_PHP = /^\s*from\s+(?:--\S+\s+)*(?:\S+\/)?php(?::|@|\s|$)/im;

function isDockerfile(name) {
  return name === "Dockerfile" || name.startsWith("Dockerfile.") || name.endsWith(".Dockerfile");
}

function readHead(file) {
  try {
    const fd = fs.openSync(file, "r");
    try {
      const buf = Buffer.alloc(64 * 1024);
      const n = fs.readSync(fd, buf, 0, buf.length, 0);
      return buf.subarray(0, n).toString("utf8");
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return "";
  }
}

const ECOSYSTEMS = {
  php: {
    label: "PHP",
    matches(dir, name) {
      if (name === "composer.json" || name === ".php-version") return true;
      return isDockerfile(name) && DOCKER_PHP.test(readHead(path.join(dir, name)));
    },
  },
};

/** The ecosystems this repository uses, searched to two directory levels. */
export function detectEcosystems(root) {
  const found = new Set();
  const walk = (dir, depth) => {
    let items;
    try {
      items = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const item of items) {
      if (item.isFile()) {
        for (const [id, eco] of Object.entries(ECOSYSTEMS)) {
          if (!found.has(id) && eco.matches(dir, item.name)) found.add(id);
        }
      } else if (item.isDirectory() && depth < SEARCH_DEPTH) {
        if (item.name.startsWith(".") || SKIP_DIRS.has(item.name)) continue;
        walk(path.join(dir, item.name), depth + 1);
      }
    }
  };
  walk(root, 1);
  return found;
}

// ---------------------------------------------------------------------------
// Feed text is data. Every string is cleaned to one capped line before it is
// rendered, markdown that could change the summary is escaped, and a link is
// rendered only when it is https on deepsweep.ai.
// ---------------------------------------------------------------------------

const TITLE_CAP = 160;
const FIX_CAP = 300;
// C0 and C1 controls other than whitespace, and the bidi embedding, override
// and isolate controls. Removed outright.
const STRIP = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/g;

/** One line: controls removed, CR, LF, tab and line separators to spaces,
 * whitespace collapsed, at most `cap` characters with an ellipsis. */
export function cleanText(value, cap) {
  if (typeof value !== "string") return "";
  const line = value.replace(STRIP, "").replace(/\s+/g, " ").trim();
  const chars = Array.from(line);
  return chars.length <= cap ? line : chars.slice(0, cap - 1).join("").trimEnd() + "\u2026";
}

/** The url when it is https on deepsweep.ai, with no credentials or port; else "". */
export function safeUrl(value) {
  if (typeof value !== "string" || /[\s\u0000-\u001F\u007F]/.test(value)) return "";
  let u;
  try {
    u = new URL(value);
  } catch {
    return "";
  }
  if (u.protocol !== "https:" || u.username || u.password || u.port) return "";
  if (u.hostname !== "deepsweep.ai" && !u.hostname.endsWith(".deepsweep.ai")) return "";
  return u.href;
}

// Escape what could turn a value into a link, image, code span, raw HTML or
// heading, and a leading character that could open a list or blockquote.
function escapeMarkdown(text) {
  const inline = text.replace(/[\\`<>\[\]#]/g, (c) => "\\" + c);
  return /^[-*+>]/.test(inline) ? "\\" + inline : inline;
}

function ecosystemsOf(entry) {
  const list = Array.isArray(entry.affected) ? entry.affected : [];
  return list
    .map((a) => (a && typeof a.ecosystem === "string" ? a.ecosystem.toLowerCase() : ""))
    .filter(Boolean);
}

/** The display fields of an entry, cleaned. Throws on nothing it can catch. */
function view(entry) {
  const fixes = Array.isArray(entry.actions) ? entry.actions : [];
  const id = entry.matched_ecosystem || ecosystemsOf(entry).find((e) => ECOSYSTEMS[e]);
  return {
    title: cleanText(entry.title, TITLE_CAP),
    fix: cleanText(fixes[0], FIX_CAP),
    url: safeUrl(entry.url),
    label: ECOSYSTEMS[id]?.label || "",
  };
}

/**
 * The bulletins to show: critical, published less than 30 days before `now`,
 * with a title left after cleaning, naming an ecosystem the repository uses.
 * Unknown fields and unknown severities are ignored. An entry that fails any
 * check, or throws while being read, is dropped on its own. At most three.
 */
export function selectBulletins(doc, repoEcosystems, now = new Date()) {
  if (!doc || !Array.isArray(doc.entries)) return [];
  const out = [];
  for (const entry of doc.entries) {
    try {
      if (!entry || typeof entry !== "object") continue;
      if (entry.severity !== "critical") continue;
      if (!cleanText(entry.title, TITLE_CAP)) continue;
      const published = Date.parse(entry.published_at);
      if (!Number.isFinite(published)) continue;
      if (now.getTime() - published >= WINDOW_MS) continue;
      const hit = ecosystemsOf(entry).find((e) => repoEcosystems.has(e) && ECOSYSTEMS[e]);
      if (!hit) continue;
      out.push({ ...entry, matched_ecosystem: hit });
    } catch {
      continue;
    }
    if (out.length === MAX_SHOWN) break;
  }
  return out;
}

/** One block for the job summary. */
export function renderSummary(entry) {
  const v = view(entry);
  const lines = ["", `### Security bulletin: ${escapeMarkdown(v.title)}`, ""];
  if (v.label) lines.push(`This repository uses ${v.label}, which this bulletin covers.`, "");
  if (v.fix) lines.push(`**Fix:** ${escapeMarkdown(v.fix)}`, "");
  if (v.url) lines.push(`Details and sources: ${v.url}`, "");
  return lines.join("\n");
}

// Workflow command data escaping, so feed text cannot end the line and start
// another command. The text is already one line; this is the second guard.
function escapeData(s) {
  return String(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}

/** One `::notice` annotation line. */
export function renderAnnotation(entry) {
  const v = view(entry);
  const parts = [v.title];
  if (v.fix) parts.push(`Fix: ${v.fix}`);
  let message = parts.join(". ") + ".";
  if (v.url) message += ` ${v.url}`;
  return `::notice title=Security bulletin::${escapeData(message)}`;
}

/**
 * The whole step. Returns the ids shown. Never throws.
 * `enabled` is the action input; anything other than "true" means off, and
 * off means no request is made.
 */
export async function run({
  enabled,
  root = ".",
  summaryPath = "",
  now = new Date(),
  fetchImpl = globalThis.fetch,
  write = (s) => process.stdout.write(s + "\n"),
} = {}) {
  try {
    if (String(enabled ?? "").trim().toLowerCase() !== "true") return [];
    const ecosystems = detectEcosystems(path.resolve(root));
    if (ecosystems.size === 0) return [];
    const doc = await fetchFeed({ fetchImpl });
    const picked = selectBulletins(doc, ecosystems, now);
    const shown = [];
    for (const entry of picked) {
      try {
        if (summaryPath) fs.appendFileSync(summaryPath, renderSummary(entry));
      } catch {
        // A summary we cannot write is skipped; the annotation still goes out.
      }
      try {
        write(renderAnnotation(entry));
      } catch {
        // Nothing to do: the step must not fail.
      }
      shown.push(entry.id);
    }
    return shown;
  } catch {
    return [];
  }
}

const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  run({
    enabled: process.env.DS_BULLETINS,
    root: process.env.DS_PATH || ".",
    summaryPath: process.env.GITHUB_STEP_SUMMARY || "",
  })
    .catch(() => {})
    .finally(() => {
      process.exitCode = 0;
    });
}
