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

function ecosystemsOf(entry) {
  const list = Array.isArray(entry.affected) ? entry.affected : [];
  return list
    .map((a) => (a && typeof a.ecosystem === "string" ? a.ecosystem.toLowerCase() : ""))
    .filter(Boolean);
}

/**
 * The bulletins to show: critical, published less than 30 days before `now`,
 * with a title and an https link, naming an ecosystem the repository uses.
 * Unknown fields and unknown severities are ignored. At most three.
 */
export function selectBulletins(doc, repoEcosystems, now = new Date()) {
  if (!doc || !Array.isArray(doc.entries)) return [];
  const out = [];
  for (const entry of doc.entries) {
    if (!entry || typeof entry !== "object") continue;
    if (entry.severity !== "critical") continue;
    if (typeof entry.title !== "string" || !entry.title.trim()) continue;
    if (typeof entry.url !== "string" || !entry.url.startsWith("https://")) continue;
    const published = Date.parse(entry.published_at);
    if (!Number.isFinite(published)) continue;
    if (now.getTime() - published >= WINDOW_MS) continue;
    const hit = ecosystemsOf(entry).find((e) => repoEcosystems.has(e) && ECOSYSTEMS[e]);
    if (!hit) continue;
    out.push({ ...entry, matched_ecosystem: hit });
    if (out.length === MAX_SHOWN) break;
  }
  return out;
}

function fixLine(entry) {
  const first = Array.isArray(entry.actions) ? entry.actions[0] : undefined;
  return typeof first === "string" && first.trim() ? first.trim() : "";
}

function labelOf(entry) {
  const id = entry.matched_ecosystem || ecosystemsOf(entry).find((e) => ECOSYSTEMS[e]);
  return ECOSYSTEMS[id]?.label || "";
}

/** One block for the job summary. */
export function renderSummary(entry) {
  const lines = ["", `### Security bulletin: ${entry.title}`, ""];
  const label = labelOf(entry);
  if (label) lines.push(`This repository uses ${label}, which this bulletin covers.`, "");
  const fix = fixLine(entry);
  if (fix) lines.push(`**Fix:** ${fix}`, "");
  lines.push(`Details and sources: ${entry.url}`, "");
  return lines.join("\n");
}

// Workflow command data escaping, so feed text cannot end the line and start
// another command.
function escapeData(s) {
  return String(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}

/** One `::notice` annotation line. */
export function renderAnnotation(entry) {
  const fix = fixLine(entry);
  const message = fix ? `${entry.title}. Fix: ${fix}. ${entry.url}` : `${entry.title}. ${entry.url}`;
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
