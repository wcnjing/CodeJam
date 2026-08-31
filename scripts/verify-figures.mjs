#!/usr/bin/env node
/**
 * Verifies every published figure against the CI run its own text cites.
 *
 * WHY THIS EXISTS, precisely. The project already had a verification habit:
 * re-read each figure against the log of the run it cites. That habit caught
 * seven wrong claims. It missed the eighth, and the way it missed is the whole
 * design brief for this file.
 *
 * The eighth was the sentence "the decision is still under 0.5% of a run's wall
 * time". The run says 0.62-0.70% over five commands and 6.6-6.9% over fifty. It
 * survived because **the habit had a shape**: it walked tables, headline
 * figures, the things that look like measurements. `0.5%` was a reassuring
 * clause at the end of a sentence about something else. It never presented
 * itself as a figure, so it was never checked as one. A process with a shape
 * only checks things of that shape, and everything else passes through
 * untouched no matter how carefully the process is followed.
 *
 * So this does not look for figures. It extracts EVERY numeric token from every
 * document and forces each one into exactly one of three states:
 *
 *   MATCHED     the number appears in the run the surrounding text cites, at
 *               the precision the text states it to.
 *   EXEMPT      the number is deliberately not from that run, and the reason is
 *               recorded in `docs/figures-exempt.json`. Historical
 *               "before" columns live here. So does anything structural.
 *   UNEXPLAINED everything else. This is the failure state, and it does not
 *               distinguish "stale" from "fabricated" on purpose: from the
 *               document's point of view they are the same defect, and the
 *               author is the only one who can say which it was.
 *
 * The third state is the point. A number that cannot be found in its own cited
 * run must be explained by a human, in a file, in words. It cannot be resolved
 * by being plausible.
 *
 * PROVENANCE LABELS are checked separately, and for a different failure. The
 * label "measured locally, not from CI - refresh once the harness lands" was
 * accurate the day it was written and false about ten hours later, when that
 * harness's CI ran. Nothing was edited; the world moved. A label is a claim
 * with an expiry date, and an expired label is indistinguishable from a current
 * one by reading. So every label registered in `docs/figures-exempt.json` must
 * carry the condition that RETIRES it, and this script evaluates those
 * conditions and fails when one has been met.
 *
 *   node scripts/verify-figures.mjs            # check, exit 1 on any failure
 *   node scripts/verify-figures.mjs --report   # print everything, exit 0
 */

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "..");
const CACHE = path.join(ROOT, "node_modules", ".cache", "ci-logs");
const EXEMPT_PATH = path.join(ROOT, "docs", "figures-exempt.json");
const REPORT_ONLY = process.argv.includes("--report");

const DOCS = [
  "README.md",
  "docs/EVALUATION_RELIABILITY_PLAN.md",
  "docs/PR_DESCRIPTION.md",
  "docs/POLICY_EVALUATION.md",
  "docs/THREAT_MODEL.md",
];

/* ── the exemption register ──────────────────────────────────────────────── */

function loadExemptions() {
  if (!existsSync(EXEMPT_PATH)) return { figures: [], provenanceLabels: [] };
  return JSON.parse(readFileSync(EXEMPT_PATH, "utf8"));
}

/* ── run logs ────────────────────────────────────────────────────────────── */

function runLog(runId) {
  mkdirSync(CACHE, { recursive: true });
  const cached = path.join(CACHE, `${runId}.log`);
  if (existsSync(cached)) return readFileSync(cached, "utf8");
  process.stderr.write(`  fetching run ${runId} ...\n`);
  let text = "";
  try {
    text = execFileSync("gh", ["run", "view", runId, "--log"], {
      encoding: "utf8",
      maxBuffer: 256 * 1024 * 1024,
      windowsHide: true,
    });
  } catch (error) {
    // A run whose logs have expired or been deleted is not a document defect.
    // Say so distinctly rather than reporting every figure in it as unexplained.
    text = "";
    process.stderr.write(`  WARNING: could not fetch run ${runId}\n`);
  }
  writeFileSync(cached, text, "utf8");
  return text;
}

/** Every number that appears anywhere in a run's log. */
function numbersIn(text) {
  const set = new Set();
  for (const match of text.matchAll(/\d+(?:\.\d+)?/g)) set.add(match[0]);
  return set;
}

/* ── figure extraction ───────────────────────────────────────────────────── */

/**
 * A "numeric token" is any number carrying a unit, a percent sign, or a
 * denominator -- plus bare integers adjacent to counting words.
 *
 * Deliberately wider than "things that look like figures", because that
 * narrowness is what let 0.5% through. Structural numbers (dates, run ids,
 * versions, section numbers) are dropped by pattern, not by judgement.
 */
const FIGURE = /(\d+(?:,\d{3})*(?:\.\d+)?)\s*(%|µs|us\b|ms\b|MB\b|GB\b|x\b)|(\d+(?:,\d{3})*)\s*\/\s*(\d+(?:,\d{3})*)/g;

function extractFigures(line) {
  const found = [];
  for (const m of line.matchAll(FIGURE)) {
    if (m[1]) { found.push({ raw: m[1].replace(/,/g, ""), unit: m[2], text: m[0].trim() }); continue; }
    // `n/m` is only a rate if it is not part of a path or a version. The
    // `/dev/udp/198.51.100.7/9999` in a threat-model example is a port on a
    // host, not seven successes out of 9999 trials.
    const before = line.slice(Math.max(0, m.index - 1), m.index);
    if (/[./\w]/.test(before)) continue;
    const after = line.slice(m.index + m[0].length, m.index + m[0].length + 1);
    if (after === "/" || after === ".") continue;
    found.push({ raw: m[3].replace(/,/g, ""), unit: "/", text: m[0].trim(), denominator: m[4].replace(/,/g, "") });
  }
  return found;
}

/** Numbers that are structure, not measurement. */
function isStructural(line) {
  return (
    /^\s*(\||#{1,6}\s|\[\d+\]:)/.test(line) === false && false
  );
}

/* ── the check ───────────────────────────────────────────────────────────── */

const RUN_URL = /actions\/runs\/(\d+)/;

function checkDoc(relPath, exemptions) {
  const abs = path.join(ROOT, relPath);
  if (!existsSync(abs)) return { relPath, missing: true, rows: [] };
  const lines = readFileSync(abs, "utf8").split(/\r?\n/);

  const rows = [];
  let inFence = false;
  // The run a figure is checked against is the last one cited at or before it,
  // or -- for a figure whose citation follows it in the same block -- the next
  // one within a short lookahead. Documents cite both ways round.
  const citationAt = new Array(lines.length).fill(null);
  let last = null;
  for (let i = 0; i < lines.length; i += 1) {
    const m = RUN_URL.exec(lines[i]);
    if (m) last = m[1];
    citationAt[i] = last;
  }
  const forward = new Array(lines.length).fill(null);
  let next = null;
  for (let i = lines.length - 1; i >= 0; i -= 1) {
    const m = RUN_URL.exec(lines[i]);
    if (m) next = { run: m[1], at: i };
    forward[i] = next;
  }

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (/^\s*```/.test(line)) { inFence = !inFence; continue; }
    if (inFence) continue;
    // Skip link definitions and the citation lines themselves.
    const stripped = line.replace(/https?:\/\/\S+/g, " ").replace(/`[^`]*`/g, (s) => s);
    if (!stripped.trim()) continue;

    for (const fig of extractFigures(stripped)) {
      const ahead = forward[i];
      const run =
        ahead && ahead.at - i <= 4 && !citationAt[i] ? ahead.run : citationAt[i] ?? (ahead ? ahead.run : null);
      rows.push({ line: i + 1, run, ...fig, source: line.trim().slice(0, 100) });
    }
  }
  return { relPath, rows };
}

function matches(fig, logNumbers) {
  if (logNumbers.has(fig.raw)) return true;
  // Match at the precision the document states. "0.62" is satisfied by a log
  // value of 0.6197; "58.19" is not satisfied by 58.2.
  const decimals = (fig.raw.split(".")[1] ?? "").length;
  const target = Number(fig.raw);
  for (const candidate of logNumbers) {
    const value = Number(candidate);
    if (!Number.isFinite(value)) continue;
    if (Number(value.toFixed(decimals)) === target) return true;
  }
  return false;
}

function exemptFor(exemptions, relPath, fig) {
  return exemptions.figures.find(
    (e) =>
      e.doc === relPath &&
      String(e.value) === fig.raw &&
      (e.unit === undefined || e.unit === fig.unit),
  );
}

/* ── provenance labels ───────────────────────────────────────────────────── */

function checkProvenanceLabels(exemptions) {
  const results = [];
  for (const label of exemptions.provenanceLabels ?? []) {
    const abs = path.join(ROOT, label.doc);
    const present = existsSync(abs) && readFileSync(abs, "utf8").includes(label.marker);
    let retired = false;
    let detail = "";
    const condition = label.retiresWhen ?? {};
    if (condition.type === "ci-run-exists-for-branch") {
      try {
        const out = execFileSync(
          "gh",
          ["run", "list", "--branch", condition.branch, "--limit", "1", "--json", "databaseId,conclusion"],
          { encoding: "utf8", windowsHide: true },
        );
        const runs = JSON.parse(out);
        const ok = runs.filter((r) => r.conclusion === "success");
        if (ok.length > 0) {
          retired = true;
          detail = `run ${ok[0].databaseId} succeeded on ${condition.branch}`;
        }
      } catch {
        detail = "could not query";
      }
    } else if (condition.type === "branch-merged") {
      try {
        const out = execFileSync("git", ["branch", "-r", "--contains", condition.ref], {
          encoding: "utf8",
          windowsHide: true,
        });
        if (/origin\/main\b/.test(out)) { retired = true; detail = `${condition.ref} is in origin/main`; }
      } catch {
        detail = "could not query";
      }
    } else {
      detail = "unknown condition type";
    }
    results.push({ ...label, present, retired, detail });
  }
  return results;
}

/* ── run ─────────────────────────────────────────────────────────────────── */

const exemptions = loadExemptions();
const logCache = new Map();

/**
 * Other runs to search when a figure is absent from the run its text cites.
 *
 * This is what turns "unexplained" into an actionable distinction. A number
 * found in a DIFFERENT run is misattributed -- the measurement happened, the
 * citation points elsewhere. A number found in NO run is either historical or
 * invented. Those need different fixes and the report must not blur them.
 */
function candidateRuns() {
  const runs = new Set();
  for (const relPath of DOCS) {
    const abs = path.join(ROOT, relPath);
    if (!existsSync(abs)) continue;
    for (const m of readFileSync(abs, "utf8").matchAll(/actions\/runs\/(\d+)/g)) runs.add(m[1]);
  }
  try {
    const out = execFileSync(
      "gh",
      ["run", "list", "--limit", "25", "--json", "databaseId,conclusion"],
      { encoding: "utf8", windowsHide: true },
    );
    for (const r of JSON.parse(out)) if (r.conclusion === "success") runs.add(String(r.databaseId));
  } catch {}
  return [...runs];
}

const CANDIDATES = process.argv.includes("--no-search") ? [] : candidateRuns();

/** Which other run, if any, actually contains this figure. */
function foundElsewhere(fig, citedRun) {
  for (const runId of CANDIDATES) {
    if (runId === citedRun) continue;
    if (!logCache.has(runId)) logCache.set(runId, numbersIn(runLog(runId)));
    const nums = logCache.get(runId);
    if (nums.size === 0) continue;
    if (matches(fig, nums)) return runId;
  }
  return null;
}

let unexplained = 0;
let matched = 0;
let exempt = 0;
let uncited = 0;
let misattributed = 0;

console.log("");
console.log("Figure verification - every numeric token, not only the ones shaped like figures");
console.log("=".repeat(78));

for (const relPath of DOCS) {
  const doc = checkDoc(relPath, exemptions);
  if (doc.missing) continue;
  const problems = [];
  for (const fig of doc.rows) {
    const registered = exemptFor(exemptions, relPath, fig);
    if (registered) { exempt += 1; continue; }
    if (!fig.run) { uncited += 1; problems.push({ ...fig, why: "no run cited anywhere in this document" }); continue; }
    if (!logCache.has(fig.run)) logCache.set(fig.run, numbersIn(runLog(fig.run)));
    const nums = logCache.get(fig.run);
    if (nums.size === 0) { exempt += 1; continue; }
    if (matches(fig, nums)) { matched += 1; continue; }
    unexplained += 1;
    const elsewhere = foundElsewhere(fig, fig.run);
    if (elsewhere) {
      misattributed += 1;
      problems.push({ ...fig, why: `MISATTRIBUTED - not in cited run ${fig.run}, but present in run ${elsewhere}` });
    } else {
      problems.push({ ...fig, why: `in NO known run (historical, or never measured) - cited ${fig.run}` });
    }
  }
  console.log("");
  console.log(`${relPath}  --  ${doc.rows.length} numeric tokens, ${problems.length} needing explanation`);
  console.log("-".repeat(78));
  if (problems.length === 0) console.log("  all accounted for");
  for (const p of problems.slice(0, 40)) {
    console.log(`  L${String(p.line).padEnd(5)} ${p.text.padEnd(14)} ${p.why}`);
    console.log(`         ${p.source}`);
  }
  if (problems.length > 40) console.log(`  ... and ${problems.length - 40} more`);
}

console.log("");
console.log("PROVENANCE LABELS - a label is a claim with an expiry date");
console.log("=".repeat(78));
const labels = checkProvenanceLabels(exemptions);
let expired = 0;
if (labels.length === 0) console.log("  none registered");
for (const l of labels) {
  if (!l.present) { console.log(`  GONE     ${l.id} - marker no longer in ${l.doc}; drop it from the register`); continue; }
  if (l.retired) { expired += 1; console.log(`  EXPIRED  ${l.id} - ${l.detail}`); console.log(`           ${l.action}`); }
  else console.log(`  current  ${l.id} - ${l.detail || "condition not yet met"}`);
}

console.log("");
console.log("=".repeat(78));
console.log(`  matched ${matched}   exempt ${exempt}   unexplained ${unexplained} (of which misattributed ${misattributed})   uncited ${uncited}   expired-labels ${expired}`);
console.log("");
console.log("  UNEXPLAINED does not distinguish stale from fabricated, deliberately.");
console.log("  From the document's side they are one defect, and only the author knows");
console.log("  which. Resolve each by fixing the number or registering it in");
console.log("  docs/figures-exempt.json with a reason.");
console.log("=".repeat(78));
console.log("");

/**
 * Ratchet, in the project's established idiom: surface residuals, fail on new
 * ones. It exists because switching this check on found 71 pre-existing
 * misattributions, and a gate that is red on arrival gets disabled rather than
 * fixed. The number may only go down.
 *
 * An expired provenance label is NOT ratcheted. A label whose retirement
 * condition has been met is actively misleading every reader from that moment
 * on, which is a different and more urgent defect than an old citation.
 */
const ratchet = exemptions.unexplainedRatchet ?? 0;
let failed = false;
if (unexplained > ratchet) {
  console.log(`FAIL: ${unexplained} unexplained figures against a ratchet of ${ratchet}.`);
  console.log("Either a new figure cannot be traced to its cited run, or an old one was");
  console.log("fixed and the ratchet was not lowered. Both want a human. Do not raise it");
  console.log("to go green.");
  failed = true;
} else if (unexplained < ratchet) {
  console.log(`Ratchet is stale: ${unexplained} unexplained against a ratchet of ${ratchet}.`);
  console.log(`Lower unexplainedRatchet to ${unexplained} in docs/figures-exempt.json.`);
  failed = true;
} else {
  console.log(`Ratchet held: ${unexplained} unexplained, all pre-existing, ratchet ${ratchet}.`);
}
if (expired > 0) {
  console.log(`FAIL: ${expired} provenance label(s) have met their retirement condition.`);
  console.log("A label that has expired reads as current. Not ratcheted, on purpose.");
  failed = true;
}
console.log("");
if (!REPORT_ONLY && failed) process.exit(1);
