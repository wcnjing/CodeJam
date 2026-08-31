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
 *   UNCITED     the number cites no run anywhere in its document, so there is
 *               nothing to check it against. Ratcheted separately, because a
 *               shared total lets a fixed misattribution make room for a
 *               fabricated uncited number with the gate still green.
 *   UNVERIFIED  the cited run's log could not be READ -- `gh` missing, token
 *               expired, rate limited, wrong repository. Nothing may be
 *               concluded, so nothing is: not ratcheted, always a failure.
 *   UNEXPLAINED everything else. This is the failure state, and it does not
 *               distinguish "stale" from "fabricated" on purpose: from the
 *               document's point of view they are the same defect, and the
 *               author is the only one who can say which it was.
 *
 * UNEXPLAINED is the point. A number that cannot be found in its own cited run
 * must be explained by a human, in a file, in words. It cannot be resolved by
 * being plausible.
 *
 * UNVERIFIED exists because the reverse failure is worse than a wrong figure. A
 * check that cannot reach its evidence and reports success has not been lenient
 * -- it has lied about having looked. So an unreadable log fails the gate
 * outright, and is never cached: caching one turns a transient outage into a
 * permanent pass on every later run.
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

/**
 * Runs whose logs could not be read for an OPERATIONAL reason: `gh` missing,
 * unauthenticated, rate-limited, pointed at the wrong repository, or the API
 * simply unreachable. Kept apart from a verifiably expired log because the two
 * mean opposite things. An expired log is a fact about the world; a failed
 * fetch is a fact about this machine, and treating it as evidence is how a gate
 * passes without checking anything.
 */
const operationalFailures = new Map();

/**
 * Read one run's log, distinguishing three outcomes rather than two.
 *
 *   ok      the log was fetched (and cached; logs are immutable once written).
 *   gone    the RUN is reachable but its log is not — expired or deleted.
 *           A verified fact, and not a document defect: figures citing it are
 *           exempt.
 *   error   anything else. The fetch failed for a reason that says nothing
 *           about the run, so nothing may be concluded from it. Fails the gate.
 *
 * The old code collapsed `gone` and `error` into "empty log", and an empty log
 * was read as "exempt". With the ratchet at zero that made the whole evidence
 * gate pass whenever `gh` was missing, the token had expired, or the API was
 * rate-limiting — the check reporting success precisely when it had checked
 * nothing. Failed fetches are also no longer cached: caching one turns a
 * transient outage into a permanent lie for every later run on that machine.
 */
function runLog(runId) {
  mkdirSync(CACHE, { recursive: true });
  const cached = path.join(CACHE, `${runId}.log`);
  if (existsSync(cached)) return { text: readFileSync(cached, "utf8"), status: "ok" };
  process.stderr.write(`  fetching run ${runId} ...\n`);
  try {
    const text = execFileSync("gh", ["run", "view", runId, "--log"], {
      encoding: "utf8",
      maxBuffer: 256 * 1024 * 1024,
      windowsHide: true,
    });
    writeFileSync(cached, text, "utf8");
    return { text, status: "ok" };
  } catch (error) {
    const detail = String(error?.stderr || error?.message || error).trim().split("\n")[0];
    // The only way to tell "this run's log has expired" from "I cannot talk to
    // GitHub" is to ask about the run itself. If the run's metadata comes back,
    // the API, the credential and the repository are all fine and it is the log
    // that is gone. If it does not, nothing here is trustworthy.
    if (runExists(runId)) {
      process.stderr.write(`  run ${runId}: log no longer available (run itself is reachable)\n`);
      return { text: "", status: "gone" };
    }
    process.stderr.write(`  ERROR: could not read run ${runId} - ${detail}\n`);
    operationalFailures.set(runId, detail);
    return { text: "", status: "error" };
  }
}

function runExists(runId) {
  try {
    execFileSync("gh", ["run", "view", runId, "--json", "databaseId"], {
      encoding: "utf8",
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return true;
  } catch {
    return false;
  }
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
  let localBlock = null;
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
    // A block the document itself declares as not-from-CI, with its reason
    // stated inline where a reader sees it:
    //
    //   <!-- figures: local reason="..." -->  ...  <!-- /figures -->
    //
    // This is better than an entry in the external register for anything
    // block-shaped. The register is keyed by value, so exempting a 1.19% that
    // was measured locally would also exempt every other 1.19% in the document.
    // It also puts the provenance in front of the reader rather than in a file
    // they will not open.
    const openMarker = /<!--\s*figures:\s*local\s+reason="([^"]*)"\s*-->/.exec(line);
    if (openMarker) { localBlock = openMarker[1]; continue; }
    if (/<!--\s*\/figures\s*-->/.test(line)) { localBlock = null; continue; }

    // Skip link definitions and the citation lines themselves.
    const stripped = line.replace(/https?:\/\/\S+/g, " ").replace(/`[^`]*`/g, (s) => s);
    if (!stripped.trim()) continue;

    if (localBlock) {
      for (const fig of extractFigures(stripped)) {
        rows.push({ line: i + 1, run: null, ...fig, declaredLocal: localBlock, source: line.trim().slice(0, 100) });
      }
      continue;
    }

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
  } catch (error) {
    // Swallowing this used to look harmless -- the candidate list is only used
    // to tell "misattributed" from "never measured". But it fails for exactly
    // the reasons a log fetch fails, so a silent catch here is the same gate
    // passing blind, one step earlier.
    const detail = String(error?.stderr || error?.message || error).trim().split("\n")[0];
    process.stderr.write(`  ERROR: could not list runs - ${detail}\n`);
    operationalFailures.set("gh run list", detail);
  }
  return [...runs];
}

const CANDIDATES = process.argv.includes("--no-search") ? [] : candidateRuns();

/** The numbers in a run's log, read at most once per process. */
function runNumbers(runId) {
  if (!logCache.has(runId)) {
    const log = runLog(runId);
    logCache.set(runId, { nums: numbersIn(log.text), status: log.status });
  }
  return logCache.get(runId);
}

/** Which other run, if any, actually contains this figure. */
function foundElsewhere(fig, citedRun) {
  for (const runId of CANDIDATES) {
    if (runId === citedRun) continue;
    const { nums, status } = runNumbers(runId);
    if (status !== "ok" || nums.size === 0) continue;
    if (matches(fig, nums)) return runId;
  }
  return null;
}

let unexplained = 0;
let unverified = 0;
let matched = 0;
let exempt = 0;
let uncited = 0;
let misattributed = 0;
let declaredLocal = 0;

console.log("");
console.log("Figure verification - every numeric token, not only the ones shaped like figures");
console.log("=".repeat(78));

for (const relPath of DOCS) {
  const doc = checkDoc(relPath, exemptions);
  if (doc.missing) continue;
  const problems = [];
  for (const fig of doc.rows) {
    if (fig.declaredLocal) { declaredLocal += 1; continue; }
    const registered = exemptFor(exemptions, relPath, fig);
    if (registered) { exempt += 1; continue; }
    if (!fig.run) { uncited += 1; problems.push({ ...fig, why: "no run cited anywhere in this document" }); continue; }
    const { nums, status } = runNumbers(fig.run);
    // Fail closed. An unreadable log is not evidence of anything, so a figure
    // citing one is neither matched nor exempt -- it is unverified, and the
    // gate says so rather than waving it through.
    if (status === "error") {
      unverified += 1;
      problems.push({ ...fig, why: `UNVERIFIED - run ${fig.run} could not be read (see errors above)` });
      continue;
    }
    // A reachable run whose log has expired is a fact about GitHub's retention,
    // not a defect in the document.
    if (status === "gone" || nums.size === 0) { exempt += 1; continue; }
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
console.log(`  matched ${matched}   declared-local ${declaredLocal}   exempt ${exempt}   unexplained ${unexplained} (of which misattributed ${misattributed})   uncited ${uncited}   unverified ${unverified}   expired-labels ${expired}`);
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
let failed = false;

/**
 * One ratchet per defect, never a shared total. A figure that cannot be traced
 * to its cited run and a figure that cites nothing at all are different
 * defects, and a single number lets one absorb the other: fix an old
 * misattribution and a newly fabricated uncited figure slots into the space it
 * left, with the gate still green.
 */
function ratchet(name, count, key, describe) {
  const limit = exemptions[key] ?? 0;
  if (count > limit) {
    console.log(`FAIL: ${count} ${name} against a ratchet of ${limit}.`);
    for (const line of describe) console.log(line);
    console.log("Do not raise the ratchet to go green.");
    failed = true;
  } else if (count < limit) {
    console.log(`Ratchet is stale: ${count} ${name} against a ratchet of ${limit}.`);
    console.log(`Lower ${key} to ${count} in docs/figures-exempt.json.`);
    failed = true;
  } else {
    console.log(`Ratchet held: ${count} ${name}, all pre-existing, ratchet ${limit}.`);
  }
}

ratchet("unexplained figures", unexplained, "unexplainedRatchet", [
  "Either a new figure cannot be traced to its cited run, or an old one was",
  "fixed and the ratchet was not lowered. Both want a human.",
]);

/**
 * Uncited figures are ratcheted too, and that is the whole point of counting
 * them. They used to be reported and then ignored by the failure condition,
 * which left the gate with a door in it: a fabricated number could pass simply
 * by citing nothing, and citing nothing is the easier thing to do. Resolve one
 * by citing the run it came from, declaring the block local, or registering it
 * in the exemption file -- the same three exits every other figure has.
 */
ratchet("uncited figures", uncited, "uncitedRatchet", [
  "A number with no cited run cannot be checked against anything. Cite the run",
  "it came from, wrap the block in a `figures: local` marker with a reason, or",
  "register it in docs/figures-exempt.json.",
]);

/**
 * NOT ratcheted, on purpose. Every count above is a claim about a document;
 * this one is a claim about whether the check ran at all, and a check that
 * could not read its evidence has no business reporting a verdict on it.
 */
if (operationalFailures.size > 0) {
  console.log("");
  console.log(`FAIL: ${operationalFailures.size} run log(s) could not be read at all.`);
  for (const [runId, detail] of operationalFailures) console.log(`  ${runId}: ${detail}`);
  console.log("This is an operational failure, not a document defect: a missing `gh`, an");
  console.log("expired token, a rate limit or the wrong repository. Figures citing those");
  console.log(`runs are counted unverified (${unverified}), never exempt, because an`);
  console.log("unreadable log is not evidence. Fix the environment and re-run.");
  failed = true;
}
if (expired > 0) {
  console.log(`FAIL: ${expired} provenance label(s) have met their retirement condition.`);
  console.log("A label that has expired reads as current. Not ratcheted, on purpose.");
  failed = true;
}
console.log("");
if (!REPORT_ONLY && failed) process.exit(1);
