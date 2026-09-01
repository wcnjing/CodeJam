#!/usr/bin/env node
/**
 * The Windows failure baseline, as a gate — `npm run test:windows-baseline`.
 *
 * `npm run test` is red on Windows for POSIX-only reasons documented in
 * docs/EVALUATION_RELIABILITY_PLAN.md §0. That is a platform defect in the
 * TESTS, not in the product, and the CI leg exists to keep both platform claims
 * resting on the same public evidence.
 *
 * What it replaces is a number in a workflow comment. "Expected: 12 failures"
 * was accurate when written and silently wrong by the time the suite had grown
 * — the README said ~20, the workflow said 12, and nothing compared either
 * against a run. A count that drifts silently is worse than no gate: it reads as
 * verified when nothing verified it.
 *
 * So the count is stored, and drift fails in BOTH directions:
 *
 *   MORE failures  a POSIX-only assumption was added. Fix the test, or widen
 *                  the baseline deliberately and say so.
 *   FEWER failures a POSIX-only assumption was fixed. Lower the baseline, or
 *                  the gate stops meaning anything.
 *
 * Same shape as the ratchets this project already uses for the generated attack
 * bank and the figure contract, and for the same reason: a threshold nobody can
 * move by accident.
 *
 * Runs the server workspace only. The web and evaluation workspaces are
 * platform-clean and a failure in either is a real failure, caught by the
 * ordinary `npm run test` step.
 */
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const BASELINE_PATH = path.join(ROOT, ".github", "windows-baseline.json");
const SERVER = path.join(ROOT, "apps", "server");

const baseline = JSON.parse(await readFile(BASELINE_PATH, "utf8"));

if (process.platform !== "win32" && !process.env.FORCE_WINDOWS_BASELINE) {
  console.log("");
  console.log(`  SKIP  the Windows baseline is a claim about win32; this is ${process.platform}.`);
  console.log("        Set FORCE_WINDOWS_BASELINE=1 to run it anyway (it will fail:");
  console.log("        POSIX hosts pass the tests this baseline expects to fail).");
  console.log("");
  process.exit(0);
}

const outputDir = await mkdtemp(path.join(tmpdir(), "windows-baseline-"));
const outputFile = path.join(outputDir, "results.json");

try {
  // vitest exits non-zero when tests fail, which is the expected case here, so
  // the exit code is not the signal — the report is.
  await execFileAsync(
    process.execPath,
    [path.join(ROOT, "node_modules", "vitest", "vitest.mjs"), "run", "--reporter=json", "--outputFile", outputFile],
    { cwd: SERVER, timeout: 600_000, maxBuffer: 64 * 1024 * 1024, windowsHide: true },
  ).catch((error) => {
    // Only a missing report is fatal; a non-zero exit with a report is normal.
    if (!error?.stdout && !error?.stderr) throw error;
  });

  const report = JSON.parse(await readFile(outputFile, "utf8"));
  const actualByFile = {};
  for (const file of report.testResults ?? []) {
    const failed = (file.assertionResults ?? []).filter((a) => a.status === "failed").length;
    if (failed > 0) actualByFile[path.basename(file.name)] = failed;
  }
  const actualTotal = report.numFailedTests ?? 0;

  console.log("");
  console.log("Windows POSIX-only failure baseline");
  console.log("-".repeat(74));
  console.log(`  measured on ${baseline.measuredOn.commit} · node ${baseline.measuredOn.node}`);
  console.log("-".repeat(74));

  const files = new Set([...Object.keys(baseline.byFile), ...Object.keys(actualByFile)]);
  let drifted = 0;
  for (const file of [...files].sort()) {
    const expected = baseline.byFile[file]?.failed ?? 0;
    const actual = actualByFile[file] ?? 0;
    const ok = expected === actual;
    if (!ok) drifted += 1;
    const cause = baseline.byFile[file]?.cause ?? "NOT IN BASELINE";
    console.log(
      `  ${ok ? "PASS" : "DRIFT"}  ${file.padEnd(34)} ${String(actual).padStart(2)} / ${String(expected).padEnd(2)}  ${cause}`,
    );
  }

  console.log("-".repeat(74));
  console.log(
    `  total ${actualTotal} failed of ${report.numTotalTests ?? "?"}  (baseline ${baseline.failedTests} of ${baseline.totalTests})`,
  );

  if (drifted === 0 && actualTotal === baseline.failedTests) {
    console.log("  Baseline held. Every failure is a known POSIX-only assumption.");
    console.log("");
    process.exit(0);
  }

  console.log("");
  if (actualTotal > baseline.failedTests) {
    console.log("  FAIL: MORE failures than the baseline.");
    console.log("  A POSIX-only assumption was probably added, or something really broke on");
    console.log("  Windows. Read the drifted files above. Prefer fixing the test to widening");
    console.log("  the baseline; if widening is right, do it in the same commit and say so.");
  } else {
    console.log("  FAIL: FEWER failures than the baseline.");
    console.log("  Something was fixed and .github/windows-baseline.json was not lowered to");
    console.log("  match. Lower it, or this gate stops being able to detect the next");
    console.log("  regression.");
  }
  console.log("");
  process.exit(1);
} finally {
  await rm(outputDir, { recursive: true, force: true });
}
