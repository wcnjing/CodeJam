/**
 * Pentest suite runner.
 *
 *   npx tsx tests/runner.ts                     # all suites
 *   npx tsx tests/runner.ts --suite baseline    # one suite
 *   npx tsx tests/runner.ts --suite baseline,command-policy
 *   npx tsx tests/runner.ts --perf              # perf only
 *   npx tsx tests/runner.ts --out /tmp/scores   # different scores dir
 *
 * Every suite score is saved as JSON under tests/scores/ (the `scores`
 * folder AGENTS.md requires) plus a summary.json with the headline numbers.
 */

import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { BASELINE_SUITE } from "./suites/baseline.suite.js";
import { COMMAND_POLICY_SUITE } from "./suites/command-policy.suite.js";
import { REDACTION_SUITE } from "./suites/redaction.suite.js";
import { BUDGET_SUITE } from "./suites/budget.suite.js";
import { APPROVAL_SUITE } from "./suites/approval.suite.js";
import { MONITOR_SUITE } from "./suites/monitor.suite.js";
import { CONFIG_INVARIANTS_SUITE } from "./suites/config-invariants.suite.js";
import { REGRESSION_SUITE } from "./suites/regression.suite.js";
import { runPerfSuite } from "./suites/perf.suite.js";
import { SCORES_DIR, renderSuite, saveScore } from "./lib/report.js";
import { pct } from "./lib/report.js";
import type { SuiteResult } from "./lib/types.js";

const ALL_SUITES = [
  BASELINE_SUITE,
  COMMAND_POLICY_SUITE,
  REDACTION_SUITE,
  BUDGET_SUITE,
  APPROVAL_SUITE,
  MONITOR_SUITE,
  CONFIG_INVARIANTS_SUITE,
  REGRESSION_SUITE,
];

function parseArgs(argv: string[]): { suites: string[]; perf: boolean; out: string } {
  const suites: string[] = [];
  let perf = false;
  let out = SCORES_DIR;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--suite") {
      const value = argv[i + 1];
      if (!value) throw new Error("--suite requires a value");
      suites.push(...value.split(",").map((s) => s.trim()).filter(Boolean));
      i += 1;
    } else if (arg === "--perf") {
      perf = true;
    } else if (arg === "--out") {
      const value = argv[i + 1];
      if (!value) throw new Error("--out requires a value");
      out = path.resolve(value);
      i += 1;
    } else {
      throw new Error("unknown argument: " + arg);
    }
  }
  return { suites, perf, out };
}

async function main(): Promise<void> {
  const { suites, perf, out } = parseArgs(process.argv.slice(2));
  await mkdir(out, { recursive: true });
  const results: SuiteResult[] = [];

  const wanted = new Set(suites);
  const toRun = suites.length === 0 ? ALL_SUITES : ALL_SUITES.filter((s) => wanted.has(s.id));
  if (suites.length > 0 && toRun.length !== suites.length) {
    const known = new Set(ALL_SUITES.map((s) => s.id));
    const unknown = suites.filter((id) => !known.has(id));
    throw new Error("unknown suite(s): " + unknown.join(", "));
  }

  console.log("Sentinel middleware pentest suite");
  console.log("cases: loading catalog from tests/cases/*.json");
  console.log("suites: " + toRun.map((s) => s.id).join(", "));

  for (const suite of toRun) {
    process.stdout.write("running " + suite.id + " ... ");
    const result = await suite.run();
    process.stdout.write("done\n");
    console.log(renderSuite(result));
    const file = await saveScore(suite.id, result);
    console.log("  saved " + path.relative(process.cwd(), file));
    results.push(result);
  }

  if (perf || toRun.length === 0) {
    const perfResult = await runPerfSuite();
    console.log(perfResult.rendered);
    const file = await saveScore("perf", perfResult.report);
    console.log("  saved " + path.relative(process.cwd(), file));
  }

  if (results.length > 0) {
    const summary = {
      generatedAt: new Date().toISOString(),
      headline: Object.fromEntries(
        results.map((r) => [
          r.profileId,
          {
            suite: r.suite,
            cases: r.totals.cases,
            attackBlockRate: r.totals.attackBlockRate,
            escapeRate: r.totals.escapeRate,
            falsePositiveRate: r.totals.falsePositiveRate,
          },
        ]),
      ),
    };
    const file = path.join(out, "summary.json");
    await writeFile(file, JSON.stringify(summary, null, 2) + "\n", "utf8");
    console.log("  saved " + path.relative(process.cwd(), file));
    console.log("");
    console.log("Headline (baseline vs protected):");
    const baseline = results.find((r) => r.profileId === "none");
    const protectedRun = results.find((r) => r.profileId === "all");
    if (baseline && protectedRun) {
      console.log("  attack block rate   " + pct(baseline.totals.attackBlockRate) + " -> " + pct(protectedRun.totals.attackBlockRate));
      console.log("  escape rate         " + pct(baseline.totals.escapeRate) + " -> " + pct(protectedRun.totals.escapeRate));
      console.log("  false positives     " + pct(baseline.totals.falsePositiveRate) + " -> " + pct(protectedRun.totals.falsePositiveRate));
    }
  }

  // Baseline "failures" are the measurement (everything escapes), not a
  // regression signal; gate the exit code on the protected layers only.
  const gateFailures = results
    .filter((r) => r.profileId !== "none")
    .flatMap((r) => r.verdicts.filter((v) => !v.matchesExpected).map((v) => r.profileId + ":" + v.caseId));
  if (gateFailures.length > 0) {
    console.log("");
    console.log("Failed verdicts (" + gateFailures.length + "):");
    for (const f of gateFailures.slice(0, 40)) console.log("  x " + f);
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
