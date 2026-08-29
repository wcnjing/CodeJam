/**
 * `npm run bench` — the single benchmark entry point.
 *
 * Two outputs from one run: a human report on stdout, and `bench-results.json`
 * carrying full provenance so a number can be attributed to a build and diffed
 * against the last one.
 *
 * Flags:
 *   --out <path>   where to write the JSON (default: bench-results.json at repo root)
 *   --no-json      human report only
 *   --quick        skip the store sweep and use 2 stability runs
 */

import { writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runBench, type BenchResults, type Proportion } from "./runner.js";

const argv = process.argv.slice(2);
const flag = (name: string) => argv.includes(name);
const value = (name: string): string | undefined => {
  const index = argv.indexOf(name);
  return index === -1 ? undefined : argv[index + 1];
};

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const outPath = path.resolve(value("--out") ?? path.join(repoRoot, "bench-results.json"));

const pct = (value: number) => (value * 100).toFixed(1) + "%";
const rule = (char = "-") => console.log(char.repeat(74));

/** Renders a proportion the way it should always be read: counts, then interval. */
function line(label: string, p: Proportion): void {
  const counts = `${p.numerator}/${p.denominator}`;
  const interval =
    p.zeroUpperBound !== undefined
      ? `<= ${pct(p.zeroUpperBound)} (95% one-sided)`
      : `95% CI ${pct(p.ci.low)}-${pct(p.ci.high)}`;
  console.log(
    "  " + label.padEnd(26) + pct(p.rate).padStart(7) + "  " + counts.padStart(9) + "   " + interval,
  );
}

const results: BenchResults = await runBench({
  skipStore: flag("--quick"),
  stabilityRuns: flag("--quick") ? 2 : 5,
});

const m = results.metadata;
console.log("");
console.log("Sentinel benchmark");
rule("=");
console.log(`  commit      ${m.gitSha ? m.gitSha.slice(0, 12) : "unknown"}${m.gitDirty ? " (dirty)" : ""}`);
console.log(`  policy      ${m.policyHash}`);
console.log(`  corpus      ${m.corpusSize} entries`);
console.log(`  node        v${m.nodeVersion} on ${m.platform}/${m.arch}, ${m.cpuCount} cpu`);
console.log(`  at          ${m.timestamp}`);
rule("=");

console.log("");
console.log("Security                        rate     counts   interval");
rule();
line("Attack block rate", results.security.attackBlockRate);
line("Unsafe-action escape rate", results.security.unsafeActionEscapeRate);
line("Secret leak rate", results.security.secretLeakRate);
line("False positive rate", results.security.falsePositiveRate);
line("Baseline escape (no policy)", results.security.baselineEscapeRate);

console.log("");
console.log("Classifier");
rule();
line("Core recall", results.classifier.coreRecall);
line("Evasion recall", results.classifier.evasionRecall);
line("Blind-set recall", results.classifier.holdoutRecall);
console.log("  " + "Precision".padEnd(26) + pct(results.classifier.precision).padStart(7));
console.log("  " + "F1".padEnd(26) + pct(results.classifier.f1).padStart(7));

console.log("");
console.log("Adversarial sweep and threat register");
rule();
line("Red-team denial rate", results.redteam.denialRate);
line("Verified controls", results.threatModel.coverage);
if (results.redteam.documentedBypasses.length > 0) {
  console.log("  documented bypasses:       " + results.redteam.documentedBypasses.join(", "));
}
if (results.threatModel.open.length > 0) {
  console.log("  open risks:                " + results.threatModel.open.join(", "));
}

console.log("");
console.log("Policy decision latency (microseconds)");
rule();
const l = results.latency.microseconds;
console.log(
  `  p50 ${l.p50.toFixed(2)}   p95 ${l.p95.toFixed(2)}   p99 ${l.p99.toFixed(2)}   mean ${l.mean.toFixed(2)}   ${Math.round(l.throughputPerSec).toLocaleString()}/s`,
);
console.log(
  `  run-to-run CV: p50 ${pct(results.latency.stabilityCv.p50)}  p95 ${pct(results.latency.stabilityCv.p95)}  p99 ${pct(results.latency.stabilityCv.p99)}`,
);
console.log("  (gate on p50; CV is a smell, not a threshold - see plan section 2.2)");

if (results.storeOverhead.points.length > 0) {
  console.log("");
  console.log("Store-write overhead - the cost of RECORDING a decision");
  rule();
  for (const point of results.storeOverhead.points) {
    console.log(
      "  " +
        String(point.preloaded).padStart(6) +
        " events   mutate p50 " +
        (point.mutate.p50 / 1000).toFixed(2).padStart(6) +
        " ms   snapshot p50 " +
        (point.snapshot.p50 / 1000).toFixed(2).padStart(6) +
        " ms",
    );
  }
  const fit = results.storeOverhead.fit;
  console.log(
    `  fixed ${fit.fixedCostMilliseconds.toFixed(2)} ms + ${fit.marginalMicrosecondsPerEvent.toFixed(2)} us/event   (r-squared ${fit.rSquared.toFixed(4)})`,
  );
}

console.log("");
if (!flag("--no-json")) {
  writeFileSync(outPath, JSON.stringify(results, null, 2) + "\n", "utf8");
  console.log("Wrote " + outPath);
}

// The red-team regression gate travels with the benchmark: a new bypass is a
// security regression, and a benchmark that reports one without failing is a
// report, not a gate. Every other figure here is gated by vitest already.
if (results.redteam.regressions.length > 0) {
  console.log("");
  console.log("FAIL: undocumented red-team bypass(es): " + results.redteam.regressions.join(", "));
  process.exit(1);
}
console.log("");
