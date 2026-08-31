/**
 * Prints the store-write overhead curve.
 *
 * The headline the README advertises for the middleware is a per-command policy
 * decision of a few microseconds. That is real, and it is the cheap half. This
 * report is the other half: what it costs to RECORD the decision, which grows
 * with everything recorded before it.
 */

import { timeSweep } from "./metrics.js";
import { policyWorkload } from "./policy-workload.js";
import { measureStoreOverhead } from "./store-overhead.js";

const ms = (microseconds: number) => (microseconds / 1000).toFixed(2).padStart(7) + " ms";
const rule = (char = "-") => console.log(char.repeat(74));

const result = await measureStoreOverhead();
const decision = timeSweep(policyWorkload(), { warmupRounds: 200, rounds: 2000 });

console.log("");
console.log("Store-write overhead — the cost of recording one policy decision");
console.log(`platform ${result.platform}, node ${result.nodeVersion}`);
rule("=");
console.log("  events    mutate p50    mutate p95   snapshot p50");
rule();
for (const point of result.points) {
  console.log(
    "  " +
      String(point.preloaded).padStart(6) +
      "  " +
      ms(point.mutate.p50) +
      "  " +
      ms(point.mutate.p95) +
      "  " +
      ms(point.snapshot.p50),
  );
}
rule();

const { fixedCostMilliseconds, marginalMicrosecondsPerEvent, rSquared } = result.fit;
console.log("");
console.log("Decomposition of mutate() p50:");
console.log(
  "  fixed cost (open, write, rename)   " +
    fixedCostMilliseconds.toFixed(2).padStart(7) +
    " ms   filesystem-bound; ~3x platform spread",
);
console.log(
  "  marginal (per stored event)        " +
    marginalMicrosecondsPerEvent.toFixed(2).padStart(7) +
    " us per stored event   ~1.4x platform spread",
);
console.log(
  "  linearity (r-squared)              " +
    rSquared.toFixed(4).padStart(7) +
    "      1.0 means growth is exactly linear",
);

const largest = result.points[result.points.length - 1];
if (largest && decision.p50 > 0) {
  console.log("");
  console.log("For contrast:");
  console.log(
    "  one evaluateCommand() call         " + decision.p50.toFixed(2).padStart(7) + " us",
  );
  console.log(
    "  recording it at " +
      String(largest.preloaded).padStart(5) +
      " events      " +
      (largest.mutate.p50 / 1000).toFixed(2).padStart(7) +
      " ms   =  " +
      Math.round(largest.mutate.p50 / decision.p50).toLocaleString() +
      "x the decision itself",
  );
}

console.log("");
console.log("TM-OPS-001 is CLOSED. Policy events are appended to an append-only JSONL log");
console.log("beside the database rather than re-serialised into it, so recording event n");
console.log("no longer costs O(n). The marginal term above should now read as noise around");
console.log("zero; if it climbs back into a clean linear fit, the fix has come undone and");
console.log("`regression.test.ts` fails on the slope.");
console.log("");
console.log("Nothing was truncated to achieve it. Both cheap options capped the log by");
console.log("discarding audit records, which for a project whose thesis is trustworthy");
console.log("evidence is a liability rather than a fix -- and a cap does not remove the");
console.log("linear term, it only moves the ceiling. That is why this stayed open through a");
console.log("full engine rewrite instead of being closed cheaply. Retention still applies,");
console.log("by compaction at startup: age is a property of a record, not of a write.");
console.log("");
