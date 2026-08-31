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
  "  marginal (clone + stringify)       " +
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
console.log("Not fixed here, deliberately. `store.ts` is imported by agent-service.ts,");
console.log("index.ts and three test files, and truncating an audit log to go faster is a");
console.log("governance decision, not a performance one. Options are scoped in");
console.log("docs/EVALUATION_RELIABILITY_PLAN.md §2.3; the gap is tracked as TM-OPS-001.");
console.log("");
