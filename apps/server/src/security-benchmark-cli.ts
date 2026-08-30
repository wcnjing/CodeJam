import { timeSweep } from "./bench/metrics.js";
import { policyWorkload } from "./bench/policy-workload.js";
import { runBenchmark } from "./security-benchmark.js";

const pct = (v: number) => (v * 100).toFixed(1) + "%";

// Security overhead: policy evaluation latency, measured apart from model time.
const policyLatency = () => timeSweep(policyWorkload(), { warmupRounds: 200, rounds: 2000 });

const protectedRun = runBenchmark("protected");
const baseline = runBenchmark("baseline");
const lat = policyLatency();

console.log("Agent Safety Evaluation");
console.log("─────────────────────────────────");
console.log("Attack tests              " + String(protectedRun.attacks).padStart(6));
console.log("Blocked                   " + String(protectedRun.blocked).padStart(6));
console.log("Policy-allowed attacks    " + String(protectedRun.escaped).padStart(6));
console.log("Attack Block Rate         " + pct(protectedRun.attackBlockRate).padStart(6));
console.log(
  "Policy-predicted escape rate " + pct(protectedRun.unsafeActionEscapeRate).padStart(6) + " <- headline",
);
console.log("");
console.log("Benign tests              " + String(protectedRun.benign).padStart(6));
console.log("Successful                " + String(protectedRun.benign - protectedRun.benignBlocked).padStart(6));
console.log("False Positive Rate       " + pct(protectedRun.falsePositiveRate).padStart(6));
console.log("");
console.log(
  "Secret-channel allowed    " +
    (protectedRun.secretLeaks + "/" + protectedRun.secretAttacks).padStart(6),
);
console.log("");
console.log("Policy latency (excludes model time)");
console.log("  p50                     " + lat.p50.toFixed(1).padStart(6) + " us");
console.log("  p95                     " + lat.p95.toFixed(1).padStart(6) + " us");
console.log("  p99                     " + lat.p99.toFixed(1).padStart(6) + " us");
console.log("");
console.log("Per family (escaped / attacks)");
for (const f of protectedRun.byFamily) {
  const mark = f.escaped === 0 ? "✓" : "✗";
  console.log(
    "  " + mark + " " + f.family.padEnd(20) + (f.escaped + "/" + f.attacks).padStart(6),
  );
}

console.log("");
console.log("Baseline (no middleware)  vs  Protected");
console.log("─────────────────────────────────────────");
const row = (label: string, b: string, p: string) =>
  console.log("  " + label.padEnd(26) + b.padStart(9) + p.padStart(12));
row("Policy-predicted escape", pct(baseline.unsafeActionEscapeRate), pct(protectedRun.unsafeActionEscapeRate));
row("Secret-channel allowed", baseline.secretLeaks + "/" + baseline.secretAttacks, protectedRun.secretLeaks + "/" + protectedRun.secretAttacks);
row("Benign success", pct(1 - baseline.falsePositiveRate), pct(1 - protectedRun.falsePositiveRate));

const escapes = protectedRun.cases.filter((c) => c.escaped);
if (escapes.length > 0) {
  console.log("");
  console.log("Policy-allowed attacks (documented residual, not hidden):");
  for (const e of escapes) console.log("  ~ " + e.id + " (" + e.family + ")");
}
console.log("");
console.log("Note: fail-closed is enforced and unit-tested (guardedEvaluate); a policy");
console.log("evaluation error denies the command rather than allowing it through.");
