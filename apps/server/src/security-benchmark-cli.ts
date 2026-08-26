import { evaluateCommand, policyContextFrom } from "./command-policy.js";
import { POLICY_CORPUS } from "./policy-corpus.js";
import { runBenchmark } from "./security-benchmark.js";

const pct = (v: number) => (v * 100).toFixed(1) + "%";

// Security overhead: policy evaluation latency, measured apart from model time.
function policyLatency(): { p50: number; p95: number; mean: number } {
  const ctx = policyContextFrom("https://ark.cn-beijing.volces.com/api/v3");
  const samples: number[] = [];
  for (let round = 0; round < 50; round += 1) {
    for (const entry of POLICY_CORPUS) {
      const t0 = process.hrtime.bigint();
      evaluateCommand(entry.command, ctx);
      samples.push(Number(process.hrtime.bigint() - t0) / 1000); // microseconds
    }
  }
  samples.sort((a, b) => a - b);
  const at = (q: number) => samples[Math.floor(q * samples.length)]!;
  const mean = samples.reduce((s, x) => s + x, 0) / samples.length;
  return { p50: at(0.5), p95: at(0.95), mean };
}

const protectedRun = runBenchmark("protected");
const baseline = runBenchmark("baseline");
const lat = policyLatency();

console.log("Agent Safety Evaluation");
console.log("─────────────────────────────────");
console.log("Attack tests              " + String(protectedRun.attacks).padStart(6));
console.log("Blocked                   " + String(protectedRun.blocked).padStart(6));
console.log("Unsafe executions         " + String(protectedRun.escaped).padStart(6));
console.log("Attack Block Rate         " + pct(protectedRun.attackBlockRate).padStart(6));
console.log(
  "Unsafe Action Escape Rate " + pct(protectedRun.unsafeActionEscapeRate).padStart(6) + "  <- headline",
);
console.log("");
console.log("Benign tests              " + String(protectedRun.benign).padStart(6));
console.log("Successful                " + String(protectedRun.benign - protectedRun.benignBlocked).padStart(6));
console.log("False Positive Rate       " + pct(protectedRun.falsePositiveRate).padStart(6));
console.log("");
console.log(
  "Secret leaks              " +
    (protectedRun.secretLeaks + "/" + protectedRun.secretAttacks).padStart(6),
);
console.log("");
console.log("Policy latency (excludes model time)");
console.log("  p50                     " + lat.p50.toFixed(1).padStart(6) + " us");
console.log("  p95                     " + lat.p95.toFixed(1).padStart(6) + " us");
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
row("Attack escape rate", pct(baseline.unsafeActionEscapeRate), pct(protectedRun.unsafeActionEscapeRate));
row("Secret leaks", baseline.secretLeaks + "/" + baseline.secretAttacks, protectedRun.secretLeaks + "/" + protectedRun.secretAttacks);
row("Benign success", pct(1 - baseline.falsePositiveRate), pct(1 - protectedRun.falsePositiveRate));

const escapes = protectedRun.cases.filter((c) => c.escaped);
if (escapes.length > 0) {
  console.log("");
  console.log("Escaped attacks (documented residual, not hidden):");
  for (const e of escapes) console.log("  ~ " + e.id + " (" + e.family + ")");
}
console.log("");
console.log("Note: fail-closed is enforced and unit-tested (guardedEvaluate); a policy");
console.log("evaluation error denies the command rather than allowing it through.");
