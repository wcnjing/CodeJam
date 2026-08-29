/**
 * `npm run bench:overhead` — what the policy layer costs per Run.
 *
 * Prints the three costs separately. Collapsing them into one number would be
 * the dishonest move: the decision is microseconds and flat, the store write is
 * milliseconds and grows with everything recorded before it, and the teardown
 * window is a safety number that happens to be measured in time.
 */

import { cleanup, measureOverhead } from "./overhead.js";

const rule = (char = "-") => console.log(char.repeat(74));
const us = (value: number) => value.toFixed(2) + " us";

const result = await measureOverhead();

console.log("");
console.log("Policy overhead per Run");
console.log(`platform ${result.platform}, node ${result.nodeVersion}`);
rule("=");

console.log("");
console.log("1. DECISION - policy on vs policy off, over one run's commands");
console.log("   Paired A/B at the scanCommandsWith seam. policy-off runs the same");
console.log("   loop with the evaluator replaced, so the delta is the decision only.");
rule();
console.log("   cmds/run     policy-on p50    policy-off p50    delta      per command");
for (const point of result.scan) {
  const perCommand = point.deltaMicroseconds / point.commandsPerRun;
  console.log(
    "   " +
      String(point.commandsPerRun).padStart(8) +
      "     " +
      us(point.policyOn.p50).padStart(12) +
      "     " +
      us(point.policyOff.p50).padStart(12) +
      "  " +
      us(point.deltaMicroseconds).padStart(10) +
      "   " +
      us(perCommand).padStart(9),
  );
}

console.log("");
console.log("2. STORE - the cost of RECORDING a decision");
rule();
console.log("   Not re-measured here. `npm run bench:store` owns this number, and");
console.log("   two harnesses measuring the same thing would eventually disagree.");
console.log("   It is O(policy events already stored), reaching ~11-16 ms at 5000");
console.log("   events in CI - three orders of magnitude above the decision above,");
console.log("   and the dominant cost of the middleware in a running system.");

console.log("");
console.log("3. TEARDOWN - denied command emitted -> Runtime process dead");
console.log("   Also the containment race window the README lists under Limitations:");
console.log("   for this long, a denied Agent is still executing.");
rule();
if (result.teardown) {
  console.log(
    `   p50 ${result.teardown.p50Milliseconds} ms   max ${result.teardown.maxMilliseconds} ms   (n=${result.teardown.samples})`,
  );
  console.log("   observations: " + result.teardown.observations.join(", ") + " ms");
} else {
  console.log("   not measured on this platform - see the note below.");
}

if (result.wallClock.length > 0) {
  console.log("");
  console.log("Denominator - full CodexRunner.run() wall clock, policy on");
  rule();
  for (const point of result.wallClock) {
    const scan = result.scan.find((entry) => entry.commandsPerRun === point.commandsPerRun);
    const share =
      scan && point.p50Milliseconds > 0
        ? (scan.deltaMicroseconds / 1000 / point.p50Milliseconds) * 100
        : 0;
    console.log(
      "   " +
        String(point.commandsPerRun).padStart(3) +
        " cmds   run p50 " +
        point.p50Milliseconds.toFixed(1).padStart(7) +
        " ms   decision is " +
        share.toFixed(4) +
        "% of it",
    );
  }
  console.log("");
  console.log("   The honest framing of \"the policy layer is free\": the DECISION is");
  console.log("   free relative to a real turn. The store write is not, and it is the");
  console.log("   one that grows.");
}

if (!result.realRunnerAvailable) {
  console.log("");
  rule("=");
  console.log("  Sections 3 and the denominator were SKIPPED on this platform.");
  console.log("");
  console.log("  They spawn the fake-codex stand-in, which relies on shebang dispatch");
  console.log("  and the executable bit. Windows honours neither, so the spawn throws");
  console.log("  EFTYPE - the same POSIX-only assumption behind 11 of the 12 known");
  console.log("  Windows test failures (plan section 0).");
  console.log("");
  console.log("  This is declared, not discovered: the harness detects it and skips,");
  console.log("  rather than reporting a wrong number or crashing. Section 1 above is");
  console.log("  cross-platform and did run. Run this on Linux or macOS, or read the");
  console.log("  ubuntu CI job, for the full picture.");
  rule("=");
}

console.log("");
await cleanup();
