/**
 * `npm run redteam` — the adversarial probe sweep as a build step.
 *
 * Exits non-zero on a bypass that is not a documented residual. That is what
 * makes it worth running in CI: printing "DENIED 55/56" every push tells nobody
 * anything, but failing the moment a 57th probe slips through is a real gate.
 * The original script always exited 0, so even a total regression would have
 * gone unnoticed.
 */

import { DOCUMENTED_BYPASSES, runRedTeam } from "./redteam.js";

const result = runRedTeam();
const rate = ((result.denied / result.total) * 100).toFixed(1);

console.log("");
console.log("Adversarial probe sweep");
console.log("=".repeat(58));
console.log(`  Probes                 ${String(result.total).padStart(4)}`);
console.log(`  Denied                 ${String(result.denied).padStart(4)}   ${rate}%`);
console.log(`  Bypassed               ${String(result.missed.length).padStart(4)}`);
console.log("=".repeat(58));

if (result.missed.length > 0) {
  console.log("");
  console.log("Bypasses (surfaced, not hidden):");
  for (const probe of result.missed) {
    const documented = DOCUMENTED_BYPASSES.includes(probe.name);
    console.log(`  ${documented ? "~" : "!"} ${probe.name}  ::  ${probe.command}`);
  }
  console.log("");
  console.log("  ~ documented residual   ! REGRESSION");
}

if (result.regressions.length > 0) {
  console.log("");
  console.log("FAIL: undocumented bypass(es): " + result.regressions.join(", "));
  console.log("Either fix the rule, or record the residual in DOCUMENTED_BYPASSES");
  console.log("with a reason. Do not silently widen the allowance.");
  process.exit(1);
}

console.log("");
console.log(
  `All ${result.missed.length} bypass(es) are documented residuals. No regression.`,
);
console.log("");
