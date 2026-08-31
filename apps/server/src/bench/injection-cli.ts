/**
 * `npm run bench:injection` — the indirect prompt-injection benchmark.
 *
 * Two rates about two systems, reported separately and never multiplied
 * (`injection.ts` says why, and `describeWhyNoCombinedScore()` prints it here):
 *
 *   ENFORCEMENT  — bulk, no key, every CI job. Given a command is emitted, does
 *                  the policy deny it? This tier runs and is GATED.
 *   ATTEMPT      — live, needs a key and a real workspace. Does the model act on
 *                  the injected instruction at all? Gated behind --live and
 *                  skipped with an explicit message otherwise, exactly like the
 *                  token tier of bench:generate skips off-POSIX.
 *
 * Gate: enforcement is malicious-by-construction, so any allowed command is a
 * bypass. Same convention as generate-cli.ts — surface residuals, fail on any
 * above the ratchet.
 */

import {
  DOCUMENTED_BYPASS_SIGNATURES,
  MAX_KNOWN_BYPASSES,
  describeWhyNoCombinedScore,
  generateRequestedCommands,
  runEnforcement,
  type RequestedCommand,
  type Stratum,
} from "./injection.js";

const pct = (value: number) => (value * 100).toFixed(2) + "%";
const rule = (char = "-") => console.log(char.repeat(78));

function stratumTable(title: string, strata: Stratum[]): void {
  console.log("");
  console.log(title + "  (worst first)");
  rule();
  for (const stratum of strata) {
    const flag = stratum.rate < 1 ? " <--" : "";
    console.log(
      "  " +
        stratum.name.padEnd(22) +
        pct(stratum.rate).padStart(8) +
        "   " +
        `${stratum.denied}/${stratum.total}`.padStart(10) +
        "   95% CI " +
        pct(stratum.ci.low) +
        "-" +
        pct(stratum.ci.high) +
        flag,
    );
  }
}

const wantsLive = process.argv.includes("--live");

const rows = generateRequestedCommands();
const enforcement = runEnforcement(rows);

console.log("");
console.log("Indirect prompt-injection benchmark");
rule("=");
console.log("  An injected instruction hidden in data the Agent reads, asking it to");
console.log("  exfiltrate a secret. Two questions, two systems, two rates:");
console.log("");
for (const line of describeWhyNoCombinedScore()) console.log("  " + line);
rule("=");

console.log("");
console.log("ENFORCEMENT TIER - given a command, does the policy deny it?");
rule("=");
console.log(`  ${enforcement.total} requested commands, the cross product of ${new Set(rows.map((r) => r.collector)).size}`);
console.log("  collectors x exfil techniques x targeted secrets x agent-shaped rewrites.");
console.log("  Every one reads a protected resource and names a non-allowlisted");
console.log("  destination, so the expected decision is DENY for all of them. This tier");
console.log("  needs no model: it measures the MIDDLEWARE, conditional on a command");
console.log("  being emitted at all.");
rule("=");

stratumTable("BY CARRIER CLASS", enforcement.byCarrierClass);
stratumTable("BY EXFIL TECHNIQUE", enforcement.byPayload);
stratumTable("BY AGENT REWRITE", enforcement.byReproduction);
stratumTable("BY COLLECTOR", enforcement.byCollector);
stratumTable("BY TARGETED SECRET", enforcement.bySecret);

if (enforcement.allowed.length > 0) {
  console.log("");
  console.log(`BYPASSES (${enforcement.allowed.length}) - surfaced, not hidden`);
  rule();
  const bySignature = new Map<string, RequestedCommand[]>();
  for (const row of enforcement.allowed) {
    const signature = `${row.payload}|${row.reproduction}`;
    bySignature.set(signature, [...(bySignature.get(signature) ?? []), row]);
  }
  for (const [signature, group] of bySignature) {
    const known = DOCUMENTED_BYPASS_SIGNATURES.includes(signature);
    console.log(`  ${known ? "~" : "!"} ${signature}  (${group.length} variant(s))`);
    console.log(`      e.g. ${group[0]!.command.slice(0, 96)}`);
  }
  console.log("");
  console.log("  ~ documented residual   ! NEW - regression");
}

console.log("");
rule("=");
console.log(
  `  Enforcement rate: ${enforcement.denied}/${enforcement.total} = ${pct(enforcement.rate)}` +
    `   95% CI ${pct(enforcement.ci.low)}-${pct(enforcement.ci.high)}`,
);
if (enforcement.missUpperBound !== null) {
  console.log(
    `  Zero allowed at n=${enforcement.total}: miss rate <= ${pct(enforcement.missUpperBound)}` +
      " (95%, one-sided exact). Not the same claim as a rate of zero.",
  );
}
console.log("  Read the strata first. A high aggregate can hide one technique at zero,");
console.log("  and the technique at zero is the finding.");
console.log("");
console.log("  Scope: this is enforcement CONDITIONAL ON a command being emitted. An");
console.log("  injection that makes the model write a secret into its PROSE answer never");
console.log("  becomes a command, takes no policy decision, and is invisible here. That");
console.log("  path is the live tier's job, and the report says so rather than implying");
console.log("  this number covers it.");
rule("=");

// ----------------------------------------------------------------- live tier

console.log("");
console.log("ATTEMPT TIER - does the model act on the injection at all?");
rule("=");
if (!wantsLive) {
  console.log("  SKIPPED: needs --live, a model key, and a real workspace to plant");
  console.log("  fixtures in. It measures a property of the MODEL, not of this project,");
  console.log("  so it is small-n, slow, and moves when the vendor ships a checkpoint we");
  console.log("  do not control. Run `npm run bench:injection -- --live` with a key set.");
  console.log("  The enforcement tier above is what gates CI.");
} else {
  console.log("  --live requested. Not wired in this build: no key was available to");
  console.log("  capture real attempts from, and a synthesized attempt rate would be a");
  console.log("  fabricated measurement of someone else's model. Left explicitly unbuilt");
  console.log("  rather than faked. See the plan for the fixture-plant/ask/observe loop.");
  process.exitCode = 2;
}
rule("=");

// ---------------------------------------------------------------------- gate

const newSignatures = [
  ...new Set(
    enforcement.allowed
      .map((row) => `${row.payload}|${row.reproduction}`)
      .filter((signature) => !DOCUMENTED_BYPASS_SIGNATURES.includes(signature)),
  ),
];

console.log("");
if (newSignatures.length > 0) {
  console.log("FAIL: enforcement bypass signature(s) not previously documented: " + newSignatures.join(", "));
  console.log("Either the rules regressed or the generator reached new ground. Both are");
  console.log("worth a human look. Do not widen DOCUMENTED_BYPASS_SIGNATURES silently.");
  process.exit(1);
}
if (enforcement.allowed.length > MAX_KNOWN_BYPASSES) {
  console.log(
    `FAIL: ${enforcement.allowed.length} bypasses against a ratchet of ${MAX_KNOWN_BYPASSES}.`,
  );
  console.log("The signatures are known but the count grew, so more of the space escapes.");
  process.exit(1);
}
console.log(
  `Gate passed: ${enforcement.allowed.length} enforcement bypass(es), all documented,` +
    ` ratchet ${MAX_KNOWN_BYPASSES}.`,
);
console.log("");
