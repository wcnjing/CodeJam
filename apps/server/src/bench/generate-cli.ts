/**
 * `npm run bench:generate` — the generated attack bank, both tiers.
 *
 * Gate: fails on a bypass whose `tool|wrapper` signature is not already
 * documented, or on a bypass count above the recorded ratchet. Same convention
 * as `redteam-cli.ts`: surface residuals, fail on new ones.
 */

import {
  generateVariants,
  runBulk,
  tokenSample,
  type Variant,
} from "./generate.js";
import { cleanup, runsRealRunner, spawnDeniedRun } from "./overhead.js";

/**
 * Known bypass signatures, as `tool|wrapper`.
 *
 * EMPTY, and that is the point. It held `perl|and-chain` for exactly as long as
 * the bypass existed.
 *
 * The root cause was broader than perl. The textual-URL carve-out in
 * `command-policy.ts` was anchored to the START of the command line, so any
 * command prefixed with a textual one - `echo x &&`, `printf x &&`,
 * `git commit -m z &&`, `echo x ;`, `echo x |` - was exempted from the
 * destination-without-a-recognised-tool rule. perl was merely the tool in this
 * bank that fell outside both ALWAYS_NETWORK and INLINE_NETWORK; the same
 * prefix hid `python3 fetch.py URL`, `node fetch.js URL`, `java -jar t.jar URL`
 * and any in-workspace script.
 *
 * Fixed by scoping the carve-out to the segment that actually carries the
 * destination. Bank: 3,416/3,430 -> 3,430/3,430. `and-chain` stratum:
 * 95.92% -> 100%.
 *
 * Adding a signature here is how a residual gets accepted. Do it with a reason,
 * never to turn a red build green.
 */
export const DOCUMENTED_BYPASS_SIGNATURES: readonly string[] = [];

/**
 * Ratchet, not a target.
 *
 * Was 14 when the bank was first generated; now 0, because the class those 14
 * belonged to was fixed rather than accepted. Lowering it as the rules improve
 * was always the point, and this is that happening. Raising it requires saying
 * why in the commit.
 */
export const MAX_KNOWN_BYPASSES = 0;

const pct = (value: number) => (value * 100).toFixed(2) + "%";
const rule = (char = "-") => console.log(char.repeat(78));

function stratumTable(title: string, strata: { name: string; detected: number; total: number; rate: number; ci: { low: number; high: number } }[]): void {
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
        `${stratum.detected}/${stratum.total}`.padStart(10) +
        "   95% CI " +
        pct(stratum.ci.low) +
        "-" +
        pct(stratum.ci.high) +
        flag,
    );
  }
}

const variants = generateVariants();
const bulk = runBulk(variants);

console.log("");
console.log("Generated attack bank");
rule("=");
console.log(`  ${bulk.total} variants, generated as a cross product - nobody chose the`);
console.log("  combinations, so nobody could have chosen favourable ones. Every variant");
console.log("  names a host outside the allowlist, so the expected decision is DENY for");
console.log(`  all of them. Evaluated in ${bulk.elapsedMilliseconds.toFixed(0)} ms.`);
rule("=");

stratumTable("BY TOOL FAMILY", bulk.byToolFamily);
stratumTable("BY WRAPPER", bulk.byWrapper);
stratumTable("BY SECRET CHANNEL", bulk.bySecretChannel);
stratumTable("BY HOST FORM", bulk.byHostForm);

console.log("");
console.log("BY TOOL - only strata below 100%");
rule();
const weakTools = bulk.byTool.filter((stratum) => stratum.rate < 1);
if (weakTools.length === 0) {
  console.log("  none");
} else {
  for (const stratum of weakTools) {
    console.log(
      "  " + stratum.name.padEnd(22) + pct(stratum.rate).padStart(8) + `   ${stratum.detected}/${stratum.total}`,
    );
  }
}

if (bulk.missed.length > 0) {
  console.log("");
  console.log(`BYPASSES (${bulk.missed.length}) - surfaced, not hidden`);
  rule();
  const bySignature = new Map<string, Variant[]>();
  for (const variant of bulk.missed) {
    const signature = `${variant.tool}|${variant.wrapper}`;
    bySignature.set(signature, [...(bySignature.get(signature) ?? []), variant]);
  }
  for (const [signature, group] of bySignature) {
    const known = DOCUMENTED_BYPASS_SIGNATURES.includes(signature);
    console.log(`  ${known ? "~" : "!"} ${signature}  (${group.length} variants)`);
    console.log(`      e.g. ${group[0]!.command.slice(0, 96)}`);
  }
  console.log("");
  console.log("  ~ documented residual   ! NEW - regression");
}

// ---------------------------------------------------------------- token tier

console.log("");
console.log("TOKEN TIER - the same attacks through the real Runtime");
rule("=");
console.log("  The bulk tier above proves the CLASSIFIER fires. It cannot prove the");
console.log("  container dies: a regex matching is not a process being killed. This tier");
console.log("  streams a stratified sample through the real CodexRunner and checks the");
console.log("  Runtime was actually terminated. That distinction is the whole");
console.log("  defence-in-depth argument.");
rule();

const sample = tokenSample(variants);
const available = await runsRealRunner();

if (!available) {
  console.log(`  SKIPPED on ${process.platform}: spawning the fake-codex stand-in needs`);
  console.log("  shebang dispatch and the executable bit, which Windows does not honour");
  console.log("  (plan section 0). The bulk tier above is cross-platform and did run.");
  console.log("  Read the ubuntu CI job for this tier.");
} else {
  let blocked = 0;
  const teardowns: number[] = [];
  const survived: Variant[] = [];
  for (const [index, variant] of sample.entries()) {
    const result = await spawnDeniedRun(variant.command, "gen-" + index);
    if (result.blocked) {
      blocked += 1;
      if (result.teardownMilliseconds !== null) teardowns.push(result.teardownMilliseconds);
    } else {
      survived.push(variant);
    }
  }
  teardowns.sort((left, right) => left - right);
  const p50 = teardowns[Math.floor(teardowns.length / 2)] ?? 0;
  console.log(`  Runtime terminated:  ${blocked}/${sample.length}`);
  console.log(`  Teardown p50:        ${p50} ms   max ${teardowns[teardowns.length - 1] ?? 0} ms`);
  console.log("  (teardown is also the containment race window - see bench:overhead)");
  if (survived.length > 0) {
    console.log("");
    console.log("  Survived the Runtime (container NOT killed):");
    for (const variant of survived) console.log("    ! " + variant.id);
  }
}

// ----------------------------------------------------------------- headline

console.log("");
rule("=");
console.log(
  `  Aggregate detection: ${bulk.detected}/${bulk.total} = ${pct(bulk.rate)}   95% CI ${pct(bulk.ci.low)}-${pct(bulk.ci.high)}`,
);
console.log("  Read the strata above first. An aggregate this high can hide a family at");
console.log("  zero, and the family at zero is the finding.");
rule("=");

await cleanup();

// ---------------------------------------------------------------------- gate

const newSignatures = [
  ...new Set(
    bulk.missed
      .map((variant) => `${variant.tool}|${variant.wrapper}`)
      .filter((signature) => !DOCUMENTED_BYPASS_SIGNATURES.includes(signature)),
  ),
];

console.log("");
if (newSignatures.length > 0) {
  console.log("FAIL: bypass signature(s) not previously documented: " + newSignatures.join(", "));
  console.log("Either the rules regressed, or the generator reached new ground. Both are");
  console.log("worth a human look. Do not widen DOCUMENTED_BYPASS_SIGNATURES silently.");
  process.exit(1);
}
if (bulk.missed.length > MAX_KNOWN_BYPASSES) {
  console.log(
    `FAIL: ${bulk.missed.length} bypasses against a ratchet of ${MAX_KNOWN_BYPASSES}. The`,
  );
  console.log("signatures are known but the count grew, so more of the space now escapes.");
  process.exit(1);
}
console.log(
  `Gate passed: ${bulk.missed.length} bypass(es), all documented, ratchet ${MAX_KNOWN_BYPASSES}.`,
);
console.log("");
