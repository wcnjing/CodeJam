#!/usr/bin/env node
/**
 * The zero-config front door.
 *
 * Everything the project claims about its safety layer can be checked here, with
 * no Ark API key, no container engine, no .env and no network. That matters
 * because until now the only way in was `npm run poc`, which needs a model key
 * and a container runtime — so a reviewer with neither saw nothing at all.
 *
 * Runs the three evaluation harnesses in sequence:
 *   eval:policy      classifier scorecard against the labeled corpus
 *   bench:security   escape rate, baseline vs protected, latency
 *   threat-model     threat register coverage
 *
 * This is NOT the deterministic offline demo mode (task 2.3 in
 * docs/EVALUATION_RELIABILITY_PLAN.md). That is a replay runner that substitutes
 * recorded events for a live model so the denial path can be demonstrated. This
 * is a front door for someone who wants to see the numbers without credentials.
 * Both are wanted; they are not the same thing.
 */

import { spawnSync } from "node:child_process";

const STEPS = [
  {
    script: "eval:policy",
    title: "Policy scorecard",
    blurb: "Recall, false positive rate, precision, F1 and blind-set recall over the labeled corpus.",
  },
  {
    script: "bench:security",
    title: "Security benchmark",
    blurb: "Unsafe-action escape rate, per-family results, baseline vs protected, policy latency.",
  },
  {
    script: "threat-model",
    title: "Threat model coverage",
    blurb: "Threat register, and which mitigations are backed by a real test.",
  },
];

const rule = (char = "=") => console.log(char.repeat(74));

console.log("");
rule();
console.log("  Sentinel — offline evaluation");
console.log("  No API key, no container engine, no network required.");
rule();

const failed = [];

for (const [index, step] of STEPS.entries()) {
  console.log("");
  console.log(`[${index + 1}/${STEPS.length}] ${step.title}  —  npm run ${step.script}`);
  console.log(`        ${step.blurb}`);
  rule("-");

  // shell:true so this resolves npm.cmd on Windows as well as npm on POSIX.
  // Passed as one string rather than (command, args): an args array with
  // shell:true is deprecated (DEP0190). The script names are module constants,
  // never user input.
  const result = spawnSync(`npm run --silent ${step.script}`, {
    stdio: "inherit",
    shell: true,
  });

  if (result.status !== 0) failed.push({ ...step, status: result.status });
}

console.log("");
rule();
if (failed.length === 0) {
  console.log("  All three harnesses completed.");
  console.log("");
  console.log("  The thresholds behind these numbers are asserted as tests, not just");
  console.log("  printed: `npm run check` fails the build if any of them regresses.");
  console.log("");
  console.log("  Next: docs/POLICY_EVALUATION.md for the methodology and the defects");
  console.log("  the harness found; docs/THREAT_MODEL.md for the register.");
} else {
  console.log(`  ${failed.length} of ${STEPS.length} harness(es) failed:`);
  for (const step of failed) console.log(`    - npm run ${step.script} (exit ${step.status})`);
}
rule();
console.log("");

process.exit(failed.length === 0 ? 0 : 1);
