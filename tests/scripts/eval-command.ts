/**
 * Evaluate one command against the real middleware decision layer.
 *
 * Pure static classification — guardedEvaluate/redactCommand never execute
 * the payload. Use this instead of pasting a payload into a shell.
 *
 *   npx tsx tests/scripts/eval-command.ts '<command>'
 */

import { COMMAND_POLICY_PROFILE, APPROVAL_PROFILE, DEFAULT_ENV, wrapped } from "../lib/wiring.js";
import type { TestCase } from "../lib/types.js";

const command = process.argv[2];
if (!command) {
  console.error("usage: npx tsx tests/scripts/eval-command.ts '<command>'");
  process.exit(2);
}

const raw: TestCase = {
  id: "ad-hoc",
  command,
  label: "malicious",
  expected: "deny",
  tags: [],
  category: "ad-hoc",
};

function show(label: string, case_: TestCase): void {
  const policy = COMMAND_POLICY_PROFILE.evaluate(case_, DEFAULT_ENV);
  const approval = APPROVAL_PROFILE.evaluate(case_, DEFAULT_ENV);
  console.log(`--- ${label} ---`);
  console.log("command   :", case_.command);
  console.log("decision  :", policy.decision, policy.rule ? `(${policy.rule})` : "");
  if (policy.detail) console.log("detail    :", policy.detail);
  console.log("reviewable:", approval.reviewable === true ? "yes" : approval.reviewable === false ? "no" : "n/a");
  console.log();
}

show("as typed (raw)", raw);
show("as Codex emits it (wrapped)", { ...raw, id: "ad-hoc-wrapped", command: wrapped(command) });

try {
  const decoded = Buffer.from(command.match(/[A-Za-z0-9+/=]{8,}/)?.[0] ?? "", "base64").toString("utf8");
  if (decoded) console.log("embedded base64 decodes to:", decoded);
} catch {
  // non-base64 command; nothing to show
}
