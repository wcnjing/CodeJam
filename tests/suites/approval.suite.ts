/**
 * Human-approval suite: held runs and the never-reviewable invariant.
 *
 * A denial on a REVIEWABLE_RULES rule (network-egress-denied) may hold the
 * run for a named human; secret-access rules are NEVER reviewable, no matter
 * what POLICY_REVIEW_RULES says (code-level invariant, TM-AGENT-005).
 *
 * The catalog pass scores reviewability correctness per case; invariant
 * checks verify the reviewable set and the config rejection loudly.
 */

import { loadConfig } from "../../apps/server/src/config.js";
import { REVIEWABLE_RULES, isReviewableRule } from "../../apps/server/src/command-policy.js";
import { APPROVAL_PROFILE, DEFAULT_ENV } from "../lib/wiring.js";
import { runProfile } from "../lib/harness.js";
import { loadCatalog } from "../lib/catalog.js";
import type { CaseVerdict } from "../lib/types.js";
import type { SuiteModule } from "./suite.js";

export const APPROVAL_SUITE: SuiteModule = {
  id: "approval",
  name: "Human-approval middleware",
  async run() {
    const cases = await loadCatalog();
    const result = runProfile({ profile: APPROVAL_PROFILE, cases, env: DEFAULT_ENV });

    const extraVerdicts: CaseVerdict[] = [];

    // Invariant: the reviewable set contains exactly the engine's designated
    // reviewable rules — membership-based, so a legitimate engine change
    // (e.g. a new reviewable rule) fails LOUDLY here instead of silently
    // skipping this check (the Critical-1 pattern).
    {
      const required = [
        "file-write-unresolved-target",
        "network-egress-denied",
        "network-egress-denied-implicit",
      ];
      const missing = required.filter((rule) => !REVIEWABLE_RULES.includes(rule));
      const unexpected = REVIEWABLE_RULES.filter((rule) => !required.includes(rule));
      const ok = missing.length === 0 && unexpected.length === 0;
      extraVerdicts.push({
        caseId: "approval-invariant-reviewable-set",
        decision: "n/a",
        rule: null,
        matchesExpected: ok,
        note: ok
          ? "REVIEWABLE_RULES = " + REVIEWABLE_RULES.join(",")
          : "reviewable-set drift: missing=" + missing.join(",") + " unexpected=" + unexpected.join(","),
      });
    }

    // Invariant: no rule except the reviewable one may be human-approved.
    for (const rule of [
      "secret-exfiltration",
      "protected-secret-access",
      "policy-error",
      "encoded-exfiltration",
      "file-write-outside-workspace",
    ]) {
      const ok = !isReviewableRule(rule);
      extraVerdicts.push({
        caseId: "approval-invariant-not-reviewable-" + rule,
        decision: "n/a",
        rule,
        matchesExpected: ok,
        note: ok ? rule + " is never reviewable" : rule + " became reviewable",
      });
    }

    // Invariant: config naming a secret rule is rejected loudly at startup.
    try {
      loadConfig({
        NODE_ENV: "test",
        ARK_API_KEY: "k",
        ARK_MODEL: "ep-test",
        POLICY_REVIEW_RULES: "secret-exfiltration",
      });
      extraVerdicts.push({
        caseId: "approval-invariant-config-rejects-secret-rule",
        decision: "n/a",
        rule: null,
        matchesExpected: false,
        note: "loadConfig accepted secret-exfiltration as a review rule",
      });
    } catch {
      extraVerdicts.push({
        caseId: "approval-invariant-config-rejects-secret-rule",
        decision: "n/a",
        rule: null,
        matchesExpected: true,
        note: "loadConfig rejected a non-reviewable rule",
      });
    }

    const verdicts = [...result.verdicts, ...extraVerdicts];
    const passed = verdicts.filter((v) => v.matchesExpected).length;
    return {
      ...result,
      suite: "approval",
      verdicts,
      totals: { ...result.totals, cases: verdicts.length, passed, failed: verdicts.length - passed },
    };
  },
};
