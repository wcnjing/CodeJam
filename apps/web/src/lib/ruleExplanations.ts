export type Severity = "critical" | "high" | "review" | "info";

export interface RuleExplanation {
  label: string;
  severity: Severity;
  glyph: string;
  /** Plain-language answer to "why did this happen?" */
  summary: string;
  /** What would have happened if the platform had not intervened. */
  consequence: string;
}

/**
 * Keyed by the `rule` string the policy engine attaches to a PolicyDecision
 * or ApprovalRequest (see apps/server/src/command-policy.ts and
 * agent-service.ts's step-budget-exceeded event). Kept in one place so the
 * decision card and the audit timeline never describe the same rule two
 * different ways.
 */
const RULE_EXPLANATIONS: Record<string, RuleExplanation> = {
  "secret-exfiltration": {
    label: "Secret exfiltration",
    severity: "critical",
    glyph: "◆",
    summary:
      "This command read a protected credential and sent data off the machine in the same step. Reading a secret is allowed on its own, and network calls are allowed on their own — combining both is a hard rule with no review path, because that combination is exactly what a credential theft looks like.",
    consequence:
      "Had this executed, a real credential would have left the Runtime container for a destination the platform does not control.",
  },
  "protected-secret-access": {
    label: "Protected file access",
    severity: "high",
    glyph: "▲",
    summary:
      "This command tried to read, copy, or reveal a file inside a protected path (such as .secrets/) without any network call attached — no evidence yet that anything left the machine, but access to the file itself is denied.",
    consequence:
      "Had this executed, the contents of a protected file would have been exposed in the Agent's next steps or shown in the Run output.",
  },
  "network-egress-denied": {
    label: "Network egress outside the allowlist",
    severity: "review",
    glyph: "●",
    summary:
      "This command contacts a host that is not on the standing allowlist. Some non-allowlisted destinations are plausibly legitimate (a package registry, a docs site), so this class is held for a human decision rather than denied outright.",
    consequence:
      "Left unchecked, the Agent could reach any host reachable from the container's network, not just the ones the operator has vetted.",
  },
  "step-budget-exceeded": {
    label: "Runaway execution stopped",
    severity: "info",
    glyph: "■",
    summary:
      "This Run issued more shell commands than the configured budget allows in a single task. This guard fires regardless of intent — it catches loops and runaway automation just as readily as an attack that tries to hide in volume.",
    consequence:
      "Left unchecked, the Agent could keep issuing commands indefinitely, consuming resources or compounding an early mistake.",
  },
  "policy-error": {
    label: "Policy evaluation failed closed",
    severity: "high",
    glyph: "▲",
    summary:
      "The policy engine hit an internal error while evaluating this command. The platform is fail-closed by design: an evaluation it cannot complete is treated as a denial, not a pass-through.",
    consequence:
      "Had the platform failed open instead, this command would have run with no check applied to it at all.",
  },
};

const fallback: RuleExplanation = {
  label: "Policy decision",
  severity: "high",
  glyph: "▲",
  summary: "The policy engine denied this command under a rule not yet documented here.",
  consequence: "Treat this the same as any other denial: nothing beyond this point ran.",
};

export function explainRule(rule: string): RuleExplanation {
  return RULE_EXPLANATIONS[rule] ?? fallback;
}
