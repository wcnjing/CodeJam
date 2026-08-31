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
 * The live policy configuration, so the copy can describe what THIS deployment
 * does rather than what the default one does.
 *
 * Whether a denial is held for a human or blocked outright is a configuration
 * answer (`POLICY_REVIEW_RULES`), and in monitor mode nothing is stopped at
 * all — the decision is recorded and the command runs. Hard-coding "this class
 * is held for a human decision" into the rule text made the UI assert one
 * deployment's behaviour as a property of the rule.
 */
export interface PolicyMode {
  enforcement: string;
  reviewRules: string[];
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
      "This command contacts a host that is not on the standing allowlist. Some non-allowlisted destinations are plausibly legitimate (a package registry, a docs site), which is why this class is one a human is permitted to review.",
    consequence:
      "Left unchecked, the Agent could reach any host reachable from the container's network, not just the ones the operator has vetted.",
  },
  "network-egress-denied-implicit": {
    label: "Destination named without a recognised network tool",
    severity: "review",
    glyph: "●",
    summary:
      "This command names a host that is not on the allowlist, but no recognised network tool alongside it. That shape is how an obfuscated command hides its binary: the binary can be disguised or built at runtime, the destination cannot.",
    consequence:
      "Left unchecked, an egress tool spelled in a way the platform does not recognise would reach a host the operator never vetted.",
  },
  "file-write-outside-workspace": {
    label: "Write outside the sandbox",
    severity: "critical",
    glyph: "◆",
    summary:
      "This command writes to a path that resolves outside the Run's workspace — after `..` segments and shell expansions are taken into account. There is no review path for this class: an out-of-sandbox write is how persistence is established (an SSH authorized_keys append, a shell profile, a cron entry), not a plausibly-legitimate need.",
    consequence:
      "Had this executed, a file outside the disposable workspace would have been changed, and the change would have outlived the container that made it.",
  },
  "file-write-unresolved-target": {
    label: "Write to a destination the text cannot settle",
    severity: "review",
    glyph: "●",
    summary:
      "This command writes to a target built from an expansion the platform cannot value — an environment variable, or the output of another command. It may land inside the workspace or outside it; the command text does not say. The platform does not guess in either direction, so it asks someone who can answer.",
    consequence:
      "Guessing 'allowed' here would let an unresolvable path become an escape route; guessing 'denied' would block ordinary work such as writing a build log to a directory named by a variable.",
  },
  "step-budget-exceeded": {
    label: "Runaway execution stopped",
    severity: "review",
    glyph: "■",
    summary:
      "This Run issued more shell commands than the configured budget allows in a single task. The guard fires regardless of intent — it catches loops and runaway automation just as readily as an attack that tries to hide in volume. Under the default configuration the Run is held, not killed: a runaway loop is more often a compounding mistake than an attack, so a human may approve ONE continuation with a raised ceiling.",
    consequence:
      "Left unchecked, the Agent could keep issuing commands indefinitely, consuming resources or compounding an early mistake. The platform stops the Run either way — the question is only whether a human gets the chance to say the loop was legitimate before it is permanently cut off.",
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

/**
 * What this deployment actually does with a denial of `rule`, in one clause.
 *
 * Derived from the served configuration rather than written into the rule copy,
 * so a deployment running in monitor mode, or one that has narrowed
 * POLICY_REVIEW_RULES, is described accurately instead of aspirationally.
 */
export function describeDisposition(rule: string, mode: PolicyMode | null): string {
  if (!mode) return "The configured enforcement mode for this rule is not known.";
  if (mode.enforcement === "monitor") {
    return "This deployment is in monitor mode: the decision was recorded as evidence and the command was NOT stopped.";
  }
  return mode.reviewRules.includes(rule)
    ? "In this deployment the Run is held for a named human to approve or deny."
    : "In this deployment the Run is blocked outright, with no review path.";
}
