/**
 * Middleware profiles — provider-agnostic.
 *
 * Each profile models ONE middleware layer exactly as the platform wires it,
 * plus a `none` profile for the no-middleware baseline and an `all` profile
 * for the whole-stack regression pass. The point of the suite is to compare
 * the layers: an attack that one layer blocks may be invisible to another,
 * and the "as a whole" run shows whether the stack closes the gaps.
 *
 * The layers under test (all server-side, none user-tunable):
 *   1. command-policy — evaluateCommand/guardedEvaluate/scanCommands
 *   2. redaction     — redactCommand (evidence sanitisation)
 *   3. budget        — step budget, always enforced (POLICY_MAX_COMMANDS)
 *   4. approval      — reviewable egress holds; secret rules never reviewable
 *   5. monitor       — POLICY_ENFORCEMENT=monitor shadow mode
 *   6. config        — REVIEWABLE_RULES invariant, fail-closed evaluation
 *
 * This library NEVER imports the platform. The middleware surface under test
 * is injected as `EvaluationDeps` by the host — the server app (for /api/pentest)
 * or the CLI wiring (tests/lib/wiring.ts) — so the same library runs anywhere
 * against whatever implementation it is handed.
 */

import type { TestCase } from "./types.js";

export type Decision = "allow" | "deny" | "n/a";

/** Structural shapes of the middleware surface (duck-typed, no server import). */
export interface PolicyContextLike {
  allowedHosts: string[];
  secretValues?: string[];
}

export interface PolicyViolationLike {
  rule: string;
  detail: string;
  hosts?: string[];
}

export interface DetectedViolationLike extends PolicyViolationLike {
  command: string;
}

/**
 * The middleware functions the profiles exercise. Injected by the host so the
 * library stays external and tests whatever implementation it is handed.
 */
export interface EvaluationDeps {
  evaluateCommand: (
    command: string,
    context: PolicyContextLike,
  ) => PolicyViolationLike | null;
  guardedEvaluate: (
    command: string,
    context: PolicyContextLike,
    evaluate?: (
      command: string,
      context: PolicyContextLike,
    ) => PolicyViolationLike | null,
  ) => PolicyViolationLike | null;
  redactCommand: (command: string, secretValues?: readonly string[]) => string;
  scanCommands: (
    commands: readonly string[],
    startIndex: number,
    context: PolicyContextLike,
  ) => DetectedViolationLike[];
  isReviewableRule: (rule: string) => boolean;
  policyContextFrom: (
    arkBaseUrl: string,
    extraHosts?: readonly string[],
    secretValues?: readonly string[],
  ) => PolicyContextLike;
  /** Config loader; the config profile asserts it REJECTS unsafe review rules. */
  loadConfig: (environment?: Record<string, string | undefined>) => unknown;
  REVIEWABLE_RULES: readonly string[];
}

export interface ProfileOutcome {
  decision: Decision;
  rule: string | null;
  detail: string | null;
  /** Approval layer: is this denial human-reviewable? */
  reviewable: boolean | null;
  /** Redaction layer: did a protected secret survive? */
  leak: boolean | null;
  /** Budget layer: did this run trip the step budget? */
  terminated: boolean | null;
  /** Redaction layer: the sanitised command. */
  redactedCommand: string | null;
  /**
   * Detection, independent of enforcement. Set by the monitor profile: it can
   * detect a violation (true) while deliberately NOT blocking it (decision
   * stays "allow"). Other profiles fall back to `decision === "deny"`.
   */
  detected: boolean | null;
  note?: string | undefined;
}

export interface EvalEnv {
  policyContext: PolicyContextLike;
  /** Fixture credential values the redaction layer must mask. */
  secretValues: string[];
  /** POLICY_MAX_COMMANDS semantics. */
  maxCommands: number;
  /** POLICY_ENFORCEMENT semantics. */
  enforcement: "enforce" | "monitor";
}

export interface MiddlewareProfile {
  id: string;
  name: string;
  describe: string;
  evaluate(case_: TestCase, env: EvalEnv): ProfileOutcome;
}

/** Default evaluation environment, built from the injected middleware. */
export function defaultEnv(deps: EvaluationDeps): EvalEnv {
  return {
    // Same default context the platform uses for the Ark host.
    policyContext: deps.policyContextFrom("https://ark.cn-beijing.volces.com/api/v3"),
    secretValues: [
      "sk-live-test-0123456789abcdef0123456789", // 40 chars, letters+digits
      "postgres://deployer:hunter2secret@db.internal:5432/app", // URL credential
    ],
    maxCommands: 50,
    enforcement: "enforce",
  };
}

/** Wrap a command in the exact form Codex reports it. */
export function wrapped(command: string): string {
  return `/bin/bash -lc ${JSON.stringify(command)}`;
}

function finalCommand(case_: TestCase): string {
  return case_.wrapped === true ? wrapped(case_.command) : case_.command;
}

const ALLOW_OUTCOME = {
  decision: "allow" as Decision,
  rule: null,
  detail: null,
  reviewable: null,
  leak: null,
  terminated: null,
  redactedCommand: null,
  detected: null,
};

/**
 * Build the full profile set (in a fixed order) from the injected middleware.
 * Order: none, command-policy, redaction, budget, approval, monitor, config, all.
 */
export function createProfiles(deps: EvaluationDeps): readonly MiddlewareProfile[] {
  /** 1. No middleware: the baseline. Everything is allowed. */
  const NONE_PROFILE: MiddlewareProfile = {
    id: "none",
    name: "No middleware (baseline)",
    describe: "The starter-kit runtime with no governance layer; every command proceeds.",
    evaluate: () => ({ ...ALLOW_OUTCOME }),
  };

  /** 2. Command policy engine. */
  const COMMAND_POLICY_PROFILE: MiddlewareProfile = {
    id: "command-policy",
    name: "Command policy",
    describe: "evaluateCommand + guardedEvaluate (fail-closed) on the command text.",
    evaluate: (case_, env) => {
      const violation = deps.guardedEvaluate(finalCommand(case_), env.policyContext);
      if (!violation) return { ...ALLOW_OUTCOME };
      return {
        decision: "deny",
        rule: violation.rule,
        detail: violation.detail,
        reviewable: deps.isReviewableRule(violation.rule),
        leak: null,
        terminated: null,
        redactedCommand: null,
        detected: true,
      };
    },
  };

  /** 3. Evidence redaction. A leak is a secret value surviving into the output. */
  const UNREDACTED_URL_CREDENTIALS = /:\/\/[^\s:/@"']+:[^\s@"']+@/;
  const HIGH_ENTROPY_REMAINING = /\b(?=[A-Za-z0-9_+/=-]{28,})(?=[^\s]*[A-Za-z])(?=[^\s]*\d)[A-Za-z0-9_+/=-]{28,}\b/;

  const REDACTION_PROFILE: MiddlewareProfile = {
    id: "redaction",
    name: "Evidence redaction",
    describe: "redactCommand masks URL credentials, high-entropy tokens and known secret values.",
    evaluate: (case_, env) => {
      const redacted = deps.redactCommand(finalCommand(case_), env.secretValues);
      const leaks: string[] = [];
      for (const secret of env.secretValues) {
        // Only values substantial enough to be credentials are masked upstream.
        if (secret.length >= 8 && redacted.includes(secret)) leaks.push("known-secret");
      }
      if (UNREDACTED_URL_CREDENTIALS.test(redacted)) leaks.push("url-credentials");
      if (HIGH_ENTROPY_REMAINING.test(redacted)) leaks.push("high-entropy-token");
      const leak = leaks.length > 0;
      return {
        decision: "n/a",
        rule: null,
        detail: leak ? "redaction left: " + [...new Set(leaks)].join(", ") : null,
        reviewable: null,
        leak,
        terminated: null,
        redactedCommand: redacted,
        detected: null,
        note: leak ? undefined : "no protected material survived redaction",
      };
    },
  };

  /**
   * 4. Step budget. Models the runner's invariant faithfully:
   * `parsed.commands.length > policyMaxCommands` terminates the run, and the
   * budget is enforced REGARDLESS of monitor mode. A single-command case can
   * never trip it, which is exactly the property the suite asserts: budget is
   * a runaway control, not a classifier.
   */
  const BUDGET_PROFILE: MiddlewareProfile = {
    id: "budget",
    name: "Step budget",
    describe: "Platform-enforced command-count limit; always on, independent of POLICY_ENFORCEMENT.",
    evaluate: (case_, env) => {
      // One case == one run with a single command in it.
      const count = 1;
      const terminated = count > env.maxCommands;
      return {
        decision: "allow",
        rule: null,
        detail: terminated ? "step budget exceeded" : null,
        reviewable: null,
        leak: null,
        terminated,
        redactedCommand: null,
        detected: null,
        note: "budget is a counter, not a classifier; behavioral tests drive the real CodexRunner",
      };
    },
  };

  /** 5. Human approval: which denials are held vs hard-blocked. */
  const APPROVAL_PROFILE: MiddlewareProfile = {
    id: "approval",
    name: "Human approval",
    describe: "Reviewable egress denials hold for a named human; secret rules are never reviewable.",
    evaluate: (case_, env) => {
      const violation = deps.guardedEvaluate(finalCommand(case_), env.policyContext);
      if (!violation) return { ...ALLOW_OUTCOME };
      return {
        decision: "deny",
        rule: violation.rule,
        detail: violation.detail,
        reviewable: deps.isReviewableRule(violation.rule),
        leak: null,
        terminated: null,
        redactedCommand: null,
        detected: true,
      };
    },
  };

  /**
   * 6. Monitor mode: visibility only. The policy runs in shadow mode — a
   * violation is DETECTED (and would be recorded) but the run is NOT blocked,
   * so the decision stays "allow". The suite therefore scores monitor on
   * detection coverage, never on a block rate.
   */
  const MONITOR_PROFILE: MiddlewareProfile = {
    id: "monitor",
    name: "Monitor mode",
    describe: "POLICY_ENFORCEMENT=monitor detects and records violations without terminating the run (shadow mode).",
    evaluate: (case_, env) => {
      const violation = deps.guardedEvaluate(finalCommand(case_), env.policyContext);
      if (!violation) {
        return { ...ALLOW_OUTCOME, detected: false };
      }
      return {
        decision: "allow",
        rule: violation.rule,
        detail: violation.detail + " (observed, run continues in monitor mode)",
        reviewable: null,
        leak: null,
        terminated: false,
        redactedCommand: null,
        detected: true,
      };
    },
  };

  /**
   * 7. Config invariants: reviewable-rule set, config rejection, fail-closed.
   *
   * Every invariant runs unconditionally — a change in the reviewable set is
   * reported loudly (no exact-list dependency that silently skips the checks
   * below it), and the config-rejection and fail-closed invariants are always
   * exercised so a regression cannot hide behind an early return.
   */
  const CONFIG_PROFILE: MiddlewareProfile = {
    id: "config",
    name: "Config invariants",
    describe: "reviewable rules sane; POLICY_REVIEW_RULES rejects non-reviewable rules; guardedEvaluate fails closed.",
    evaluate: (case_, env) => {
      const problems: string[] = [];
      const outcome: ProfileOutcome = {
        decision: "n/a",
        rule: null,
        detail: null,
        reviewable: null,
        leak: null,
        terminated: null,
        redactedCommand: null,
        detected: null,
      };
      // Invariant 1: the required reviewable rule must stay reviewable, and
      // rules that must NEVER be human-approved must not appear in the set.
      // Unknown extra rules are flagged loudly rather than matched against an
      // exact serialized list, so a reviewable-set expansion is surfaced.
      const requiredReviewable = "network-egress-denied";
      const neverReviewable = [
        "secret-exfiltration",
        "protected-secret-access",
        "policy-error",
        "encoded-exfiltration",
      ];
      if (!deps.REVIEWABLE_RULES.includes(requiredReviewable)) {
        problems.push("required reviewable rule missing: " + requiredReviewable);
      }
      for (const rule of neverReviewable) {
        if (deps.REVIEWABLE_RULES.includes(rule)) {
          problems.push("forbidden rule is reviewable: " + rule);
        }
      }
      for (const rule of deps.REVIEWABLE_RULES) {
        if (rule !== requiredReviewable && !neverReviewable.includes(rule)) {
          problems.push("unexpected reviewable rule: " + rule);
        }
      }
      // Invariant 2: a config naming a secret rule must be rejected loudly.
      try {
        deps.loadConfig({
          NODE_ENV: "test",
          ARK_API_KEY: "k",
          ARK_MODEL: "ep-test",
          POLICY_REVIEW_RULES: "network-egress-denied,protected-secret-access",
        });
        problems.push("loadConfig accepted a secret-access review rule");
      } catch {
        /* expected: rejected */
      }
      // Invariant 3: guardedEvaluate fails closed on a throwing evaluator.
      const failClosed = deps.guardedEvaluate(finalCommand(case_), env.policyContext, () => {
        throw new Error("boom");
      });
      if (!failClosed || failClosed.rule !== "policy-error") {
        problems.push("fail-closed did not deny");
      }
      outcome.detail = problems.length > 0 ? problems.join("; ") : null;
      outcome.note =
        problems.length === 0
          ? "reviewable set sane, forbidden config rejected, evaluation fails closed"
          : undefined;
      return outcome;
    },
  };

  /** Whole stack: policy -> approval classification -> redaction -> budget. */
  const ALL_PROFILE: MiddlewareProfile = {
    id: "all",
    name: "Whole stack (regression)",
    describe: "command policy, fail-closed, approval classification, redaction and budget chained as the platform wires them.",
    evaluate: (case_, env) => {
      const violation = deps.guardedEvaluate(finalCommand(case_), env.policyContext);
      if (!violation) return { ...ALLOW_OUTCOME };
      const redacted = deps.redactCommand(finalCommand(case_), env.secretValues);
      const leak = env.secretValues.some(
        (secret) => secret.length >= 8 && redacted.includes(secret),
      );
      return {
        decision: "deny",
        rule: violation.rule,
        detail: violation.detail,
        reviewable: deps.isReviewableRule(violation.rule),
        leak,
        terminated: false,
        redactedCommand: redacted,
        detected: true,
      };
    },
  };

  return [
    NONE_PROFILE,
    COMMAND_POLICY_PROFILE,
    REDACTION_PROFILE,
    BUDGET_PROFILE,
    APPROVAL_PROFILE,
    MONITOR_PROFILE,
    CONFIG_PROFILE,
    ALL_PROFILE,
  ];
}

export function profileById(deps: EvaluationDeps, id: string): MiddlewareProfile {
  const profile = createProfiles(deps).find((p) => p.id === id);
  if (!profile) throw new Error("Unknown middleware profile: " + id);
  return profile;
}
