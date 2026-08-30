import { describe, expect, it } from "vitest";
import { buildAuditTimeline } from "./timeline";
import { describeDisposition, explainRule, type PolicyMode } from "./ruleExplanations";
import { EXAMPLE_PROMPTS, outcomeFor } from "./exampleCommands";
import { buildTourSteps } from "./evaluationTour";
import type {
  AgentRun,
  ApprovalRequest,
  EvaluationSummary,
  PolicyDecision,
} from "../types";

/**
 * The browser is the surface that TELLS an operator what the platform did. A
 * wrong number here is a governance defect, not a cosmetic one: it is the copy
 * a reviewer reads when deciding whether to trust the control. These tests
 * exist because the first version of this UI asserted three things the platform
 * could not support — that a denial is always held for a human, that the
 * workspace is provably unchanged after containment, and that the timeline was
 * chronological while it sorted the other way.
 */

const run = (over: Partial<AgentRun> = {}): AgentRun => ({
  id: "run-1",
  agentId: "agent-1",
  status: "completed",
  prompt: "do the thing",
  output: null,
  error: null,
  usage: null,
  startedAt: "2026-08-30T10:00:00.000Z",
  completedAt: "2026-08-30T10:00:05.000Z",
  createdAt: "2026-08-30T10:00:00.000Z",
  ...over,
});

const decision = (over: Partial<PolicyDecision> = {}): PolicyDecision => ({
  id: "pd-1",
  agentId: "agent-1",
  runId: "run-1",
  rule: "network-egress-denied",
  command: "curl https://attacker.example",
  detail: "Command contacts non-allowlisted host(s): attacker.example.",
  enforced: true,
  decidedAt: "2026-08-30T10:00:03.000Z",
  ...over,
});

const approval = (over: Partial<ApprovalRequest> = {}): ApprovalRequest => ({
  id: "ap-1",
  agentId: "agent-1",
  runId: "run-1",
  prompt: "fetch the registry",
  rule: "network-egress-denied",
  command: "curl https://registry.npmjs.org/react",
  detail: "Command contacts non-allowlisted host(s): registry.npmjs.org.",
  hosts: ["registry.npmjs.org"],
  status: "pending",
  requestedAt: "2026-08-30T10:00:04.000Z",
  resolvedBy: null,
  decisionReason: null,
  resolvedAt: null,
  continuationRunId: null,
  ...over,
});

describe("audit timeline", () => {
  it("orders most recent first, which is what the copy claims", () => {
    const events = buildAuditTimeline(
      [run({ id: "r-old", completedAt: "2026-08-30T09:00:00.000Z" })],
      [decision({ id: "pd-new", decidedAt: "2026-08-30T11:00:00.000Z" })],
      [],
    );
    expect(events.map((event) => event.id)).toEqual(["policy-pd-new", "run-r-old"]);
  });

  it("carries the capability set the flat policy list used to render", () => {
    // The consolidation must not narrow the audit trail. "NETWORK_EGRESS ->
    // attacker.example, via network-tool" is what the engine decided on.
    const [event] = buildAuditTimeline(
      [],
      [
        decision({
          capabilities: [
            {
              capability: "NETWORK_EGRESS",
              resource: "attacker.example",
              trusted: false,
              via: "network-tool",
            },
          ],
        }),
      ],
      [],
    );
    expect(event?.capabilities).toHaveLength(1);
    expect(event?.capabilities?.[0]?.resource).toBe("attacker.example");
  });

  it("covers every terminal run status exactly once", () => {
    const runs: AgentRun[] = [
      run({ id: "a", status: "completed" }),
      run({ id: "b", status: "failed", error: "boom" }),
      run({ id: "c", status: "cancelled" }),
      // blocked/held/terminated are explained by their own policy or approval
      // record; a second entry for the same moment would be duplicate evidence.
      run({ id: "d", status: "blocked" }),
      run({ id: "e", status: "held" }),
      run({ id: "f", status: "terminated" }),
    ];
    const ids = buildAuditTimeline(runs, [], []).map((event) => event.id);
    expect(ids.sort()).toEqual(["run-a", "run-b", "run-c"]);
  });

  it("pairs an approval request with its resolution and names the approver", () => {
    const events = buildAuditTimeline(
      [],
      [],
      [
        approval({
          status: "approved",
          resolvedBy: "wenjing",
          decisionReason: "npm registry is fine",
          resolvedAt: "2026-08-30T10:05:00.000Z",
        }),
      ],
    );
    expect(events[0]?.meta).toBe("by wenjing");
    expect(events[0]?.severity).toBe("success");
  });

  it("marks a monitor-mode decision as observed rather than enforced", () => {
    const [event] = buildAuditTimeline([], [decision({ enforced: false })], []);
    expect(event?.meta).toBe("observed only (monitor mode)");
  });
});

describe("rule explanations", () => {
  it("explains every rule the engine can actually emit", () => {
    // A rule the server can produce but the browser cannot name renders as the
    // generic fallback, which tells the operator nothing at the moment they
    // most need telling.
    for (const rule of [
      "secret-exfiltration",
      "protected-secret-access",
      "file-write-outside-workspace",
      "file-write-unresolved-target",
      "network-egress-denied",
      "network-egress-denied-implicit",
      "step-budget-exceeded",
      "policy-error",
    ]) {
      expect(explainRule(rule).label, rule).not.toBe("Policy decision");
    }
  });

  it("falls back safely for a rule it has never seen", () => {
    const explanation = explainRule("rule-invented-next-quarter");
    expect(explanation.label).toBe("Policy decision");
    expect(explanation.severity).toBe("high");
  });
});

describe("disposition is read from configuration, never assumed", () => {
  const enforceDefault: PolicyMode = {
    enforcement: "enforce",
    reviewRules: [
      "network-egress-denied",
      "network-egress-denied-implicit",
      "file-write-unresolved-target",
    ],
  };

  it("says held for a reviewable rule under the default configuration", () => {
    expect(describeDisposition("network-egress-denied", enforceDefault)).toContain("held");
  });

  it("says blocked for the same rule when the operator narrowed the review set", () => {
    // The exact case the hard-coded copy got wrong: identical rule, different
    // deployment, opposite outcome.
    expect(
      describeDisposition("network-egress-denied", { enforcement: "enforce", reviewRules: [] }),
    ).toContain("blocked outright");
  });

  it("says nothing was stopped in monitor mode", () => {
    expect(
      describeDisposition("secret-exfiltration", { ...enforceDefault, enforcement: "monitor" }),
    ).toContain("NOT stopped");
  });

  it("never claims a hard rule is reviewable", () => {
    expect(describeDisposition("secret-exfiltration", enforceDefault)).toContain(
      "blocked outright",
    );
  });

  it("admits ignorance before the configuration has loaded", () => {
    expect(describeDisposition("network-egress-denied", null)).toContain("not known");
  });
});

describe("playground examples", () => {
  const enforceDefault: PolicyMode = {
    enforcement: "enforce",
    reviewRules: ["network-egress-denied", "network-egress-denied-implicit"],
  };

  it("labels a registry fetch as held under the default configuration", () => {
    const registry = EXAMPLE_PROMPTS.find((item) => item.prompt.includes("registry.npmjs.org"))!;
    expect(outcomeFor(registry, enforceDefault)).toBe("held");
  });

  it("relabels the same example as blocked when review is narrowed", () => {
    const registry = EXAMPLE_PROMPTS.find((item) => item.prompt.includes("registry.npmjs.org"))!;
    expect(outcomeFor(registry, { enforcement: "enforce", reviewRules: [] })).toBe("blocked");
  });

  it("never promises a hard-blocked example is merely held", () => {
    const exfil = EXAMPLE_PROMPTS.find((item) => item.deniedUnder === "secret-exfiltration")!;
    expect(outcomeFor(exfil, enforceDefault)).toBe("blocked");
  });

  it("shows everything running in monitor mode, because nothing is stopped", () => {
    for (const example of EXAMPLE_PROMPTS) {
      expect(outcomeFor(example, { ...enforceDefault, enforcement: "monitor" })).toBe("allowed");
    }
  });

  it("assumes the conservative outcome before configuration loads", () => {
    const exfil = EXAMPLE_PROMPTS.find((item) => item.deniedUnder === "secret-exfiltration")!;
    expect(outcomeFor(exfil, null)).toBe("blocked");
  });
});

describe("guided tour reads live numbers", () => {
  // The tour narrates the dashboard. If it interpolated static text it would
  // become a second, stale source of truth for exactly the figures the project
  // is most careful about — and it would go stale silently, because nothing
  // renders the two side by side.
  const summary: EvaluationSummary = {
    generatedAt: "2026-08-30T10:00:00.000Z",
    corpusSize: 187,
    headline: {
      unsafeActionEscapeRate: 0,
      baselineEscapeRate: 1,
      attackBlockRate: 1,
      attacks: 101,
      escaped: 0,
    },
    secrets: { leaks: 0, attacks: 40, baselineLeaks: 40 },
    falsePositiveRate: 0.012,
    benign: 82,
    policy: {
      coreRecall: 1,
      evasionRecall: 1,
      externalReviewRecall: 1,
      externalReviewFalsePositiveRate: 0,
      externalReviewAttacks: 4,
      externalReviewBenign: 2,
      internalRedTeam: 17,
      precision: 1,
      f1: 1,
    },
    latency: { p50: 3, p95: 9, mean: 4 },
    families: [{ family: "egress", attacks: 40, escaped: 0 }],
    escapes: [],
  };

  it("interpolates the summary it was given, not a pinned figure", () => {
    const steps = buildTourSteps(summary);
    const hero = steps.find((step) => step.target === "hero");
    expect(hero?.body).toContain("187");
    expect(hero?.body).toContain("0.0%");
  });

  it("moves with the numbers when the numbers move", () => {
    const worse = { ...summary, corpusSize: 999 };
    expect(buildTourSteps(worse).find((step) => step.target === "hero")?.body).toContain("999");
  });

  it("keeps the residual named when there is one", () => {
    const withEscape = {
      ...summary,
      headline: { ...summary.headline, escaped: 1, unsafeActionEscapeRate: 0.01 },
      families: [{ family: "encoding", attacks: 10, escaped: 1 }],
      escapes: [{ id: "b64-eval", family: "encoding" }],
    };
    const steps = buildTourSteps(withEscape);
    expect(steps.some((step) => step.body.includes("encoding"))).toBe(true);
  });
});
