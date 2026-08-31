import { describe, expect, it } from "vitest";
import { codexConfigToml, loadConfig } from "./config.js";
import {
  guardedEvaluate,
  policyContextFrom,
  REVIEWABLE_RULES,
} from "./command-policy.js";

const base = { NODE_ENV: "test", ARK_API_KEY: "k", ARK_MODEL: "ep-test" } as const;

/**
 * @covers TM-AGENT-005
 * The "secret rules are never reviewable" claim is a code-level invariant, not a
 * documentation promise: config that would make a secret rule human-approvable
 * is rejected at startup.
 */
describe("POLICY_REVIEW_RULES invariant", () => {
  it("rejects secret-access rules at startup", () => {
    expect(() =>
      loadConfig({ ...base, POLICY_REVIEW_RULES: "secret-exfiltration,protected-secret-access" }),
    ).toThrow(/never be human-approved|reviewable rules/i);
  });

  it("rejects any rule outside the reviewable set (fails closed)", () => {
    expect(() => loadConfig({ ...base, POLICY_REVIEW_RULES: "made-up-rule" })).toThrow();
  });

  it("accepts the default reviewable egress rule", () => {
    const config = loadConfig({ ...base, POLICY_REVIEW_RULES: "network-egress-denied" });
    expect(config.policyReviewRules).toEqual(["network-egress-denied"]);
  });

  it("defaults to the rules where a human genuinely adds information", () => {
    // Egress to a plausibly-legitimate host, and a write whose destination the
    // text cannot settle. Both are cases where the operator knows something the
    // engine does not. Secret access and demonstrated sandbox escapes are
    // absent and cannot be added — parseReviewRules rejects them.
    expect(loadConfig(base).policyReviewRules).toEqual([
      "network-egress-denied",
      "network-egress-denied-implicit",
      "file-write-unresolved-target",
    ]);
  });
});

describe("credential configuration", () => {
  it("refuses to start when the retired APP_AUTH_TOKEN is still set", () => {
    expect(() => loadConfig({ ...base, APP_AUTH_TOKEN: "a-strong-legacy-token" })).toThrow(
      /APP_PRINCIPALS/,
    );
  });

  it("requires at least one principal on a non-loopback production server", () => {
    expect(() => loadConfig({ ...base, NODE_ENV: "production", HOST: "0.0.0.0" })).toThrow(
      /APP_PRINCIPALS/,
    );
  });

  it("requires production tokens of at least 24 characters", () => {
    expect(() =>
      loadConfig({
        ...base,
        NODE_ENV: "production",
        HOST: "0.0.0.0",
        APP_PRINCIPALS: "alice:tok_short",
      }),
    ).toThrow(/at least 24/);
  });

  it("allows a loopback development server with no principals", () => {
    expect(loadConfig(base).principals.size).toBe(0);
  });

  it("resolves a configured token through the parsed config", () => {
    const config = loadConfig({ ...base, APP_PRINCIPALS: "alice:tok_alice_0123456789abcdef" });
    expect(config.principals.resolve("tok_alice_0123456789abcdef")).toEqual({ id: "alice" });
  });
});

// @covers TM-AGENT-002
describe("Codex shell credential isolation", () => {
  it("keeps the Ark key available to Codex but excludes it from shell commands", () => {
    const toml = codexConfigToml(loadConfig(base));
    expect(toml).toContain('env_key = "ARK_API_KEY"');
    expect(toml).toContain("[shell_environment_policy]");
    expect(toml).toContain("ignore_default_excludes = false");
    // `exclude` is the documented key; a `filters` sub-table does not exist and
    // would leave the explicit rule inert.
    expect(toml).toContain('exclude = ["ARK_API_KEY"]');
    expect(toml).not.toContain("[shell_environment_policy.filters]");
  });
});

/**
 * @covers TM-AGENT-005
 * The three safety invariants, asserted INDEPENDENTLY.
 *
 * Ported from the finding in PR #3's review rather than from PR #3's code. Its
 * harness checked the same three invariants in one function that returned early
 * on the first failure, and compared the reviewable set against a joined string
 * literal. When 06bd51a legitimately added `network-egress-denied-implicit`,
 * the literal stopped matching, invariant 1 failed for every case, and the
 * early return meant invariants 2 and 3 — config rejects a secret rule, and
 * evaluation fails CLOSED — silently stopped executing. A real security fix
 * disabled the fail-closed test, with no conflict and nothing to announce it.
 *
 * Two properties follow from that, and both are structural rather than
 * incidental: each invariant gets its own `it` block, so one failing cannot
 * prevent another from running; and membership is asserted by set semantics
 * rather than by a serialized literal, so growing the reviewable set for a good
 * reason does not look identical to breaking it.
 */
describe("safety invariants hold independently of one another", () => {
  it("keeps every rule that must never be human-approved out of the set", () => {
    for (const rule of [
      "secret-exfiltration",
      "protected-secret-access",
      "file-write-outside-workspace",
      "policy-error",
    ]) {
      expect(REVIEWABLE_RULES, rule).not.toContain(rule);
    }
  });

  it("keeps the rules that must stay reviewable in the set", () => {
    for (const rule of ["network-egress-denied", "network-egress-denied-implicit"]) {
      expect(REVIEWABLE_RULES, rule).toContain(rule);
    }
  });

  it("rejects a configuration naming a rule outside that set", () => {
    // Asserted here as well as above, so this invariant survives a failure of
    // either membership check rather than sharing their fate.
    expect(() =>
      loadConfig({ ...base, POLICY_REVIEW_RULES: "network-egress-denied,protected-secret-access" }),
    ).toThrow();
  });

  it("denies rather than allows when evaluation throws", () => {
    const violation = guardedEvaluate(
      { agentId: "invariant", threadId: null },
      "npm install",
      policyContextFrom("https://ark.cn-beijing.volces.com/api/v3"),
      () => {
        throw new Error("boom");
      },
    );
    expect(violation?.rule).toBe("policy-error");
  });
});
