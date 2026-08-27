import { describe, expect, it } from "vitest";
import { loadConfig } from "../core/config.js";

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

  it("defaults to egress-only", () => {
    expect(loadConfig(base).policyReviewRules).toEqual(["network-egress-denied"]);
  });
});
