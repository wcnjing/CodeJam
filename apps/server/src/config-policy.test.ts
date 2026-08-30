import { describe, expect, it } from "vitest";
import { codexConfigToml, loadConfig } from "./config.js";

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
