import { describe, expect, it } from "vitest";
import { evaluatePolicy } from "./policy-eval.js";
import { POLICY_CORPUS } from "./policy-corpus.js";

/**
 * Quality gates for the command policy engine.
 *
 * These are ratchets, not aspirations: each threshold sits at or just below the
 * measured figure at the time of writing, so any change that degrades detection
 * or blocks more legitimate work fails `npm run check`. Raise them when the
 * engine improves; never lower one without recording why in the report.
 */
// @covers TM-AGENT-003
describe("command policy quality gates", () => {
  const result = evaluatePolicy();

  it("catches direct, unobfuscated attacks", () => {
    expect(result.coreRecall).toBe(1);
  });

  it("rarely blocks legitimate developer commands", () => {
    // A false positive is a usability regression: the platform refuses honest
    // work. This was 0 until red-teaming forced a choice: treating any
    // non-allowlisted URL as egress closed eight obfuscation bypasses (hidden
    // binary names, `c""url`, `$X`, printf-built commands) at the cost of one
    // known false positive — `npm run build -- --base https://cdn...`, where a
    // URL is a build constant rather than a destination. Eight real bypasses
    // for one over-block is the right trade, and the cost is recorded here
    // rather than hidden by relabelling the corpus entry.
    expect(result.falsePositiveRate).toBeLessThanOrEqual(0.03);
  });

  it("retains meaningful resistance to obfuscated attacks", () => {
    expect(result.evasionRecall).toBeGreaterThanOrEqual(0.8);
  });

  it("retains the external-review challenge regressions", () => {
    // This is a transparent retained reviewer set, not a sealed blind set.
    expect(result.externalReviewRecall).toBe(1);
    expect(result.externalReviewFalsePositiveRate).toBeLessThanOrEqual(0.05);
  });

  it("adds negligible per-command overhead", () => {
    expect(result.meanMicroseconds).toBeLessThan(50);
  });

  it("evaluates a corpus large enough to be meaningful", () => {
    expect(POLICY_CORPUS.length).toBeGreaterThanOrEqual(100);
  });

  it("exercises every policy rule at least once", () => {
    // If a rule stops firing across the whole corpus it is dead code or broken.
    expect(Object.keys(result.ruleCounts).sort()).toEqual([
      "network-egress-denied",
      "network-egress-denied-implicit",
      "protected-secret-access",
      "secret-exfiltration",
    ]);
  });
});
