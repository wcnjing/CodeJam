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
    // 100, not 50. This branch is the first to run the gate on CI hardware -- the
    // workflow did not exist before it -- and the capability engine measures
    // 33 us/command on a 4-cpu GitHub runner against 24 us on a laptop. The 50
    // was calibrated on laptop hardware against the old regex engine and leaves
    // ~1.5x headroom on a metric whose run-to-run CV is over 20%.
    //
    // It first measured 85 us on CI, which is why an earlier version of this
    // comment set 250 and said warmup was not the cause. That was wrong: the
    // warmup was too short for a structural parser, and a laptop was already
    // warm enough to hide it. Sizing the warmup properly took CI from 85 to 33,
    // and 250 was headroom bought against a number that no longer exists.
    //
    // An absolute cannot be a performance gate across unknown hardware -- that
    // is why section 2.3 of the plan keeps absolutes to pinned platforms. This
    // is a smoke check against catastrophic regression, sized against the
    // SLOWEST runner rather than the fastest. Three measurements now exist:
    //
    //   laptop            24 us
    //   ubuntu CI         33 us
    //   windows CI       102 us
    //
    // 100 was sized from ubuntu alone and failed on windows, taking that leg
    // from 12 known failures to 13 -- and the failure COUNT is the only signal
    // that leg carries, so breaking it is worse than a loose threshold. 200 is
    // ~2x the slowest observed.
    expect(result.meanMicroseconds).toBeLessThan(200);
  });

  it("evaluates a corpus large enough to be meaningful", () => {
    expect(POLICY_CORPUS.length).toBeGreaterThanOrEqual(100);
  });

  it("exercises every policy rule at least once", () => {
    // If a rule stops firing across the whole corpus it is dead code or broken.
    expect(Object.keys(result.ruleCounts).sort()).toEqual([
      "file-write-outside-workspace",
      "network-egress-denied",
      "network-egress-denied-implicit",
      "protected-secret-access",
      "secret-exfiltration",
    ]);
  });
});
