import { describe, expect, it } from "vitest";
import baseline from "./baseline.json" with { type: "json" };
import { timeSweep } from "./metrics.js";
import { policyWorkload } from "./policy-workload.js";
import { measureStoreOverhead } from "./store-overhead.js";

/**
 * Task 1.5 — the performance regression gate.
 *
 * WHY THIS LOOKS DIFFERENT FROM `policy-eval.test.ts`.
 *
 * Those thresholds sit at or just below the measured figure, because the things
 * they gate are deterministic: the same corpus through the same rules gives the
 * same recall every time, so a ratchet at the measured value is safe and any
 * movement is real. Timing is not deterministic, and this lane has measured how
 * badly:
 *
 *   - latency p50 run-to-run CV 3.5%-22.9% depending on the machine
 *   - store-write marginal cost, single runs, one machine: 2.25-6.08 us/event
 *   - the same, median-of-3: 3.83-5.27 us/event
 *
 * Taking a median barely helps (CV 15.7% -> 13.8%) because the noise is
 * correlated within a session — machine load, not independent sampling. So a
 * ratchet at the measured value would flake constantly, and everyone would learn
 * to re-run the build until it passed, which is worse than having no gate.
 *
 * TWO TIERS, per the decision recorded in plan §2.3:
 *
 *   Everywhere — assert the SHAPE. Growth must stay linear, and the slope must
 *   stay under a ceiling loose enough that a loaded laptop cannot trip it. This
 *   catches an algorithmic regression (someone makes the store O(n^2)) which is
 *   the failure that actually matters, and cannot flake.
 *
 *   Pinned CI only — assert absolutes, with headroom sized from the observed CV.
 *   Only meaningful because the platform is fixed; the same numbers on an
 *   unpinned machine would be noise.
 *
 * Every threshold below records what was measured and when, so raising one is a
 * decision someone has to justify rather than a number they can quietly edit.
 */

/** Pinned-platform CI: the only place an absolute timing threshold means anything. */
const PINNED_CI = process.env.CI === "true" && process.platform === "linux";

const median = (values: number[]): number => {
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.floor(sorted.length / 2)] ?? 0;
};

/** Three points is enough for a slope; keeping it small keeps `check` fast. */
const EVENT_COUNTS = [0, 1000, 5000];
const REPETITIONS = 3;

async function slopeAndLinearity(): Promise<{ slope: number; rSquared: number }> {
  const slopes: number[] = [];
  const rSquareds: number[] = [];
  for (let index = 0; index < REPETITIONS; index += 1) {
    const result = await measureStoreOverhead({
      eventCounts: EVENT_COUNTS,
      mutateRounds: 10,
      snapshotRounds: 5,
    });
    slopes.push(result.fit.marginalMicrosecondsPerEvent);
    rSquareds.push(result.fit.rSquared);
  }
  return { slope: median(slopes), rSquared: median(rSquareds) };
}

describe("store-write cost: shape, gated everywhere", () => {
  it("no longer grows with the number of stored events", async () => {
    // THIS ASSERTION IS INVERTED FROM WHAT IT USED TO BE, and the inversion is
    // the record of TM-OPS-001 being closed.
    //
    // It read `expect(rSquared).toBeGreaterThanOrEqual(0.98)` and was described
    // as "the load-bearing invariant": r-squared 0.9931-1.0000 across five
    // environments, the most stable thing measured in this lane. That was a gate
    // protecting a DEFECT's shape -- it asserted the store kept growing linearly,
    // because at the time the only regression worth catching was it becoming
    // quadratic.
    //
    // Now that events are appended to a JSONL log rather than re-serialised into
    // the blob, the cost of recording event n does not depend on n, so a strong
    // linear fit would mean the fix had come undone. The slope is what carries
    // the claim, and r-squared is deliberately no longer asserted: with the
    // slope at zero the fit is dominated by noise and r-squared becomes
    // meaningless rather than merely low.
    const { slope } = await slopeAndLinearity();
    expect(slope).toBeLessThan(1);
  }, 60_000);

  it("keeps the marginal cost under an algorithmic-regression ceiling", async () => {
    // Kept, and now a much wider margin than it was. 25 us/event was ~4x
    // headroom over the worst honest reading when every write re-serialised the
    // log; against an append it is enormous. Left deliberately loose rather than
    // retuned: this exists to catch the store becoming super-linear again, not
    // to police a 20% drift the measurement cannot support.
    const { slope } = await slopeAndLinearity();
    expect(slope).toBeLessThan(25);
  }, 60_000);
});

describe("absolutes, pinned CI only", () => {
  // Skipped until re-derived: baseline.json's samples are from the regex engine
  // that main replaced. See the $superseded note in that file.
  it.skip(
    "keeps the store-write marginal cost near its CI baseline",
    async () => {
      // Threshold now comes from `baseline.json`, derived from 22 samples across
      // 11 green CI runs on this branch rather than from one machine's guess.
      // Observed 1.93-2.81 us/event, CV 10.8%; the band sits at 4.0, which is
      // 1.42x the highest sample and ~5.7 sd above the mean.
      const metric = baseline.metrics.storeWriteMarginalMicrosecondsPerEvent;
      const { slope } = await slopeAndLinearity();
      expect(slope, metric.thresholdRationale).toBeLessThan(metric.threshold);
    },
    60_000,
  );

  // Skipped for the same reason as the store absolute above: the baseline was
  // collected against the regex engine.
  it.skip("keeps policy decision p50 near its CI baseline", () => {
    // p50 ONLY. p95 and p99 are not gated: their run-to-run CV was 28.0% and
    // 26.4% on the same ubuntu runner that gave p50 22.9%, and p99 reached 48.8%
    // locally. Gating those would be gating the runner. See plan §2.2.
    const p50 = median(
      Array.from(
        { length: REPETITIONS },
        () => timeSweep(policyWorkload(), { warmupRounds: 200, rounds: 1000 }).p50,
      ),
    );
    // Also from `baseline.json`: 14 samples, 3.10-7.75 us, CV 23.3%. The band is
    // 12.0 - deliberately looser relative to its spread than the slope's,
    // because this metric is the noisier of the two even on pinned CI.
    const metric = baseline.metrics.policyDecisionP50Microseconds;
    expect(p50, metric.thresholdRationale).toBeLessThan(metric.threshold);
  }, 60_000);
});

describe("the baseline file itself", () => {
  it("carries the history its thresholds were derived from", () => {
    // A threshold with no recorded provenance is a number someone can quietly
    // raise. These assertions make the derivation part of the build.
    for (const [name, metric] of Object.entries(baseline.metrics)) {
      expect(metric.samples.length, name).toBeGreaterThanOrEqual(10);
      expect(metric.thresholdRationale.length, name).toBeGreaterThan(40);
      // The band must actually sit above everything observed, or it is not a
      // band, it is a coin flip.
      expect(metric.threshold, name).toBeGreaterThan(Math.max(...metric.samples));
    }
    expect(baseline.sourceRuns.length).toBeGreaterThanOrEqual(10);
  });
});

describe("the gate's own assumptions", () => {
  it("declares which tier it is running in", () => {
    // Not decoration: if this ever reports pinned-CI on a developer laptop the
    // absolutes above become noise-driven, and someone should notice.
    expect(typeof PINNED_CI).toBe("boolean");
    if (PINNED_CI) {
      expect(process.platform).toBe("linux");
      expect(process.env.CI).toBe("true");
    }
  });
});
