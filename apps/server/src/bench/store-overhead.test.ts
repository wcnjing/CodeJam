import { describe, expect, it } from "vitest";
import { DEFAULT_EVENT_COUNTS, linearFit, measureStoreOverhead } from "./store-overhead.js";

/**
 * As with `metrics.test.ts`, nothing here asserts a wall-clock magnitude — that
 * would measure the CI runner rather than the code, and the store-write cost
 * varies ~3x between platforms on its fixed term alone.
 *
 * `linearFit` is pure arithmetic, so it is pinned against closed-form values.
 * The harness itself is checked for structure and cleanup only.
 */

describe("linearFit", () => {
  it("recovers slope and intercept from a perfect line", () => {
    // y = 10 + 10x, in microseconds.
    const fit = linearFit([
      { x: 0, y: 10 },
      { x: 1, y: 20 },
      { x: 2, y: 30 },
    ]);
    expect(fit.marginalMicrosecondsPerEvent).toBeCloseTo(10, 10);
    expect(fit.fixedCostMilliseconds).toBeCloseTo(0.01, 10); // 10 us
    expect(fit.rSquared).toBeCloseTo(1, 10);
  });

  it("matches the closed-form fit on noisy points", () => {
    // (0,0) (1,1) (2,2) (3,5): slope 1.6, intercept -0.4, r-squared 1 - 1.2/14.
    const fit = linearFit([
      { x: 0, y: 0 },
      { x: 1, y: 1 },
      { x: 2, y: 2 },
      { x: 3, y: 5 },
    ]);
    expect(fit.marginalMicrosecondsPerEvent).toBeCloseTo(1.6, 10);
    expect(fit.fixedCostMilliseconds).toBeCloseTo(-0.0004, 10);
    expect(fit.rSquared).toBeCloseTo(0.9142857142857143, 10);
  });

  it("reports a flat series as zero marginal cost", () => {
    const fit = linearFit([
      { x: 0, y: 5 },
      { x: 1, y: 5 },
      { x: 2, y: 5 },
    ]);
    expect(fit.marginalMicrosecondsPerEvent).toBeCloseTo(0, 10);
    expect(fit.rSquared).toBe(1);
  });

  it("returns zeros rather than NaN for degenerate input", () => {
    const zero = { fixedCostMilliseconds: 0, marginalMicrosecondsPerEvent: 0, rSquared: 0 };
    expect(linearFit([])).toEqual(zero);
    expect(linearFit([{ x: 1, y: 1 }])).toEqual(zero);
    // No variance in x: no slope is defined.
    expect(linearFit([{ x: 3, y: 1 }, { x: 3, y: 9 }])).toEqual(zero);
  });
});

describe("measureStoreOverhead", () => {
  it("returns a point per requested event count, with run metadata", async () => {
    const result = await measureStoreOverhead({
      eventCounts: [0, 50],
      mutateRounds: 3,
      snapshotRounds: 3,
    });

    expect(result.points.map((point) => point.preloaded)).toEqual([0, 50]);
    expect(result.platform).toBe(process.platform);
    expect(result.nodeVersion).toBe(process.versions.node);

    for (const point of result.points) {
      expect(point.mutate.n).toBe(3);
      expect(point.snapshot.n).toBe(3);
      // Real work was timed, but how much is the runner's business, not ours.
      expect(point.mutate.p50).toBeGreaterThan(0);
      expect(Number.isFinite(point.snapshot.p50)).toBe(true);
    }

    expect(Number.isFinite(result.fit.marginalMicrosecondsPerEvent)).toBe(true);
    expect(Number.isFinite(result.fit.rSquared)).toBe(true);
  });

  it("measures a spread of counts by default", () => {
    // The curve is the finding; a single point would not show it.
    expect(DEFAULT_EVENT_COUNTS.length).toBeGreaterThanOrEqual(3);
    expect(Math.max(...DEFAULT_EVENT_COUNTS)).toBeGreaterThanOrEqual(1000);
  });
});
