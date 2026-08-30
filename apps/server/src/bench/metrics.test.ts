import { describe, expect, it } from "vitest";
import {
  coefficientOfVariation,
  resourceDelta,
  stability,
  timeSweep,
  wilson,
  zeroFailureUpperBound,
} from "./metrics.js";

/**
 * These tests assert structure and arithmetic, never wall-clock magnitudes.
 *
 * A test that asserts "p95 is under N microseconds" measures the CI runner, not
 * the code, and the stability data is explicit that p95 moves 2-3x between runs
 * on one machine. So timing here is checked for internal consistency (ordering,
 * counts, derived values) and the statistics are pinned against closed-form
 * values that cannot drift with hardware.
 */

describe("timeSweep", () => {
  it("collects exactly the requested number of samples", () => {
    const result = timeSweep(() => {}, { warmupRounds: 5, rounds: 50 });
    expect(result.n).toBe(50);
  });

  it("runs warmup before measuring, and warmup is not sampled", () => {
    let calls = 0;
    const result = timeSweep(() => { calls += 1; }, { warmupRounds: 200, rounds: 30 });
    // Every call is accounted for: warmup rounds plus measured rounds.
    expect(calls).toBe(230);
    // But only the measured ones became samples.
    expect(result.n).toBe(30);
  });

  it("divides batched samples back out to per-call cost", () => {
    let calls = 0;
    const result = timeSweep(() => { calls += 1; }, {
      warmupRounds: 0,
      rounds: 10,
      batchSize: 20,
    });
    expect(calls).toBe(200);
    // n counts batches, not calls — the distribution has 10 points, each the
    // mean of 20 calls.
    expect(result.n).toBe(10);
  });

  it("keeps percentiles ordered", () => {
    const result = timeSweep(() => { Math.sqrt(Math.random()); }, {
      warmupRounds: 10,
      rounds: 200,
    });
    expect(result.p50).toBeLessThanOrEqual(result.p95);
    expect(result.p95).toBeLessThanOrEqual(result.p99);
    expect(result.p99).toBeLessThanOrEqual(result.max);
  });

  it("derives throughput from the mean", () => {
    const result = timeSweep(() => { Math.sqrt(2); }, { warmupRounds: 10, rounds: 100 });
    expect(result.throughputPerSec * result.mean).toBeCloseTo(1_000_000, 3);
  });

  it("survives a zero-round sweep without dividing by zero", () => {
    const result = timeSweep(() => {}, { warmupRounds: 0, rounds: 0 });
    expect(result.n).toBe(0);
    expect(result.throughputPerSec).toBe(0);
    expect(Number.isNaN(result.mean)).toBe(false);
  });
});

describe("stability", () => {
  it("runs the sweep the requested number of times", () => {
    const result = stability(() => {}, { runs: 3, warmupRounds: 2, rounds: 20 });
    expect(result.runs).toHaveLength(3);
    expect(result.runs.every((run) => run.n === 20)).toBe(true);
  });

  it("reports a finite, non-negative CV for every metric", () => {
    const result = stability(() => { Math.sqrt(3); }, { runs: 3, warmupRounds: 2, rounds: 20 });
    for (const [metric, value] of Object.entries(result.cv)) {
      expect(Number.isFinite(value), metric).toBe(true);
      expect(value, metric).toBeGreaterThanOrEqual(0);
    }
  });
});

describe("coefficientOfVariation", () => {
  it("is zero for identical values", () => {
    expect(coefficientOfVariation([10, 10, 10, 10])).toBe(0);
  });

  it("matches the closed-form value", () => {
    // mean 3, sample sd sqrt(2.5) = 1.5811..., cv = 0.52705...
    expect(coefficientOfVariation([1, 2, 3, 4, 5])).toBeCloseTo(0.52705, 5);
  });

  it("is defined for degenerate inputs", () => {
    expect(coefficientOfVariation([])).toBe(0);
    expect(coefficientOfVariation([7])).toBe(0);
    expect(coefficientOfVariation([0, 0])).toBe(0);
  });
});

describe("resourceDelta", () => {
  it("invokes the workload exactly once and times it", () => {
    let calls = 0;
    const delta = resourceDelta(() => {
      calls += 1;
      let sink = 0;
      for (let index = 0; index < 200_000; index += 1) sink += index;
      return sink;
    });
    expect(calls).toBe(1);
    expect(delta.wallMicroseconds).toBeGreaterThan(0);
    expect(delta.cpuUserMicroseconds).toBeGreaterThanOrEqual(0);
    expect(delta.cpuSystemMicroseconds).toBeGreaterThanOrEqual(0);
    // RSS can legitimately go negative if a collection lands mid-window, so the
    // only safe assertion is that it is a number.
    expect(Number.isFinite(delta.rssBytes)).toBe(true);
  });
});

describe("wilson", () => {
  it("matches the textbook interval for 50/100", () => {
    // The standard worked example: Wilson 95% for 0.5 at n=100 is (0.4038, 0.5962).
    const interval = wilson(50, 100);
    expect(interval.point).toBe(0.5);
    expect(interval.low).toBeCloseTo(0.40383, 4);
    expect(interval.high).toBeCloseTo(0.59617, 4);
  });

  it("stays inside [0, 1] at the zero boundary", () => {
    const interval = wilson(0, 69);
    expect(interval.point).toBe(0);
    expect(interval.low).toBeGreaterThanOrEqual(0);
    // Two-sided Wilson upper bound at 0/69.
    expect(interval.high).toBeCloseTo(0.05274, 4);
  });

  it("gives a usable interval at the measured 1/69 escape rate", () => {
    // The normal approximation degenerates here; Wilson does not.
    const interval = wilson(1, 69);
    expect(interval.point).toBeCloseTo(0.014493, 5);
    expect(interval.low).toBeCloseTo(0.002562, 5);
    expect(interval.high).toBeCloseTo(0.077634, 5);
  });

  it("returns a non-informative interval for zero trials rather than NaN", () => {
    expect(wilson(0, 0)).toEqual({ point: 0, low: 0, high: 1 });
  });
});

describe("zeroFailureUpperBound", () => {
  it("bounds the true rate after zero failures in 69 trials", () => {
    // Exact one-sided 95% Clopper-Pearson: 1 - 0.05^(1/69) = 4.2487%.
    expect(zeroFailureUpperBound(69)).toBeCloseTo(0.042487, 6);
  });

  it("tightens as the trial count grows", () => {
    // 1 - 0.05^(1/300) = 0.9936%.
    expect(zeroFailureUpperBound(300)).toBeCloseTo(0.009936, 6);
    expect(zeroFailureUpperBound(300)).toBeLessThan(zeroFailureUpperBound(69));
  });

  it("is conservative: wider than Wilson once sidedness is matched", () => {
    // The comparison has to be like-for-like. Against Wilson's TWO-sided upper
    // bound this helper looks tighter (4.2487% vs 5.2739%), but that is an
    // artefact of comparing a one-sided bound to a two-sided one. Match the
    // sidedness and the relationship inverts: Wilson one-sided (z = 1.645) gives
    // 3.7738% where the exact bound gives 4.2487%.
    //
    // Being wider is the reason to use it, not a defect. Clopper-Pearson is
    // exact and known to be conservative, so a zero-failure security claim built
    // on it errs toward overstating the residual risk. A bound that could be
    // accused of understating risk is worthless in a security writeup.
    expect(wilson(0, 69, 1.645).high).toBeCloseTo(0.037738, 6);
    expect(zeroFailureUpperBound(69)).toBeGreaterThan(wilson(0, 69, 1.645).high);
  });

  it("stays conservative at every trial count the corpus actually reports", () => {
    // 33 secret-extraction attempts, 69 attacks, and a hypothetical grown corpus.
    for (const trials of [33, 69, 300]) {
      expect(zeroFailureUpperBound(trials), String(trials)).toBeGreaterThan(
        wilson(0, trials, 1.645).high,
      );
    }
  });

  it("agrees with the rule of three to within a few percent", () => {
    const exact = zeroFailureUpperBound(69);
    const ruleOfThree = 3 / 69;
    expect(Math.abs(ruleOfThree - exact) / exact).toBeLessThan(0.05);
  });

  it("claims nothing from zero trials", () => {
    expect(zeroFailureUpperBound(0)).toBe(1);
  });
});
