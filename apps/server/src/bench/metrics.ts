/**
 * Shared measurement primitives for the evaluation harnesses.
 *
 * Before this module there were three hand-rolled timers — `measureThroughput()`
 * in `policy-eval.ts` (200 rounds, mean only), `latency()` in
 * `evaluation-summary.ts` (30 rounds) and `policyLatency()` in
 * `security-benchmark-cli.ts` (50 rounds). They disagreed by construction: none
 * warmed up, none reported p99, and each picked its own round count, so the same
 * function measured three ways produced three numbers. Everything routes through
 * here now, so a figure quoted in one report means the same thing in another.
 *
 * Two properties of the host clock shape this design, both measured rather than
 * assumed:
 *
 * - **Resolution is platform-dependent.** `process.hrtime.bigint()` ticks at
 *   100 ns on Windows — 68% of back-to-back reads return a 0 ns delta and the
 *   rest return exactly 100 ns — against roughly 55 ns on Linux. Timing a ~5 µs
 *   call on a 100 ns clock quantises every sample into ~2% steps. `batchSize`
 *   exists for that: it times a run of calls together and divides back out,
 *   trading tail detail for resolution.
 * - **`max` is not a statistic.** It is a single sample, so it reports whichever
 *   GC pause or scheduler preemption happened to land inside the window. The
 *   same sweep on two machines produced maxima ~30x apart while every percentile
 *   agreed within 2x. Report it; never gate on it.
 */

/** Sorted-sample nearest-rank quantile. */
function quantile(sorted: readonly number[], q: number): number {
  if (sorted.length === 0) return 0;
  const index = Math.min(sorted.length - 1, Math.floor(q * sorted.length));
  return sorted[index]!;
}

function mean(values: readonly number[]): number {
  if (values.length === 0) return 0;
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

/** Sample standard deviation (n-1). Zero for fewer than two values. */
function standardDeviation(values: readonly number[]): number {
  if (values.length < 2) return 0;
  const average = mean(values);
  const variance =
    values.reduce((sum, value) => sum + (value - average) ** 2, 0) / (values.length - 1);
  return Math.sqrt(variance);
}

/**
 * Coefficient of variation — standard deviation as a fraction of the mean.
 * Dimensionless, so it compares spread across metrics with different units, and
 * it is the figure a threshold should be sized against.
 */
export function coefficientOfVariation(values: readonly number[]): number {
  const average = mean(values);
  if (average === 0) return 0;
  return standardDeviation(values) / average;
}

export interface SweepOptions {
  /**
   * Untimed calls made before measurement starts, to let the JIT settle.
   * Defaults to 200 — enough that the interpreted-tier samples which otherwise
   * dominate p99 and `max` are gone before recording begins.
   */
  warmupRounds?: number;
  /**
   * Timed samples to collect. Defaults to 1000, so p99 rests on ~10 samples
   * rather than one; below a few hundred, p99 is an outlier reading.
   */
  rounds?: number;
  /**
   * Calls timed together per sample, divided back out. Defaults to 1, giving a
   * true per-call distribution. Raise it when the unit under test is near the
   * clock tick: it multiplies effective resolution by the same factor, at the
   * cost of averaging away the tail inside each batch.
   */
  batchSize?: number;
}

export interface SweepResult {
  /** Samples recorded (batches, not individual calls). */
  n: number;
  /** Microseconds per call. */
  p50: number;
  p95: number;
  p99: number;
  mean: number;
  /** Single worst sample. Diagnostic only — never gate on this. */
  max: number;
  /** Sustained calls per second, derived from the mean. */
  throughputPerSec: number;
}

/** Warm up, then time `fn` and return its latency distribution in microseconds. */
export function timeSweep(fn: () => void, options: SweepOptions = {}): SweepResult {
  const warmupRounds = options.warmupRounds ?? 200;
  const rounds = options.rounds ?? 1000;
  const batchSize = Math.max(1, options.batchSize ?? 1);

  for (let index = 0; index < warmupRounds; index += 1) fn();

  const samples: number[] = [];
  for (let round = 0; round < rounds; round += 1) {
    const startedAt = process.hrtime.bigint();
    for (let call = 0; call < batchSize; call += 1) fn();
    const elapsedNanoseconds = Number(process.hrtime.bigint() - startedAt);
    samples.push(elapsedNanoseconds / 1000 / batchSize);
  }

  return summarise(samples);
}

/** Shared by the sync and async sweeps so the two can never drift apart. */
function summarise(samples: readonly number[]): SweepResult {
  const sorted = [...samples].sort((left, right) => left - right);
  const meanMicroseconds = mean(sorted);
  return {
    n: sorted.length,
    p50: quantile(sorted, 0.5),
    p95: quantile(sorted, 0.95),
    p99: quantile(sorted, 0.99),
    mean: meanMicroseconds,
    max: sorted[sorted.length - 1] ?? 0,
    throughputPerSec: meanMicroseconds === 0 ? 0 : 1_000_000 / meanMicroseconds,
  };
}

/**
 * Async counterpart of `timeSweep`, for work that cannot be measured
 * synchronously — `JsonStore.mutate()` awaits a file write, so its cost is
 * invisible to the sync sweep.
 *
 * Each sample awaits `fn` to completion, so this measures end-to-end latency
 * including the event-loop turn, which is the number a caller actually pays.
 */
export async function timeSweepAsync(
  fn: () => Promise<unknown>,
  options: SweepOptions = {},
): Promise<SweepResult> {
  const warmupRounds = options.warmupRounds ?? 200;
  const rounds = options.rounds ?? 1000;
  const batchSize = Math.max(1, options.batchSize ?? 1);

  for (let index = 0; index < warmupRounds; index += 1) await fn();

  const samples: number[] = [];
  for (let round = 0; round < rounds; round += 1) {
    const startedAt = process.hrtime.bigint();
    for (let call = 0; call < batchSize; call += 1) await fn();
    const elapsedNanoseconds = Number(process.hrtime.bigint() - startedAt);
    samples.push(elapsedNanoseconds / 1000 / batchSize);
  }

  return summarise(samples);
}

export interface StabilityOptions extends SweepOptions {
  /** Independent sweeps to run. Defaults to 5. */
  runs?: number;
}

export interface StabilityResult {
  /** Each sweep result, in order. */
  runs: SweepResult[];
  /**
   * Coefficient of variation across runs, per metric. A CI threshold belongs on
   * whichever of these is smallest: gating a metric whose run-to-run spread
   * approaches the headroom allowed guarantees a flaky build.
   */
  cv: { p50: number; p95: number; p99: number; mean: number };
}

/**
 * Run the sweep repeatedly and report how far the answer moves between runs.
 *
 * A threshold set from a single sample is a guess. Measured over the policy
 * corpus on one machine, across four separate process invocations, run-to-run CV
 * ordered p50 (~3.5%) < p95 (7.5-41%) < mean (~11%) < p99 (~17%). Two things
 * follow. The ordering is durable: p50 is the statistic worth gating, and p99 and
 * `max` are not. The magnitudes are not: p95 CV alone ranged 7.5% to 41% between
 * invocations, so the stability figure itself wants repeating before a threshold
 * is set from it.
 */
export function stability(fn: () => void, options: StabilityOptions = {}): StabilityResult {
  const runCount = options.runs ?? 5;
  const runs: SweepResult[] = [];
  for (let index = 0; index < runCount; index += 1) runs.push(timeSweep(fn, options));
  return {
    runs,
    cv: {
      p50: coefficientOfVariation(runs.map((run) => run.p50)),
      p95: coefficientOfVariation(runs.map((run) => run.p95)),
      p99: coefficientOfVariation(runs.map((run) => run.p99)),
      mean: coefficientOfVariation(runs.map((run) => run.mean)),
    },
  };
}

export interface ResourceDelta {
  /** Resident set size delta, in bytes. */
  rssBytes: number;
  heapUsedBytes: number;
  /** CPU time attributed to the workload, in microseconds. */
  cpuUserMicroseconds: number;
  cpuSystemMicroseconds: number;
  wallMicroseconds: number;
}

/**
 * Memory and CPU consumed across a workload.
 *
 * Honest limitation: without `--expose-gc` the collector cannot be pinned, so
 * `rssBytes` reflects whatever GC did or did not run inside the window. It is a
 * trend signal across a sustained workload, not an allocation count, and a
 * negative delta means a collection landed mid-measurement rather than that the
 * workload released memory.
 */
export function resourceDelta(fn: () => void): ResourceDelta {
  const memoryBefore = process.memoryUsage();
  const cpuBefore = process.cpuUsage();
  const startedAt = process.hrtime.bigint();

  fn();

  const wallMicroseconds = Number(process.hrtime.bigint() - startedAt) / 1000;
  const cpuAfter = process.cpuUsage(cpuBefore);
  const memoryAfter = process.memoryUsage();

  return {
    rssBytes: memoryAfter.rss - memoryBefore.rss,
    heapUsedBytes: memoryAfter.heapUsed - memoryBefore.heapUsed,
    cpuUserMicroseconds: cpuAfter.user,
    cpuSystemMicroseconds: cpuAfter.system,
    wallMicroseconds,
  };
}

export interface ConfidenceInterval {
  /** Observed proportion. */
  point: number;
  low: number;
  high: number;
}

/**
 * Wilson score interval for a binomial proportion.
 *
 * Preferred over the normal approximation because it stays inside [0, 1] and
 * keeps usable coverage at the small trial counts and extreme proportions this
 * corpus produces — the textbook interval degenerates outright at a 1/69 escape
 * rate.
 */
export function wilson(successes: number, trials: number, z = 1.96): ConfidenceInterval {
  if (trials <= 0) return { point: 0, low: 0, high: 1 };
  const point = successes / trials;
  const zSquared = z * z;
  const denominator = 1 + zSquared / trials;
  const center = (point + zSquared / (2 * trials)) / denominator;
  const spread =
    (z / denominator) *
    Math.sqrt((point * (1 - point)) / trials + zSquared / (4 * trials * trials));
  // An interval must contain its own point estimate. At p=1 the arithmetic
  // above returns 0.9999999999999998 for the upper bound -- floating-point
  // noise, but it makes the published interval exclude the value it is an
  // interval for, and it only ever shows up at exactly 0% or 100%, which is
  // where these figures are most often quoted. Clamping to the point rather
  // than widening keeps every other case byte-identical.
  return {
    point,
    low: Math.min(point, Math.max(0, center - spread)),
    high: Math.max(point, Math.min(1, center + spread)),
  };
}

/**
 * Exact one-sided upper bound on a failure rate when zero failures were observed.
 *
 * "0 secret leaks in 33 attempts" is not evidence that the true rate is zero.
 * This is the Clopper-Pearson bound, `1 - alpha^(1/n)` — the quantity the "rule
 * of three" (3/n) approximates.
 *
 * Prefer it over `wilson()` for zero-failure claims because it is exact and
 * conservative. Compared like-for-like at 0/69, Wilson's ONE-sided upper bound
 * (z = 1.645) is 3.77% against this bound's 4.25%, so Clopper-Pearson is the
 * WIDER of the two. That is the property worth having in a security writeup: a
 * residual-risk claim that errs toward overstating risk cannot be accused of
 * understating it. Against Wilson's two-sided 5.27% this bound looks tighter,
 * but that comparison mixes sidedness and means nothing.
 */
export function zeroFailureUpperBound(trials: number, confidence = 0.95): number {
  if (trials <= 0) return 1;
  const alpha = 1 - confidence;
  return 1 - Math.pow(alpha, 1 / trials);
}
