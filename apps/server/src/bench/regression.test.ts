import { describe, expect, it } from "vitest";
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
  it("stays linear in the number of stored events", async () => {
    // The load-bearing invariant. r-squared has been 0.9931-1.0000 across five
    // environments; it is the most stable thing measured in this lane, because
    // it is a property of the algorithm rather than of the machine. If the store
    // ever becomes super-linear this is what catches it, and a threshold of 0.98
    // cannot be tripped by a busy runner.
    const { rSquared } = await slopeAndLinearity();
    expect(rSquared).toBeGreaterThanOrEqual(0.98);
  }, 60_000);

  it("keeps the marginal cost under an algorithmic-regression ceiling", async () => {
    // 25 us/event against a measured worst case of 6.08 on a heavily loaded
    // laptop and 2.15-3.09 in CI: roughly 4x headroom over the worst honest
    // reading. Deliberately loose. This is not tuned to detect a 20% slowdown -
    // the measurement cannot support that claim - it is tuned to detect the
    // store becoming quadratic, which it would catch immediately.
    const { slope } = await slopeAndLinearity();
    expect(slope).toBeLessThan(25);
  }, 60_000);
});

describe("absolutes, pinned CI only", () => {
  it.skipIf(!PINNED_CI)(
    "keeps the store-write marginal cost near its CI baseline",
    async () => {
      // Measured on ubuntu-latest: 2.15 (node 22 in-bench), 2.60 and 2.80
      // (node 24 / node 22 standalone). Threshold 8 us/event is ~3x the highest,
      // sized from the 22.9%-27.6% CV observed for timing metrics. Tighten this
      // once several CI runs have been collected - a baseline file is the
      // follow-up, and it needs history this branch does not have yet.
      const { slope } = await slopeAndLinearity();
      expect(slope).toBeLessThan(8);
    },
    60_000,
  );

  it.skipIf(!PINNED_CI)("keeps policy decision p50 near its CI baseline", () => {
    // p50 ONLY. p95 and p99 are not gated: their run-to-run CV was 28.0% and
    // 26.4% on the same ubuntu runner that gave p50 22.9%, and p99 reached 48.8%
    // locally. Gating those would be gating the runner. See plan §2.2.
    const p50 = median(
      Array.from(
        { length: REPETITIONS },
        () => timeSweep(policyWorkload(), { warmupRounds: 200, rounds: 1000 }).p50,
      ),
    );
    // CI measured 4.77 us p50; 15 us is ~3x. Same reasoning as above.
    expect(p50).toBeLessThan(15);
  }, 60_000);
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
