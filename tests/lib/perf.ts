/**
 * Performance and operational-cost harness — provider-agnostic.
 *
 * Measures each middleware layer the way an operator would care about:
 *   - per-decision latency (µs) for the command policy
 *   - end-to-end cost of the whole stack per command
 *   - redaction cost and leak-check coverage
 *   - scanCommands throughput on a stream (the runner's hot path)
 *   - config load cost (startup path)
 *   - scaling with command length (short / mid / long)
 *
 * All timings use process.hrtime.bigint and exclude model time — the policy
 * adds microseconds per command, which is the honest operational claim.
 * The middleware surface is injected (`deps`), so this library never imports
 * the platform.
 */

import {
  defaultEnv,
  wrapped,
  type EvalEnv,
  type MiddlewareProfile,
  type EvaluationDeps,
} from "./profiles.js";
import type { PerfReport, PerfSample, TestCase } from "./types.js";

interface Timing {
  samples: number[];
  mean: number;
  p50: number;
  p95: number;
  ops: number;
}

function percentile(sorted: number[], q: number): number {
  if (sorted.length === 0) return 0;
  return sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))]!;
}

function summarize(samples: number[], elapsedNs: number): Timing {
  const sorted = [...samples].sort((a, b) => a - b);
  const mean = samples.reduce((s, x) => s + x, 0) / samples.length;
  return {
    samples,
    mean,
    p50: percentile(sorted, 0.5),
    p95: percentile(sorted, 0.95),
    ops: samples.length === 0 ? 0 : 1e9 / (elapsedNs / samples.length),
  };
}

export interface PerfOptions {
  cases: readonly TestCase[];
  iterations?: number;
  deps: EvaluationDeps;
  /** The whole-stack ("all") profile, for the end-to-end chain measure. */
  allProfile: MiddlewareProfile;
  env?: EvalEnv;
}

function bucketOf(command: string): string {
  if (command.length <= 80) return "short (<=80 chars)";
  if (command.length <= 200) return "mid (81-200 chars)";
  return "long (>200 chars)";
}

export function runPerf(options: PerfOptions): PerfReport {
  const cases = options.cases;
  const iterations = options.iterations ?? 200;
  const deps = options.deps;
  const env = options.env ?? defaultEnv(deps);
  const samples: PerfSample[] = [];

  const measure = (
    profileId: string,
    profileName: string,
    metric: string,
    fn: (case_: TestCase) => unknown,
    byLength = false,
  ): void => {
    const raw: number[] = [];
    const byLengthSamples: Record<string, number[]> = {};
    const start = process.hrtime.bigint();
    for (let i = 0; i < iterations; i += 1) {
      for (const case_ of cases) {
        const t0 = process.hrtime.bigint();
        fn(case_);
        const elapsed = Number(process.hrtime.bigint() - t0) / 1000; // µs
        raw.push(elapsed);
        if (byLength) {
          const b = bucketOf(case_.command);
          (byLengthSamples[b] ??= []).push(elapsed);
        }
      }
    }
    const elapsedNs = Number(process.hrtime.bigint() - start);
    const timing = summarize(raw, elapsedNs);
    const lengthBuckets = byLength
      ? Object.fromEntries(
          Object.entries(byLengthSamples).map(([b, arr]) => [
            b,
            { samples: arr.length, meanMicroseconds: arr.reduce((s, x) => s + x, 0) / arr.length },
          ]),
        )
      : undefined;
    samples.push({
      profileId,
      profileName,
      metric,
      samples: raw.length,
      meanMicroseconds: timing.mean,
      p50Microseconds: timing.p50,
      p95Microseconds: timing.p95,
      opsPerSecond: timing.ops,
      byLength: lengthBuckets,
    });
  };

  // 1. Command policy — plain evaluateCommand.
  measure("command-policy", "Command policy", "evaluateCommand per case", (c) =>
    deps.evaluateCommand(c.wrapped ? wrapped(c.command) : c.command, env.policyContext),
    true,
  );
  // 2. Command policy — guarded (fail-closed wrapper, the runner's actual call).
  measure("command-policy", "Command policy", "guardedEvaluate per case", (c) =>
    deps.guardedEvaluate(c.wrapped ? wrapped(c.command) : c.command, env.policyContext),
  );
  // 3. Redaction.
  measure("redaction", "Evidence redaction", "redactCommand per case", (c) =>
    deps.redactCommand(c.wrapped ? wrapped(c.command) : c.command, env.secretValues),
  );
  // 4. Whole stack (policy + approval classification + redaction) — the
  //    regression profile is the closest model of the production path.
  measure("all", "Whole stack", "full chain per case", (c) => options.allProfile.evaluate(c, env));

  // 5. scanCommands throughput on a synthetic stream of the catalog.
  {
    const stream: string[] = [];
    for (let i = 0; i < 50; i += 1) {
      for (const c of cases) stream.push(c.wrapped ? wrapped(c.command) : c.command);
    }
    const runs = 20;
    // Time each batch run separately so the p50/p95 columns report a real
    // per-run distribution instead of echoing the aggregate mean.
    const runSamples: number[] = [];
    const wallStart = process.hrtime.bigint();
    for (let r = 0; r < runs; r += 1) {
      const t0 = process.hrtime.bigint();
      deps.scanCommands(stream, 0, env.policyContext);
      const elapsed = Number(process.hrtime.bigint() - t0);
      runSamples.push(elapsed / 1000 / stream.length); // µs per command, one sample per batch
    }
    const elapsed = Number(process.hrtime.bigint() - wallStart);
    const timing = summarize(runSamples, elapsed / stream.length);
    samples.push({
      profileId: "command-policy",
      profileName: "Command policy",
      metric: "scanCommands per command (streamed batch)",
      samples: stream.length * runs,
      meanMicroseconds: timing.mean,
      p50Microseconds: timing.p50,
      p95Microseconds: timing.p95,
      opsPerSecond: timing.ops,
    });
  }

  // 6. Config load (startup path, one-time cost).
  {
    const start = process.hrtime.bigint();
    for (let i = 0; i < 200; i += 1) {
      deps.loadConfig({ NODE_ENV: "test", ARK_API_KEY: "k", ARK_MODEL: "ep-test" });
    }
    const elapsed = Number(process.hrtime.bigint() - start);
    const per = elapsed / 1000 / 200;
    samples.push({
      profileId: "config",
      profileName: "Config invariants",
      metric: "loadConfig (startup)",
      samples: 200,
      meanMicroseconds: per,
      p50Microseconds: per,
      p95Microseconds: per,
      opsPerSecond: 1e9 / (elapsed / 200),
    });
  }

  return { generatedAt: new Date().toISOString(), samples };
}
