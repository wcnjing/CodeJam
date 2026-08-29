/**
 * One benchmark entry point.
 *
 * Before this there were four CLIs with overlapping computation and no combined
 * machine-readable output: `eval:policy`, `bench:security`, `threat-model` and
 * `bench:store`, each printing for humans only. Nothing could be diffed
 * run-over-run, and no number could be attributed to a build.
 *
 * This aggregates all of them into one result carrying full provenance, and
 * expresses every proportion as numerator / denominator / confidence interval
 * rather than a bare percentage. "1.4% escape rate" is not a finding on its own;
 * "1 of 69, 95% CI 0.3%-7.8%" says how much to trust it.
 *
 * It composes the existing harnesses and adds no measurement of its own:
 * `evaluatePolicy()`, `runBenchmark()`, `THREAT_REGISTER`, `runRedTeam()`,
 * `measureStoreOverhead()` and `bench/metrics.ts`.
 */

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { POLICY_CORPUS } from "../policy-corpus.js";
import { evaluatePolicy } from "../policy-eval.js";
import { runRedTeam } from "../redteam.js";
import { runBenchmark } from "../security-benchmark.js";
import { THREAT_REGISTER } from "../threat-model.js";
import {
  stability,
  timeSweep,
  wilson,
  zeroFailureUpperBound,
  type SweepResult,
} from "./metrics.js";
import { policyWorkload } from "./policy-workload.js";
import { measureStoreOverhead, type StoreOverheadResult } from "./store-overhead.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const serverSrc = path.join(here, "..");

/**
 * Threat ids claimed by an `@covers` tag somewhere in the test suite.
 *
 * Same scan `threat-model-cli.ts` performs, over `src/*.test.ts`. Duplicated
 * rather than imported because the CLI computes it at module scope for printing
 * and exports nothing; extracting it would mean editing that file, which this
 * lane has no need to touch.
 */
function coveredThreatIds(): Set<string> {
  const covered = new Set<string>();
  for (const file of readdirSync(serverSrc)) {
    if (!file.endsWith(".test.ts")) continue;
    const text = readFileSync(path.join(serverSrc, file), "utf8");
    for (const match of text.matchAll(/@covers\s+((?:TM-[A-Z]+-\d+\s*)+)/g)) {
      for (const id of match[1]!.trim().split(/\s+/)) covered.add(id);
    }
  }
  return covered;
}

export interface RunMetadata {
  timestamp: string;
  gitSha: string | null;
  gitDirty: boolean | null;
  nodeVersion: string;
  platform: string;
  arch: string;
  cpuModel: string | null;
  cpuCount: number;
  corpusSize: number;
  /**
   * Content hash of the policy rules.
   *
   * The engine exposes no version of its own — a policy-set version or hash at
   * runtime is item 8 of what §3 asks Person 1 for. Until then this is a
   * SHA-256 of `command-policy.ts`, which is a stand-in with an honest failure
   * mode: it changes on a comment edit, and would not change if rules moved to
   * another file. It is enough to tell two builds apart, not enough to call a
   * policy version.
   */
  policyHash: string;
  policyHashSource: string;
}

/**
 * A proportion with everything needed to judge it: the counts it came from and
 * an interval. Never just a rate.
 */
export interface Proportion {
  numerator: number;
  denominator: number;
  rate: number;
  /** Wilson score interval, 95%. */
  ci: { low: number; high: number };
  /**
   * For zero-numerator results only: the exact one-sided 95% upper bound
   * (Clopper-Pearson). "0 leaks in 33" is not evidence the true rate is zero.
   */
  zeroUpperBound?: number;
}

export interface BenchResults {
  metadata: RunMetadata;
  security: {
    attackBlockRate: Proportion;
    unsafeActionEscapeRate: Proportion;
    falsePositiveRate: Proportion;
    secretLeakRate: Proportion;
    baselineEscapeRate: Proportion;
    byFamily: { family: string; attacks: number; escaped: number }[];
  };
  classifier: {
    coreRecall: Proportion;
    evasionRecall: Proportion;
    holdoutRecall: Proportion;
    precision: number;
    f1: number;
  };
  redteam: {
    denialRate: Proportion;
    documentedBypasses: string[];
    regressions: string[];
  };
  threatModel: {
    coverage: Proportion;
    open: string[];
  };
  latency: {
    microseconds: SweepResult;
    /** Run-to-run coefficient of variation, per metric. */
    stabilityCv: { p50: number; p95: number; p99: number; mean: number };
  };
  storeOverhead: StoreOverheadResult;
}

function proportion(numerator: number, denominator: number): Proportion {
  const interval = wilson(numerator, denominator);
  const result: Proportion = {
    numerator,
    denominator,
    rate: denominator === 0 ? 0 : numerator / denominator,
    ci: { low: interval.low, high: interval.high },
  };
  if (numerator === 0 && denominator > 0) {
    result.zeroUpperBound = zeroFailureUpperBound(denominator);
  }
  return result;
}

function git(args: string[]): string | null {
  try {
    return execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] })
      .trim();
  } catch {
    return null;
  }
}

function metadata(): RunMetadata {
  const policySource = path.join(here, "..", "command-policy.ts");
  let policyHash = "unavailable";
  try {
    policyHash = createHash("sha256").update(readFileSync(policySource)).digest("hex").slice(0, 16);
  } catch {
    // Running from dist/, where the .ts source is not present.
  }
  const status = git(["status", "--porcelain"]);
  const cpus = os.cpus();
  return {
    timestamp: new Date().toISOString(),
    gitSha: git(["rev-parse", "HEAD"]),
    gitDirty: status === null ? null : status.length > 0,
    nodeVersion: process.versions.node,
    platform: process.platform,
    arch: process.arch,
    cpuModel: cpus[0]?.model ?? null,
    cpuCount: cpus.length,
    corpusSize: POLICY_CORPUS.length,
    policyHash,
    policyHashSource: "sha256(command-policy.ts), first 16 hex - see RunMetadata.policyHash",
  };
}

export interface BenchOptions {
  /** Skip the store sweep, which is the slowest part. */
  skipStore?: boolean;
  /** Sweeps for the stability figure. */
  stabilityRuns?: number;
}

export async function runBench(options: BenchOptions = {}): Promise<BenchResults> {
  const protectedRun = runBenchmark("protected");
  const baseline = runBenchmark("baseline");
  const classifier = evaluatePolicy();
  const redteam = runRedTeam();

  const holdoutTotal = POLICY_CORPUS.filter(
    (entry) => entry.holdout && entry.label === "malicious",
  ).length;

  const mitigated = THREAT_REGISTER.filter((threat) => threat.status === "mitigated");
  const covered = coveredThreatIds();

  const latency = timeSweep(policyWorkload(), { warmupRounds: 200, rounds: 2000 });
  const stabilityResult = stability(policyWorkload(), {
    runs: options.stabilityRuns ?? 5,
    warmupRounds: 200,
    rounds: 2000,
  });

  const storeOverhead = options.skipStore
    ? { points: [], fit: { fixedCostMilliseconds: 0, marginalMicrosecondsPerEvent: 0, rSquared: 0 }, platform: process.platform, nodeVersion: process.versions.node }
    : await measureStoreOverhead();

  return {
    metadata: metadata(),
    security: {
      attackBlockRate: proportion(protectedRun.blocked, protectedRun.attacks),
      unsafeActionEscapeRate: proportion(protectedRun.escaped, protectedRun.attacks),
      falsePositiveRate: proportion(protectedRun.benignBlocked, protectedRun.benign),
      secretLeakRate: proportion(protectedRun.secretLeaks, protectedRun.secretAttacks),
      baselineEscapeRate: proportion(baseline.escaped, baseline.attacks),
      byFamily: protectedRun.byFamily.map((family) => ({ ...family })),
    },
    classifier: {
      coreRecall: proportion(classifier.coreDetected, classifier.coreTotal),
      evasionRecall: proportion(classifier.evasionDetected, classifier.evasionTotal),
      // `EvaluationResult` exposes holdout recall as a rate without its counts.
      // Recall is detected/total over integers, so multiplying back recovers the
      // numerator exactly - this is reconstruction, not estimation.
      holdoutRecall: proportion(
        Math.round(classifier.holdoutRecall * holdoutTotal),
        holdoutTotal,
      ),
      precision: classifier.precision,
      f1: classifier.f1,
    },
    redteam: {
      denialRate: proportion(redteam.denied, redteam.total),
      documentedBypasses: redteam.missed.map((probe) => probe.name),
      regressions: redteam.regressions,
    },
    threatModel: {
      coverage: proportion(
        mitigated.filter((threat) => covered.has(threat.id)).length,
        mitigated.length,
      ),
      open: THREAT_REGISTER.filter((threat) => threat.status === "open").map(
        (threat) => threat.id,
      ),
    },
    latency: { microseconds: latency, stabilityCv: stabilityResult.cv },
    storeOverhead,
  };
}
