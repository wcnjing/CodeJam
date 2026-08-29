/**
 * Live evaluation summary, computed from the SAME policy engine that enforces at
 * runtime. Because the numbers are derived on demand from `evaluateCommand`, the
 * in-app dashboard can never drift from the deployed policy — it is not a static
 * report, it is a measurement of the code that is actually running.
 */

import { timeSweep } from "./bench/metrics.js";
import { policyWorkload } from "./bench/policy-workload.js";
import { POLICY_CORPUS } from "./policy-corpus.js";
import { evaluatePolicy } from "./policy-eval.js";
import { runBenchmark, type Family } from "./security-benchmark.js";

export interface EvaluationSummary {
  generatedAt: string;
  corpusSize: number;
  headline: {
    unsafeActionEscapeRate: number;
    baselineEscapeRate: number;
    attackBlockRate: number;
    attacks: number;
    escaped: number;
  };
  secrets: { leaks: number; attacks: number; baselineLeaks: number };
  falsePositiveRate: number;
  benign: number;
  policy: {
    coreRecall: number;
    evasionRecall: number;
    externalReviewRecall: number;
    externalReviewFalsePositiveRate: number;
    /** Sample sizes behind the two rates above; a rate alone is not evidence. */
    externalReviewAttacks: number;
    externalReviewBenign: number;
    /** Retained regressions authored while reading the rules, not independent. */
    internalRedTeam: number;
    precision: number;
    f1: number;
  };
  /**
   * Per-command policy evaluation cost, in microseconds.
   *
   * `p99` is OPTIONAL and must stay that way. `apps/web/src/types.ts` hand-copies
   * this interface with no shared import and no build-time link between them, so
   * a required field added here breaks the dashboard at runtime with a green
   * build. The two copies have already drifted once: the server types `families`
   * and `escapes` with the `Family` union where the web side widened both to
   * `string`. `app.test.ts` pins the payload shape for that reason.
   */
  latency: { p50: number; p95: number; mean: number; p99?: number };
  families: { family: Family; attacks: number; escaped: number }[];
  escapes: { id: string; family: Family }[];
}

function latency(): { p50: number; p95: number; mean: number; p99: number } {
  const sweep = timeSweep(policyWorkload(), { warmupRounds: 200, rounds: 2000 });
  return { p50: sweep.p50, p95: sweep.p95, mean: sweep.mean, p99: sweep.p99 };
}

export function buildEvaluationSummary(): EvaluationSummary {
  const prot = runBenchmark("protected");
  const base = runBenchmark("baseline");
  const evalResult = evaluatePolicy();

  return {
    generatedAt: new Date().toISOString(),
    corpusSize: POLICY_CORPUS.length,
    headline: {
      unsafeActionEscapeRate: prot.unsafeActionEscapeRate,
      baselineEscapeRate: base.unsafeActionEscapeRate,
      attackBlockRate: prot.attackBlockRate,
      attacks: prot.attacks,
      escaped: prot.escaped,
    },
    secrets: { leaks: prot.secretLeaks, attacks: prot.secretAttacks, baselineLeaks: base.secretLeaks },
    falsePositiveRate: prot.falsePositiveRate,
    benign: prot.benign,
    policy: {
      coreRecall: evalResult.coreRecall,
      evasionRecall: evalResult.evasionRecall,
      externalReviewRecall: evalResult.externalReviewRecall,
      externalReviewFalsePositiveRate: evalResult.externalReviewFalsePositiveRate,
      externalReviewAttacks: evalResult.externalReviewMaliciousTotal,
      externalReviewBenign: evalResult.externalReviewBenignTotal,
      internalRedTeam: evalResult.internalRedTeamTotal,
      precision: evalResult.precision,
      f1: evalResult.f1,
    },
    latency: latency(),
    families: prot.byFamily,
    escapes: prot.cases
      .filter((c) => c.escaped)
      .map((c) => ({ id: c.id, family: c.family })),
  };
}
