/**
 * Live evaluation summary, computed from the SAME policy engine that enforces at
 * runtime. Because the numbers are derived on demand from `evaluateCommand`, the
 * in-app dashboard can never drift from the deployed policy — it is not a static
 * report, it is a measurement of the code that is actually running.
 */

import { evaluateCommand, policyContextFrom, type Actor } from "./command-policy.js";
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
  latency: { p50: number; p95: number; mean: number };
  families: { family: Family; attacks: number; escaped: number }[];
  escapes: { id: string; family: Family }[];
}

const EVALUATION_SUMMARY_ACTOR: Actor = { agentId: "eval", threadId: null };

function latency(): { p50: number; p95: number; mean: number } {
  const ctx = policyContextFrom("https://ark.cn-beijing.volces.com/api/v3", [], [], "/workspace");
  const samples: number[] = [];
  for (let round = 0; round < 30; round += 1) {
    for (const entry of POLICY_CORPUS) {
      const t0 = process.hrtime.bigint();
      evaluateCommand(EVALUATION_SUMMARY_ACTOR, entry.command, ctx);
      samples.push(Number(process.hrtime.bigint() - t0) / 1000);
    }
  }
  samples.sort((a, b) => a - b);
  const at = (q: number) => samples[Math.floor(q * samples.length)] ?? 0;
  return {
    p50: at(0.5),
    p95: at(0.95),
    mean: samples.reduce((s, x) => s + x, 0) / samples.length,
  };
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
