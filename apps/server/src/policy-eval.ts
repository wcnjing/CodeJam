/**
 * Scorecard for the command policy engine.
 *
 * Turns the labeled corpus into measurable quality signals: detection recall,
 * false-positive rate on legitimate developer commands, per-category coverage,
 * evasion resistance, and evaluation overhead. `policy-eval.test.ts` asserts
 * thresholds so a regression fails `npm run check`, and `npm run eval:policy`
 * prints the human-readable report used in the writeup.
 */

import { timeSweep } from "./bench/metrics.js";
import { BENCHMARK_ACTOR, BENCHMARK_CONTEXT, policyWorkload } from "./bench/policy-workload.js";
import { evaluateCommand } from "./command-policy.js";
import {
  CORPUS_WRITE_ROOTS,
  EVASION_CATEGORIES,
  POLICY_CORPUS,
  type CorpusEntry,
} from "./policy-corpus.js";

export interface CategoryScore {
  category: string;
  total: number;
  detected: number;
  rate: number;
}

export interface EvaluationResult {
  /** Malicious entries excluding deliberate evasion attempts. */
  coreRecall: number;
  coreDetected: number;
  coreTotal: number;
  /** Evasion attempts, scored separately — expected to be the weak area. */
  evasionRecall: number;
  evasionDetected: number;
  evasionTotal: number;
  /** Benign commands wrongly blocked. The usability cost of the control. */
  falsePositiveRate: number;
  falsePositives: CorpusEntry[];
  /** Malicious commands missed, excluding evasion. */
  falseNegatives: CorpusEntry[];
  /** Evasion attempts that slipped through, reported for honesty. */
  evasionMisses: CorpusEntry[];
  precision: number;
  f1: number;
  /**
   * Recall on the retained external-review challenge cases — entries written by
   * reviewers who did not read the rule source. Reported with its denominator:
   * a rate over an unstated sample size is not evidence.
   */
  externalReviewRecall: number;
  externalReviewFalsePositiveRate: number;
  externalReviewMaliciousTotal: number;
  externalReviewBenignTotal: number;
  /** Entries authored during a review of the rules; retained, not independent. */
  internalRedTeamTotal: number;
  byCategory: CategoryScore[];
  ruleCounts: Record<string, number>;
  /** Mean evaluateCommand cost in microseconds. */
  meanMicroseconds: number;
}

// The scorecard evaluates as the same pinned actor and against the same pinned
// context as every other harness, so its rule counts and its latency figure
// describe one engine configuration rather than two.
const EVAL_ACTOR = BENCHMARK_ACTOR;
const DEFAULT_CONTEXT = BENCHMARK_CONTEXT;

function isBlocked(entry: CorpusEntry, context = DEFAULT_CONTEXT): string | null {
  const violation = evaluateCommand(EVAL_ACTOR, entry.command, context);
  return violation ? violation.rule : null;
}

function rate(numerator: number, denominator: number): number {
  return denominator === 0 ? 1 : numerator / denominator;
}

export function evaluatePolicy(
  corpus: CorpusEntry[] = POLICY_CORPUS,
): EvaluationResult {
  const ruleCounts: Record<string, number> = {};
  const categoryTotals = new Map<string, { total: number; detected: number }>();

  const falsePositives: CorpusEntry[] = [];
  const falseNegatives: CorpusEntry[] = [];
  const evasionMisses: CorpusEntry[] = [];

  let coreDetected = 0;
  let coreTotal = 0;
  let evasionDetected = 0;
  let evasionTotal = 0;
  let benignTotal = 0;
  let externalMaliciousTotal = 0;
  let externalMaliciousDetected = 0;
  let externalBenignTotal = 0;
  let externalBenignBlocked = 0;

  for (const entry of corpus) {
    const rule = isBlocked(entry);
    if (rule) ruleCounts[rule] = (ruleCounts[rule] ?? 0) + 1;

    const bucket = categoryTotals.get(entry.category) ?? { total: 0, detected: 0 };
    bucket.total += 1;

    if (entry.label === "malicious") {
      const isEvasion = EVASION_CATEGORIES.has(entry.category);
      if (rule) bucket.detected += 1;

      if (isEvasion) {
        evasionTotal += 1;
        if (rule) evasionDetected += 1;
        else evasionMisses.push(entry);
      } else {
        coreTotal += 1;
        if (rule) coreDetected += 1;
        else falseNegatives.push(entry);
      }

      if (entry.source === "external-review") {
        externalMaliciousTotal += 1;
        if (rule) externalMaliciousDetected += 1;
      }
    } else {
      benignTotal += 1;
      // For benign entries "detected" means correctly allowed.
      if (!rule) bucket.detected += 1;
      else falsePositives.push(entry);

      if (entry.source === "external-review") {
        externalBenignTotal += 1;
        if (rule) externalBenignBlocked += 1;
      }
    }

    categoryTotals.set(entry.category, bucket);
  }

  const truePositives = coreDetected + evasionDetected;
  const precision = rate(truePositives, truePositives + falsePositives.length);
  const recallAll = rate(truePositives, coreTotal + evasionTotal);
  const f1 =
    precision + recallAll === 0 ? 0 : (2 * precision * recallAll) / (precision + recallAll);

  return {
    coreRecall: rate(coreDetected, coreTotal),
    coreDetected,
    coreTotal,
    evasionRecall: rate(evasionDetected, evasionTotal),
    evasionDetected,
    evasionTotal,
    falsePositiveRate: benignTotal === 0 ? 0 : falsePositives.length / benignTotal,
    falsePositives,
    falseNegatives,
    evasionMisses,
    precision,
    f1,
    externalReviewRecall: rate(externalMaliciousDetected, externalMaliciousTotal),
    externalReviewFalsePositiveRate:
      externalBenignTotal === 0 ? 0 : externalBenignBlocked / externalBenignTotal,
    externalReviewMaliciousTotal: externalMaliciousTotal,
    externalReviewBenignTotal: externalBenignTotal,
    internalRedTeamTotal: corpus.filter((entry) => entry.source === "internal-red-team").length,
    byCategory: [...categoryTotals.entries()]
      .map(([category, value]) => ({
        category,
        total: value.total,
        detected: value.detected,
        rate: rate(value.detected, value.total),
      }))
      .sort((left, right) => left.category.localeCompare(right.category)),
    ruleCounts,
    meanMicroseconds: measureThroughput(corpus),
  };
}

/**
 * Mean per-command evaluation cost, to show the control adds negligible overhead.
 *
 * Batched at one full corpus pass per sample. That keeps the figure directly
 * comparable to the hand-rolled timer this replaced — which took a single hrtime
 * pair around every call and so never paid per-call timer overhead — while still
 * producing a distribution rather than a single number. See `bench/metrics.ts`
 * for why per-call timing of a ~5 µs function needs care on a 100 ns clock.
 */
function measureThroughput(corpus: CorpusEntry[]): number {
  if (corpus.length === 0) return 0;
  const workload = policyWorkload(
    corpus.map((entry) => entry.command),
    DEFAULT_CONTEXT,
  );
  // Warmup sized for the engine actually being measured.
  //
  // This was `corpus.length * 2` (~240 calls), carried over from when the policy
  // was a handful of regexes. Against the capability engine - a real shell
  // parser with far more code paths - that measures a cold JIT and reported ~2x
  // the steady-state cost, which is what tripped `policy-eval.test.ts`'s <50us
  // gate on CI while the same engine passed it on main. Main's loop is 200 full
  // corpus passes in one timed block, so its mean is almost entirely warm; this
  // now warms for comparably long before timing anything.
  return timeSweep(workload, {
    warmupRounds: corpus.length * 40,
    rounds: 40,
    batchSize: corpus.length,
  }).mean;
}

function percent(value: number): string {
  return (value * 100).toFixed(1).padStart(5) + "%";
}

export function formatReport(result: EvaluationResult): string {
  const lines: string[] = [];
  lines.push("Command policy scorecard");
  lines.push("========================");
  lines.push("");
  lines.push(
    "  Core detection      " +
      percent(result.coreRecall) +
      "   (" + result.coreDetected + "/" + result.coreTotal + " direct attacks caught)",
  );
  lines.push(
    "  Evasion resistance  " +
      percent(result.evasionRecall) +
      "   (" + result.evasionDetected + "/" + result.evasionTotal + " obfuscated attacks caught)",
  );
  lines.push(
    "  False positives     " +
      percent(result.falsePositiveRate) +
      "   (" + result.falsePositives.length + " legitimate commands blocked)",
  );
  lines.push("  Precision           " + percent(result.precision));
  lines.push("  F1                  " + percent(result.f1));
  lines.push(
    "  External-review recall " +
      percent(result.externalReviewRecall) +
      "   (" + result.externalReviewMaliciousTotal +
      " attacks written without reading the rules)",
  );
  lines.push(
    "  External-review FPR    " +
      percent(result.externalReviewFalsePositiveRate) +
      "   (" + result.externalReviewBenignTotal +
      " legitimate reviewer cases)",
  );
  lines.push(
    "  Internal red-team      " +
      String(result.internalRedTeamTotal).padStart(6) +
      "   (authored while reading the rules; retained, not independent)",
  );
  lines.push("  Mean eval cost      " + result.meanMicroseconds.toFixed(1) + " us/command");
  lines.push("");
  lines.push("Per category");
  lines.push("------------");
  for (const category of result.byCategory) {
    lines.push(
      "  " +
        category.category.padEnd(22) +
        percent(category.rate) +
        "   (" + category.detected + "/" + category.total + ")",
    );
  }
  lines.push("");
  lines.push("Rules fired");
  lines.push("-----------");
  for (const [rule, count] of Object.entries(result.ruleCounts).sort()) {
    lines.push("  " + rule.padEnd(26) + String(count));
  }

  if (result.falsePositives.length > 0) {
    lines.push("");
    lines.push("False positives (legitimate work the control would break)");
    lines.push("---------------------------------------------------------");
    for (const entry of result.falsePositives) lines.push("  ! " + entry.command);
  }

  if (result.falseNegatives.length > 0) {
    lines.push("");
    lines.push("Missed direct attacks");
    lines.push("---------------------");
    for (const entry of result.falseNegatives) lines.push("  x " + entry.command);
  }

  if (result.evasionMisses.length > 0) {
    lines.push("");
    lines.push("Known bypasses (documented residual risk)");
    lines.push("-----------------------------------------");
    for (const entry of result.evasionMisses) {
      lines.push("  ~ " + entry.command);
      if (entry.note) lines.push("      " + entry.note);
    }
  }

  return lines.join("\n");
}
