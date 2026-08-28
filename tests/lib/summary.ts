/**
 * Pentest summary — the "library of tests" as a single on-demand measurement,
 * served to the web UI's Security Evaluation page and available to the CLI.
 *
 * Runs every middleware profile (baseline, command policy, redaction, budget,
 * approval, monitor, config, whole stack) over the tagged bypass catalog and
 * measures operational cost, then returns a structured summary the frontend
 * renders. Unlike the full CLI suite, this deliberately does NOT spawn the
 * real CodexRunner or run the project's own test gate — those stay in
 * CI/CLI-land; here only the pure decision-layer passes run, fast enough for a
 * request handler. Results are cached briefly so page reloads do not recompute.
 *
 * The middleware surface is injected (`deps`): the server app hands in the
 * real functions for /api/pentest; the CLI wiring does the same locally.
 */

import { loadCatalog } from "./catalog.js";
import { gitRevision, runProfile } from "./harness.js";
import { runPerf } from "./perf.js";
import {
  createProfiles,
  defaultEnv,
  type MiddlewareProfile,
  type EvaluationDeps,
} from "./profiles.js";
import type { BucketScore, PerfReport, SuiteResult, SuiteTotals, TestCase } from "./types.js";

export interface EvaluationSuiteSummary {
  suite: string;
  profileId: string;
  profileName: string;
  totals: SuiteTotals;
  byTag: Record<string, BucketScore>;
}

export interface EvaluationResidual {
  caseId: string;
  command: string;
  tags: string[];
  category: string;
}

export interface EvaluationRunSummary {
  generatedAt: string;
  revision: string;
  catalogSize: number;
  suites: EvaluationSuiteSummary[];
  perf: PerfReport;
  residuals: {
    /** Malicious commands the whole stack would allow — the escape list. */
    escapes: EvaluationResidual[];
    /** Benign commands the whole stack would block — the false positives. */
    falsePositives: EvaluationResidual[];
  };
  limitations: string[];
}

export interface EvaluationOptions {
  deps: EvaluationDeps;
  refresh?: boolean;
}

/** perf iterations for the UI path — enough to be stable, fast enough to wait on. */
const UI_PERF_ITERATIONS = 100;
const CACHE_TTL_MS = 30_000;

let cached: { at: number; value: EvaluationRunSummary } | null = null;

export async function runEvaluationSummary(options: EvaluationOptions): Promise<EvaluationRunSummary> {
  const { deps, refresh = false } = options;
  if (!refresh && cached && Date.now() - cached.at < CACHE_TTL_MS) {
    return cached.value;
  }
  const cases = await loadCatalog();
  const env = defaultEnv(deps);
  const profiles: readonly MiddlewareProfile[] = createProfiles(deps);
  const results: SuiteResult[] = profiles.map((profile) =>
    runProfile({ profile, cases, env }),
  );
  const suites: EvaluationSuiteSummary[] = results.map((result) => ({
    suite: suiteName(result.profileId),
    profileId: result.profileId,
    profileName: result.profileName,
    totals: result.totals,
    byTag: result.byTag,
  }));

  const whole = results.find((r) => r.profileId === "all")!;
  const index = new Map(cases.map((c) => [c.id, c]));
  const residual = (caseId: string): EvaluationResidual | null => {
    const entry = index.get(caseId);
    if (!entry) return null;
    return { caseId, command: entry.command, tags: entry.tags, category: entry.category };
  };
  const escapes = whole.verdicts
    .filter((v) => !v.matchesExpected)
    .map((v) => residual(v.caseId))
    .filter((r): r is EvaluationResidual => r !== null && index.get(r.caseId)!.label === "malicious");
  const falsePositives = whole.verdicts
    .filter((v) => !v.matchesExpected)
    .map((v) => residual(v.caseId))
    .filter((r): r is EvaluationResidual => r !== null && index.get(r.caseId)!.label === "benign");

  const value: EvaluationRunSummary = {
    generatedAt: new Date().toISOString(),
    revision: gitRevision(),
    catalogSize: cases.length,
    suites,
    perf: runPerf({ cases, iterations: UI_PERF_ITERATIONS, deps, allProfile: profiles[7]! }),
    residuals: { escapes, falsePositives },
    limitations: [
      "Computed locally against the middleware's pure functions over command text — no model is called, no API key is used, and no request leaves the machine.",
      "UI path runs the pure decision-layer passes only: step-budget behavioral tests (real CodexRunner driven by a fake codex script, still no model) and the project's own test gate run in the CLI/CI suite (tests/), not here.",
      "The budget layer is a counter, not a classifier; its 100% escape figure means a single command never trips it.",
      "Catalog numbers are on an authored + escalated corpus, not an observed real-world bypass rate.",
    ],
  };
  cached = { at: Date.now(), value };
  return value;
}

function suiteName(profileId: string): string {
  switch (profileId) {
    case "none":
      return "baseline";
    case "all":
      return "regression";
    default:
      return profileId;
  }
}
