/**
 * Performance suite: operational cost of each middleware (AGENTS.md).
 *
 * Produces a PerfReport, not a pass/fail SuiteResult — operators care about
 * microseconds per decision, throughput of the scan path, and redaction cost.
 */

import { runPerf } from "../lib/perf.js";
import { loadCatalog } from "../lib/catalog.js";
import { renderPerf } from "../lib/report.js";
import { ALL_PROFILE, DEFAULT_ENV, PENTEST_DEPS } from "../lib/wiring.js";
import type { PerfReport } from "../lib/types.js";

export interface PerfSuiteResult {
  report: PerfReport;
  rendered: string;
}

export async function runPerfSuite(): Promise<PerfSuiteResult> {
  const cases = await loadCatalog();
  const report = runPerf({
    cases,
    iterations: 300,
    deps: PENTEST_DEPS,
    allProfile: ALL_PROFILE,
    env: DEFAULT_ENV,
  });
  return { report, rendered: renderPerf(report) };
}
