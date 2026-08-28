/**
 * Performance suite: operational cost of each middleware (AGENTS.md).
 *
 * Produces a PerfReport, not a pass/fail SuiteResult — operators care about
 * microseconds per decision, throughput of the scan path, and redaction cost.
 */

import { runPerf } from "../../apps/server/src/pentest/perf.js";
import { loadCatalog } from "../../apps/server/src/pentest/catalog.js";
import { renderPerf } from "../lib/report.js";
import type { PerfReport } from "../../apps/server/src/pentest/types.js";

export interface PerfSuiteResult {
  report: PerfReport;
  rendered: string;
}

export async function runPerfSuite(): Promise<PerfSuiteResult> {
  const cases = await loadCatalog();
  const report = runPerf({ cases, iterations: 300 });
  return { report, rendered: renderPerf(report) };
}
