/**
 * Suite definition contract. Each suite returns a SuiteResult the runner
 * persists into tests/scores/.
 */

import type { SuiteResult } from "../lib/types.js";

export interface SuiteModule {
  id: string;
  name: string;
  run(): Promise<SuiteResult>;
}

/** Merge an extra scorecard line into a suite result for reporting. */
export function annotate(result: SuiteResult, extra: Partial<SuiteResult["totals"]>): SuiteResult {
  return { ...result, totals: { ...result.totals, ...extra } };
}
