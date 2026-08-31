/**
 * Server-side wiring for the evaluation library.
 *
 * Binds the provider-agnostic library (@sentinel/evaluation) to the REAL
 * middleware running in this process, so /api/pentest measures exactly the
 * code that enforces. The CLI has its own equivalent (tests/lib/wiring.ts).
 */

import {
  evaluateCommand,
  guardedEvaluate,
  redactCommand,
  scanCommands,
  isReviewableRule,
  policyContextFrom,
  REVIEWABLE_RULES,
} from "./command-policy.js";
import { loadConfig } from "./config.js";
import type { EvaluationDeps } from "@sentinel/evaluation";

export const evaluationDeps: EvaluationDeps = {
  evaluateCommand,
  guardedEvaluate,
  redactCommand,
  scanCommands,
  isReviewableRule,
  policyContextFrom,
  loadConfig,
  REVIEWABLE_RULES,
};
