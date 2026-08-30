/**
 * CLI wiring — binds the provider-agnostic evaluation library to the REAL
 * middleware (the code under test) and to the platform's config/corpus.
 *
 * This is the only tests/-side module that imports the server sources; the
 * library itself (lib/) never does. The server app has its own equivalent
 * (apps/server/src/evaluation-deps.ts) for /api/pentest.
 */

import {
  evaluateCommand,
  guardedEvaluate,
  redactCommand,
  scanCommands,
  isReviewableRule,
  policyContextFrom,
  REVIEWABLE_RULES,
} from "../../apps/server/src/command-policy.js";
import { loadConfig } from "../../apps/server/src/config.js";
import {
  createProfiles,
  defaultEnv,
  type EvaluationDeps,
} from "./profiles.js";

/** The real middleware surface, injected into the library. */
export const EVALUATION_DEPS: EvaluationDeps = {
  evaluateCommand,
  guardedEvaluate,
  redactCommand,
  scanCommands,
  isReviewableRule,
  policyContextFrom,
  loadConfig,
  REVIEWABLE_RULES,
};

/** The full profile set wired to the real middleware (order: none, command-policy, redaction, budget, approval, monitor, config, all). */
const WIRED = createProfiles(EVALUATION_DEPS);
export const NONE_PROFILE = WIRED[0]!;
export const COMMAND_POLICY_PROFILE = WIRED[1]!;
export const REDACTION_PROFILE = WIRED[2]!;
export const BUDGET_PROFILE = WIRED[3]!;
export const APPROVAL_PROFILE = WIRED[4]!;
export const MONITOR_PROFILE = WIRED[5]!;
export const CONFIG_PROFILE = WIRED[6]!;
export const ALL_PROFILE = WIRED[7]!;

/** Default evaluation environment wired to the real middleware. */
export const DEFAULT_ENV = defaultEnv(EVALUATION_DEPS);

// Convenience re-export for CLI helpers.
export { wrapped } from "./profiles.js";
