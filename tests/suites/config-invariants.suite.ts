/**
 * Config-invariants suite: the code-level guarantees the middleware relies on.
 *
 *   1. REVIEWABLE_RULES is exactly [network-egress-denied] (code, not config).
 *   2. loadConfig rejects POLICY_REVIEW_RULES naming a secret rule.
 *   3. guardedEvaluate fails CLOSED: a throwing evaluator denies the command
 *      rather than allowing it (a safety control that crashes must not
 *      become a bypass).
 */

import { CONFIG_PROFILE, DEFAULT_ENV } from "../lib/middleware.js";
import { runProfile } from "../lib/harness.js";
import { loadCatalog } from "../lib/catalog.js";
import type { SuiteModule } from "./suite.js";

export const CONFIG_INVARIANTS_SUITE: SuiteModule = {
  id: "config",
  name: "Config-invariants middleware",
  async run() {
    const cases = await loadCatalog();
    const result = runProfile({ profile: CONFIG_PROFILE, cases, env: DEFAULT_ENV });
    return { ...result, suite: "config" };
  },
};
