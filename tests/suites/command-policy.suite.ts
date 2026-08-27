/**
 * Command-policy suite: the policy engine alone (evaluateCommand +
 * guardedEvaluate), the middleware that actually classifies commands.
 */

import { COMMAND_POLICY_PROFILE, DEFAULT_ENV } from "../lib/middleware.js";
import { runProfile } from "../lib/harness.js";
import { loadCatalog } from "../lib/catalog.js";
import type { SuiteModule } from "./suite.js";

export const COMMAND_POLICY_SUITE: SuiteModule = {
  id: "command-policy",
  name: "Command policy middleware",
  async run() {
    const cases = await loadCatalog();
    const result = runProfile({ profile: COMMAND_POLICY_PROFILE, cases, env: DEFAULT_ENV });
    return { ...result, suite: "command-policy" };
  },
};
