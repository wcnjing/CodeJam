/**
 * Command-policy suite: the policy engine alone (evaluateCommand +
 * guardedEvaluate), the middleware that actually classifies commands.
 */

import { COMMAND_POLICY_PROFILE, DEFAULT_ENV } from "../../apps/server/src/pentest/profiles.js";
import { runProfile } from "../../apps/server/src/pentest/harness.js";
import { loadCatalog } from "../../apps/server/src/pentest/catalog.js";
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
