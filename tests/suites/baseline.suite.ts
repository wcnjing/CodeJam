/**
 * Baseline suite: the provided code with NO middleware.
 *
 * This is the score AGENTS.md asks for first ("test the baseline, get a
 * baseline score for the provided code"). It models the starter-kit runtime
 * before Sentinel: every command proceeds. Against the same catalog the
 * protected stack is scored, so the two numbers are directly comparable.
 */

import { NONE_PROFILE, DEFAULT_ENV } from "../../apps/server/src/pentest/profiles.js";
import { runProfile } from "../../apps/server/src/pentest/harness.js";
import { loadCatalog } from "../../apps/server/src/pentest/catalog.js";
import type { SuiteModule } from "./suite.js";

export const BASELINE_SUITE: SuiteModule = {
  id: "baseline",
  name: "Baseline (no middleware)",
  async run() {
    const cases = await loadCatalog();
    const result = runProfile({ profile: NONE_PROFILE, cases, env: DEFAULT_ENV });
    return { ...result, suite: "baseline" };
  },
};
