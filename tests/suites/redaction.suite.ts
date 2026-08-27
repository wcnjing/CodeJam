/**
 * Redaction suite: evidence sanitisation. Every denied command is recorded as
 * evidence; a leak would publish the very secret the control protects. The
 * profile passes a case when no protected material survives redaction.
 */

import { REDACTION_PROFILE, DEFAULT_ENV } from "../lib/middleware.js";
import { runProfile } from "../lib/harness.js";
import { loadCatalog } from "../lib/catalog.js";
import type { SuiteModule } from "./suite.js";

export const REDACTION_SUITE: SuiteModule = {
  id: "redaction",
  name: "Evidence redaction middleware",
  async run() {
    const cases = await loadCatalog();
    const result = runProfile({ profile: REDACTION_PROFILE, cases, env: DEFAULT_ENV });
    return { ...result, suite: "redaction" };
  },
};
