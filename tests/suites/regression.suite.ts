/**
 * Regression suite: the middleware AS A WHOLE.
 *
 * AGENTS.md: "ensure to test the middleware individually and as a whole
 * (regression tests) for the test cases". This is the whole-stack pass:
 * every case runs through the chained layers exactly as the platform wires
 * them (policy -> fail-closed -> approval classification -> redaction ->
 * budget), and the project's own unit/integration suite is run as an
 * additional gate so a regression in the runtime wiring fails this suite too.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ALL_PROFILE, DEFAULT_ENV } from "../../apps/server/src/pentest/profiles.js";
import { runProfile } from "../../apps/server/src/pentest/harness.js";
import { loadCatalog } from "../../apps/server/src/pentest/catalog.js";
import type { CaseVerdict } from "../../apps/server/src/pentest/types.js";
import type { SuiteModule } from "./suite.js";

const execFileAsync = promisify(execFile);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

export const REGRESSION_SUITE: SuiteModule = {
  id: "regression",
  name: "Whole stack (regression)",
  async run() {
    const cases = await loadCatalog();
    const result = runProfile({ profile: ALL_PROFILE, cases, env: DEFAULT_ENV });

    // Gate: the project's own tests must still pass against the code under
    // test. This covers runner wiring, store, approvals, budget and threat
    // coverage that pure catalog passes cannot reach.
    let gate: CaseVerdict;
    try {
      await execFileAsync("npm", ["test", "-w", "@launchpad/server", "--", "--reporter=dot"], {
        cwd: ROOT,
        timeout: 300_000,
        env: { ...process.env, CI: "1" },
      });
      gate = {
        caseId: "regression-gate-server-tests",
        decision: "allow",
        rule: null,
        matchesExpected: true,
        note: "npm test -w @launchpad/server passed",
      };
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      gate = {
        caseId: "regression-gate-server-tests",
        decision: "deny",
        rule: "regression-gate",
        matchesExpected: false,
        note: "server test suite failed: " + detail.slice(0, 300),
      };
    }

    const verdicts = [...result.verdicts, gate];
    const passed = verdicts.filter((v) => v.matchesExpected).length;
    return {
      ...result,
      suite: "regression",
      verdicts,
      totals: { ...result.totals, cases: verdicts.length, passed, failed: verdicts.length - passed },
    };
  },
};
