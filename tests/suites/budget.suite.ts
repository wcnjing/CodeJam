/**
 * Step-budget suite: the runaway-execution control.
 *
 * Two halves:
 *   1. Catalog pass through the budget layer — a single-command run must
 *      never trip the budget (it is a counter, not a classifier).
 *   2. Behavioral tests against the REAL CodexRunner with a fake codex
 *      binary (the project's own test technique):
 *        - a run emitting more commands than POLICY_MAX_COMMANDS is killed
 *          with BudgetExceededError;
 *        - a run within budget completes normally;
 *        - the budget is enforced in monitor mode too (always-on invariant,
 *          TM-AGENT-004).
 */

import { CodexRunner } from "../../apps/server/src/codex-runner.js";
import { loadConfig } from "../../apps/server/src/config.js";
import { BudgetExceededError } from "../../apps/server/src/errors.js";
import { BUDGET_PROFILE, DEFAULT_ENV } from "../lib/middleware.js";
import { runProfile } from "../lib/harness.js";
import { loadCatalog } from "../lib/catalog.js";
import { FakeCodex, makeWorkspace } from "../lib/fake-codex.js";
import type { CaseVerdict } from "../lib/types.js";
import type { SuiteModule } from "./suite.js";

async function runnerWith(bin: string, workspace: string, maxCommands: number, enforcement: "enforce" | "monitor") {
  const config = loadConfig({
    NODE_ENV: "test",
    CODEX_BIN: bin,
    CODEX_HOME: workspace,
    ARK_API_KEY: "k",
    ARK_MODEL: "ep-test",
    POLICY_MAX_COMMANDS: String(maxCommands),
    POLICY_ENFORCEMENT: enforcement,
  });
  return new CodexRunner(config);
}

export const BUDGET_SUITE: SuiteModule = {
  id: "budget",
  name: "Step-budget middleware",
  async run() {
    const cases = await loadCatalog();
    const result = runProfile({ profile: BUDGET_PROFILE, cases, env: DEFAULT_ENV });

    const extraVerdicts: CaseVerdict[] = [];
    const ws = await makeWorkspace();
    const fake = new FakeCodex(ws.dir);
    try {
      // 1. Over budget -> terminated (BudgetExceededError).
      {
        const bin = await fake.write({ commands: Array.from({ length: 12 }, (_, i) => "echo " + i), linger: true });
        const runner = await runnerWith(bin, ws.dir, 5, "enforce");
        try {
          await runner.run({ agentId: "a", workspacePath: ws.dir, prompt: "loop", threadId: null });
          extraVerdicts.push({ caseId: "budget-behavior-over-budget", decision: "allow", rule: null, matchesExpected: false, note: "over-budget run was NOT terminated" });
        } catch (error) {
          const ok = error instanceof BudgetExceededError;
          extraVerdicts.push({ caseId: "budget-behavior-over-budget", decision: ok ? "deny" : "allow", rule: "step-budget-exceeded", matchesExpected: ok, note: ok ? "BudgetExceededError raised" : String(error) });
        }
      }
      // 2. Within budget -> completes.
      {
        const bin = await fake.write({ commands: ["echo 1", "echo 2", "echo 3"] });
        const runner = await runnerWith(bin, ws.dir, 5, "enforce");
        try {
          const out = await runner.run({ agentId: "b", workspacePath: ws.dir, prompt: "ok", threadId: null });
          extraVerdicts.push({ caseId: "budget-behavior-within-budget", decision: "allow", rule: null, matchesExpected: out.output === "done", note: "completed normally" });
        } catch (error) {
          extraVerdicts.push({ caseId: "budget-behavior-within-budget", decision: "deny", rule: null, matchesExpected: false, note: "within-budget run failed: " + String(error) });
        }
      }
      // 3. Monitor mode does NOT disable the budget (always-on invariant).
      {
        const bin = await fake.write({ commands: Array.from({ length: 12 }, (_, i) => "echo " + i), linger: true });
        const runner = await runnerWith(bin, ws.dir, 5, "monitor");
        try {
          await runner.run({ agentId: "c", workspacePath: ws.dir, prompt: "loop", threadId: null });
          extraVerdicts.push({ caseId: "budget-behavior-monitor-always-on", decision: "allow", rule: null, matchesExpected: false, note: "budget NOT enforced in monitor mode" });
        } catch (error) {
          const ok = error instanceof BudgetExceededError;
          extraVerdicts.push({ caseId: "budget-behavior-monitor-always-on", decision: ok ? "deny" : "allow", rule: "step-budget-exceeded", matchesExpected: ok, note: ok ? "budget enforced in monitor mode" : String(error) });
        }
      }
    } finally {
      await fake.cleanup();
      await ws.cleanup();
    }

    const verdicts = [...result.verdicts, ...extraVerdicts];
    const passed = verdicts.filter((v) => v.matchesExpected).length;
    return {
      ...result,
      suite: "budget",
      verdicts,
      totals: { ...result.totals, cases: verdicts.length, passed, failed: verdicts.length - passed },
    };
  },
};
