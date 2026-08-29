/**
 * Replay runtime provider — `RUNTIME_PROVIDER=replay`.
 *
 * Streams a recorded Codex event stream through the enforcement path so the
 * governance loop can be demonstrated without a model, a key, or a network.
 *
 * WHAT IS REAL AND WHAT IS NOT. This matters more than the feature, and it is
 * stated here so nobody has to infer it from a demo:
 *
 *   FAKED - exactly one thing: the model. The bytes that would have come from
 *   the Codex CLI's stdout come from a fixture file instead.
 *
 *   REAL - the event parser (`parseCodexEventLine`, the same function the live
 *   runner uses), the policy engine (`scanCommands` over a `policyContextFrom`
 *   built from the same config fields, including the run-scoped
 *   `extraAllowedHosts` a human approval grants), the enforcement decision, the
 *   step budget, monitor-mode observation carrying, the error types, and
 *   everything downstream: `AgentService`'s status mapping, the store write, the
 *   audit trail, the approval record and the continuation run. None of that is
 *   modified or bypassed.
 *
 *   RE-IMPLEMENTED - the stream orchestration loop, about 25 lines: accumulate
 *   commands, scan the ones not yet scanned, arm the kill on the first denial,
 *   check the budget. That logic lives inside a closure in `codex-runner.ts` and
 *   cannot be imported, so it is written out again here. It is the one place
 *   this provider could drift from production, which is why
 *   `replay-runner.test.ts` asserts the two produce identical decisions over the
 *   same fixtures.
 *
 *   ABSENT - there is no container, so there is no container teardown and no
 *   process to kill. A replayed denial proves the decision and the audit trail;
 *   it does not prove containment. Containment is proven separately, by
 *   `bench:generate`'s token tier and `runner-policy.test.ts`, both of which
 *   spawn for real. Do not present replay as evidence of containment.
 */

import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  policyContextFrom,
  scanCommands,
  type DetectedViolation,
} from "./command-policy.js";
import type { AppConfig } from "./config.js";
import { emptyParsedEvents, parseCodexEventLine } from "./codex-runner.js";
import { BudgetExceededError, PolicyViolationError, RunCancelledError } from "./errors.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";

const here = path.dirname(fileURLToPath(import.meta.url));

export const DEFAULT_FIXTURE_DIRECTORY = path.join(here, "fixtures", "replay");

export interface ReplayFixture {
  name: string;
  /** Case-insensitive substrings; the first fixture matching the prompt wins. */
  match: string[];
  /** Raw Codex stdout lines, exactly as the CLI would emit them. */
  lines: string[];
  /** Provenance. Recorded fixtures say where from; synthesized ones say so. */
  source: string;
}

interface LoadedFixture extends ReplayFixture {
  file: string;
}

/**
 * Reads every `*.json` fixture in the directory.
 *
 * Fixtures are data, not code: adding a demo scenario is a file, not a change to
 * this class.
 */
export async function loadFixtures(directory = DEFAULT_FIXTURE_DIRECTORY): Promise<LoadedFixture[]> {
  const entries = await readdir(directory);
  const fixtures: LoadedFixture[] = [];
  for (const entry of entries.filter((name) => name.endsWith(".json")).sort()) {
    const raw = await readFile(path.join(directory, entry), "utf8");
    const parsed = JSON.parse(raw) as ReplayFixture;
    fixtures.push({ ...parsed, file: entry });
  }
  return fixtures;
}

/** First fixture whose `match` list hits the prompt; otherwise the fallback. */
export function selectFixture(
  fixtures: readonly LoadedFixture[],
  prompt: string,
): LoadedFixture | undefined {
  const haystack = prompt.toLowerCase();
  return (
    fixtures.find((fixture) =>
      fixture.match.some((needle) => haystack.includes(needle.toLowerCase())),
    ) ?? fixtures.find((fixture) => fixture.match.length === 0)
  );
}

export class ReplayRunner implements AgentRunner {
  private readonly cancelled = new Set<string>();
  private fixtures: LoadedFixture[] | null = null;

  constructor(
    private readonly config: AppConfig,
    private readonly fixtureDirectory = DEFAULT_FIXTURE_DIRECTORY,
  ) {}

  /** Always available: that is the entire point of this provider. */
  async isAvailable(): Promise<boolean> {
    try {
      return (await this.load()).length > 0;
    } catch {
      return false;
    }
  }

  async cancel(agentId: string): Promise<boolean> {
    this.cancelled.add(agentId);
    return true;
  }

  private async load(): Promise<LoadedFixture[]> {
    if (!this.fixtures) this.fixtures = await loadFixtures(this.fixtureDirectory);
    return this.fixtures;
  }

  async run(request: RunnerRequest): Promise<RunnerResult> {
    const fixtures = await this.load();
    const fixture = selectFixture(fixtures, request.prompt);
    if (!fixture) {
      throw new Error(
        "No replay fixture matches this prompt. Available: " +
          fixtures.map((entry) => entry.name).join(", "),
      );
    }

    // Identical construction to CodexRunner: same config fields, same
    // run-scoped grant, same secret redaction list.
    const parsed = emptyParsedEvents(request.threadId);
    const policyContext = policyContextFrom(
      this.config.arkBaseUrl,
      [...this.config.policyAllowedHosts, ...(request.extraAllowedHosts ?? [])],
      [this.config.arkApiKey],
    );

    const observations: DetectedViolation[] = [];
    let violation: DetectedViolation | null = null;
    let budgetExceeded = false;
    let scannedCommands = 0;

    // The re-implemented orchestration loop. Mirrors applyPolicy() in
    // codex-runner.ts line for line, including the ordering that matters: the
    // budget is enforced regardless of monitor mode, and only the FIRST denial
    // arms the kill while every denial is still recorded as evidence.
    const applyPolicy = (): void => {
      const found = scanCommands(parsed.commands, scannedCommands, policyContext);
      scannedCommands = parsed.commands.length;
      if (!budgetExceeded && parsed.commands.length > this.config.policyMaxCommands) {
        budgetExceeded = true;
      }
      for (const detected of found) observations.push(detected);
      if (found.length > 0 && !violation) violation = found[0]!;
    };

    try {
      for (const line of fixture.lines) {
        if (this.cancelled.has(request.agentId)) throw new RunCancelledError();
        parseCodexEventLine(line, parsed);
        applyPolicy();
        // In enforce mode the live runner kills the Runtime here and stops
        // reading. Stopping the replay at the same point keeps the recorded
        // evidence identical to what a real denial would have produced: events
        // after the kill never reach the store.
        if (violation && this.config.policyEnforcement === "enforce") break;
      }
      applyPolicy();

      if (this.cancelled.has(request.agentId)) throw new RunCancelledError();
      if (violation && this.config.policyEnforcement === "enforce") {
        const denial: DetectedViolation = violation;
        throw new PolicyViolationError(
          denial.rule,
          denial.command,
          denial.detail,
          denial.hosts ?? [],
        );
      }
      if (budgetExceeded) {
        throw new BudgetExceededError(this.config.policyMaxCommands, parsed.commands.length);
      }
      const output = parsed.messages.at(-1)?.trim();
      if (!output) throw new Error("Replay fixture produced no agent message");
      return { output, threadId: parsed.threadId, usage: parsed.usage, violations: observations };
    } catch (error) {
      // Same contract as the live runner: monitor-mode near-misses survive the
      // failure path so AgentService can still record them.
      (error as { observations?: DetectedViolation[] }).observations = observations;
      throw error;
    } finally {
      this.cancelled.delete(request.agentId);
    }
  }
}
