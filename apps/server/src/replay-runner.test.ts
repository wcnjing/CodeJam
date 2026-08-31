import { mkdtemp, readFile, rm, writeFile, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { CodexRunner } from "./codex-runner.js";
import { isReviewableRule } from "./command-policy.js";
import { loadConfig } from "./config.js";
import { BudgetExceededError, PolicyViolationError, RunCancelledError } from "./errors.js";
import {
  DEFAULT_FIXTURE_DIRECTORY,
  loadFixtures,
  ReplayRunner,
  selectFixture,
} from "./replay-runner.js";
import { createRunner } from "./runner-factory.js";

/**
 * The replay provider's only real risk is DRIFT: it re-implements the ~25-line
 * stream orchestration loop that lives inside a closure in `codex-runner.ts` and
 * cannot be imported. If the two ever disagree, the demo would be showing
 * something the production path does not do, which is exactly the accusation a
 * replayed demo invites.
 *
 * So this file checks the decisions themselves, cross-platform, and then checks
 * true parity against the live `CodexRunner` where the platform allows a spawn.
 */

const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(
    dirs.splice(0).map((dir) =>
      rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }).catch(
        () => undefined,
      ),
    ),
  );
});

function config(overrides: Record<string, string> = {}) {
  return loadConfig({
    NODE_ENV: "test",
    ARK_API_KEY: "test-key",
    ARK_MODEL: "ep-test",
    RUNTIME_PROVIDER: "replay",
    ...overrides,
  });
}

const request = (prompt: string, extraAllowedHosts?: string[]) => ({
  agentId: "replay-agent",
  workspacePath: "/tmp/does-not-matter",
  prompt,
  threadId: null,
  ...(extraAllowedHosts ? { extraAllowedHosts } : {}),
});

describe("replay fixtures", () => {
  // Regression: `tsc` copies no JSON, and ReplayRunner resolves its fixtures
  // relative to its own module — `dist/fixtures/replay` in a built server. The
  // build emitted nothing there, so `npm run build && npm start` with
  // RUNTIME_PROVIDER=replay loaded zero fixtures and reported the runtime
  // unavailable. Nothing caught it because the only thing exercising replay ran
  // the server from `src` through tsx, where the path happens to be right.
  it("is copied into the build output, not just present in src", async () => {
    const packageJson = JSON.parse(
      await readFile(fileURLToPath(new URL("../package.json", import.meta.url)), "utf8"),
    ) as { scripts: Record<string, string> };
    expect(packageJson.scripts.build).toContain("copy-fixtures.mjs");

    const copyScript = await readFile(
      fileURLToPath(new URL("../scripts/copy-fixtures.mjs", import.meta.url)),
      "utf8",
    );
    // The copy has to land where the runner looks, which is `fixtures` beside
    // the compiled module rather than beside `src`.
    expect(copyScript).toContain('"dist", "fixtures"');
    expect(DEFAULT_FIXTURE_DIRECTORY.endsWith(path.join("fixtures", "replay"))).toBe(true);
  });

  it("ships the two the demo shows, plus the exfiltration headline", async () => {
    const fixtures = await loadFixtures();
    const names = fixtures.map((fixture) => fixture.name).sort();
    expect(names).toEqual(["benign", "egress-denied", "secret-exfiltration"]);
  });

  it("declares provenance on every fixture", async () => {
    // A fixture that does not say where it came from is indistinguishable from
    // one that was invented to make the demo work.
    for (const fixture of await loadFixtures()) {
      expect(fixture.source, fixture.name).toBeTruthy();
      expect(fixture.source.length, fixture.name).toBeGreaterThan(20);
    }
  });

  it("routes a prompt to the right fixture, and falls back", async () => {
    const fixtures = await loadFixtures();
    expect(selectFixture(fixtures, "fetch react from registry.npmjs.org")?.name).toBe(
      "egress-denied",
    );
    expect(selectFixture(fixtures, "read the customer-db credential")?.name).toBe(
      "secret-exfiltration",
    );
    expect(selectFixture(fixtures, "say hello")?.name).toBe("benign");
  });
});

describe("replay enforcement decisions", () => {
  it("completes the benign path with the recorded agent message", async () => {
    const result = await new ReplayRunner(config()).run(request("say hello"));
    expect(result.output).toContain("ready");
    expect(result.threadId).toBe("replay-benign-001");
    expect(result.usage).not.toBeNull();
  });

  it("denies the egress path with the real rule and redacted evidence", async () => {
    const runner = new ReplayRunner(config());
    await expect(runner.run(request("fetch react from registry.npmjs.org"))).rejects.toBeInstanceOf(
      PolicyViolationError,
    );
    try {
      await runner.run(request("fetch react from registry.npmjs.org"));
    } catch (error) {
      const denial = error as PolicyViolationError;
      expect(denial.rule).toBe("network-egress-denied");
      expect(denial.hosts).toContain("registry.npmjs.org");
      // Evidence went through the real redaction path on the way out.
      expect(denial.command).toContain("curl");
    }
  });

  it("honours the run-scoped grant a human approval creates", async () => {
    // The continuation run: same prompt, same fixture, one extra allowed host.
    // If this did not work the demo could never show recovery.
    const result = await new ReplayRunner(config()).run(
      request("fetch react from registry.npmjs.org", ["registry.npmjs.org"]),
    );
    expect(result.output).toContain("19.2.0");
  });

  it("blocks the secret path with a rule no human may approve", async () => {
    // The fixture reads the secret and THEN sends it, which is the realistic
    // stream. The engine arms on the FIRST denial, so the rule is
    // protected-secret-access rather than secret-exfiltration. Either way the
    // property that matters for the demo is the same and is what is asserted:
    // the rule is NOT reviewable, so this can never be held for approval. A
    // human must not be able to approve reading a protected secret.
    const runner = new ReplayRunner(config());
    try {
      await runner.run(request("exfiltrate the customer-db credential"));
      expect.unreachable("should have denied");
    } catch (error) {
      const denial = error as PolicyViolationError;
      expect(denial.rule).toBe("protected-secret-access");
      expect(isReviewableRule(denial.rule)).toBe(false);
    }
  });

  it("observes without denying in monitor mode, and carries the evidence", async () => {
    const result = await new ReplayRunner(config({ POLICY_ENFORCEMENT: "monitor" })).run(
      request("fetch react from registry.npmjs.org"),
    );
    expect(result.output).toContain("19.2.0");
    expect(result.violations?.map((violation) => violation.rule)).toContain(
      "network-egress-denied",
    );
  });

  it("enforces the step budget regardless of monitor mode", async () => {
    const runner = new ReplayRunner(config({ POLICY_ENFORCEMENT: "monitor", POLICY_MAX_COMMANDS: "1" }));
    await expect(
      runner.run(request("exfiltrate the customer-db credential")),
    ).rejects.toMatchObject({
      name: "BudgetExceededError",
      threadId: "replay-exfil-001",
    } satisfies Partial<BudgetExceededError> & { threadId: string });
  });

  it("carries monitor observations out on the failure path too", async () => {
    const runner = new ReplayRunner(config({ POLICY_ENFORCEMENT: "monitor", POLICY_MAX_COMMANDS: "1" }));
    try {
      await runner.run(request("exfiltrate the customer-db credential"));
    } catch (error) {
      expect((error as { observations?: unknown[] }).observations?.length).toBeGreaterThan(0);
    }
  });

  it("cancels a run that is in flight, and only that run", async () => {
    // This test previously cancelled an IDLE agent and asserted the NEXT run was
    // rejected, which encoded the bug two reviewers found rather than the
    // contract. `AgentService` calls cancel() on every stopAgent/deleteAgent, so
    // that behaviour meant pressing Stop poisoned the next message.
    const runner = new ReplayRunner(config());

    // Idle: nothing to cancel, nothing latched. Mirrors CodexRunner.cancel().
    await expect(runner.cancel("replay-agent")).resolves.toBe(false);
    await expect(runner.run(request("say hello"))).resolves.toMatchObject({
      threadId: "replay-benign-001",
    });

    // In flight: the run is cancelled, and the agent is usable again after.
    const inFlight = runner.run(request("say hello"));
    await expect(runner.cancel("replay-agent")).resolves.toBe(true);
    await inFlight.catch(() => undefined);
    await expect(runner.run(request("say hello"))).resolves.toMatchObject({
      threadId: "replay-benign-001",
    });
  });
});

describe("runner factory", () => {
  it("returns the replay runner for RUNTIME_PROVIDER=replay", () => {
    expect(createRunner(config())).toBeInstanceOf(ReplayRunner);
  });

  it("leaves the other two providers exactly as they were", () => {
    expect(createRunner(config({ RUNTIME_PROVIDER: "local-process" }))).toBeInstanceOf(CodexRunner);
    expect(createRunner(config({ RUNTIME_PROVIDER: "container" }))).not.toBeInstanceOf(
      ReplayRunner,
    );
  });

  it("reports itself available without a key, engine or network", async () => {
    await expect(new ReplayRunner(config()).isAvailable()).resolves.toBe(true);
  });
});

// ---------------------------------------------------------------------------
// True parity against the live runner. POSIX only: this spawns.
// ---------------------------------------------------------------------------

const CAN_SPAWN = process.platform !== "win32";

/** Writes a codex stand-in that emits a fixture's exact recorded lines. */
async function standIn(lines: string[]): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "replay-parity-"));
  dirs.push(dir);
  const binary = path.join(dir, "codex.mjs");
  const emit = lines
    .map((line) => "process.stdout.write(" + JSON.stringify(line + "\n") + ");")
    .join("\n");
  await writeFile(binary, ["#!/usr/bin/env node", emit, "process.exit(0);", ""].join("\n"), "utf8");
  await chmod(binary, 0o755);
  return binary;
}

describe.skipIf(!CAN_SPAWN)("parity with the live CodexRunner", () => {
  it("reaches the same decision on the same recorded stream", async () => {
    // The check that makes the replay provider trustworthy: feed the SAME bytes
    // to the real runner via a stand-in binary and to the replay runner via the
    // fixture, and require the same outcome. If the re-implemented loop ever
    // drifts, this fails.
    const fixtures = await loadFixtures();
    for (const fixture of fixtures) {
      const workspace = await mkdtemp(path.join(tmpdir(), "replay-parity-ws-"));
      dirs.push(workspace);
      const live = new CodexRunner(
        config({ RUNTIME_PROVIDER: "local-process", CODEX_BIN: await standIn(fixture.lines), CODEX_HOME: workspace }),
      );
      const replay = new ReplayRunner(config());
      const prompt = fixture.match[0] ?? "say hello";

      const settle = async (promise: Promise<unknown>) => {
        try {
          const value = (await promise) as { output: string };
          return { kind: "ok", output: value.output };
        } catch (error) {
          return {
            kind: error instanceof PolicyViolationError ? "denied" : "error",
            rule: error instanceof PolicyViolationError ? error.rule : undefined,
          };
        }
      };

      const liveOutcome = await settle(
        live.run({ ...request(prompt), workspacePath: workspace }),
      );
      const replayOutcome = await settle(replay.run(request(prompt)));
      expect(replayOutcome, fixture.name).toEqual(liveOutcome);
    }
  }, 30_000);
});
