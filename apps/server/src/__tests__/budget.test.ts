import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { CodexRunner } from "../runners/codex-runner.js";
import { loadConfig } from "../core/config.js";
import { BudgetExceededError } from "../core/errors.js";

/**
 * @covers TM-AGENT-004
 * Step-budget enforcement: a runaway turn is killed by the platform, not left
 * to the agent or the wall-clock timeout.
 */

const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

/** Emits `count` benign command_execution events, then lingers so the test
 *  proves the kill rather than a natural exit. */
async function fakeCodex(count: number, linger: boolean): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "budget-codex-"));
  dirs.push(dir);
  const bin = path.join(dir, "codex.mjs");
  const lines: string[] = [
    `process.stdout.write(${JSON.stringify(JSON.stringify({ type: "thread.started", thread_id: "t1" }) + "\n")});`,
  ];
  for (let i = 0; i < count; i += 1) {
    const ev = {
      type: "item.started",
      item: { id: "c" + i, type: "command_execution", command: "echo " + i },
    };
    lines.push(`process.stdout.write(${JSON.stringify(JSON.stringify(ev) + "\n")});`);
  }
  const msg = { type: "item.completed", item: { type: "agent_message", text: "done" } };
  lines.push(`process.stdout.write(${JSON.stringify(JSON.stringify(msg) + "\n")});`);
  lines.push(linger ? "setTimeout(() => process.exit(0), 30000);" : "process.exit(0);");
  await writeFile(bin, ["#!/usr/bin/env node", ...lines, ""].join("\n"), "utf8");
  await chmod(bin, 0o755);
  return bin;
}

async function runner(bin: string, maxCommands: number) {
  const ws = await mkdtemp(path.join(tmpdir(), "budget-ws-"));
  dirs.push(ws);
  const config = loadConfig({
    NODE_ENV: "test",
    CODEX_BIN: bin,
    CODEX_HOME: ws,
    ARK_API_KEY: "k",
    ARK_MODEL: "ep-test",
    POLICY_MAX_COMMANDS: String(maxCommands),
  });
  return { runner: new CodexRunner(config), ws };
}

describe("step budget", () => {
  it("terminates a run that exceeds the command budget", async () => {
    const bin = await fakeCodex(12, true);
    const { runner: r, ws } = await runner(bin, 5);
    await expect(
      r.run({ agentId: "a", workspacePath: ws, prompt: "loop", threadId: null }),
    ).rejects.toBeInstanceOf(BudgetExceededError);
  }, 15_000);

  it("allows a run that stays within budget", async () => {
    const bin = await fakeCodex(3, false);
    const { runner: r, ws } = await runner(bin, 5);
    const result = await r.run({ agentId: "b", workspacePath: ws, prompt: "ok", threadId: null });
    expect(result.output).toBe("done");
  }, 15_000);
});
