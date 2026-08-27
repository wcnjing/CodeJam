/**
 * Fake `codex` binary for driving the REAL CodexRunner end-to-end, the same
 * technique the project's own budget/runner tests use. This is what lets the
 * suite test the step-budget and monitor-mode middleware as they really run,
 * not as reimplementations.
 */

import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

export interface FakeCodexOptions {
  /** Commands the fake reports via item.started events. */
  commands: string[];
  /** After the command stream, linger so a kill is observable. */
  linger?: boolean;
  /** Optional extra stdout events (JSON lines) before the stream. */
  preamble?: string[];
}

export class FakeCodex {
  readonly bin: string;
  private dirs: string[] = [];

  constructor(private readonly workspace: string) {
    this.bin = path.join(this.workspace, "codex.mjs");
  }

  async write(options: FakeCodexOptions): Promise<string> {
    const dir = await mkdtemp(path.join(tmpdir(), "suite-codex-"));
    this.dirs.push(dir);
    const bin = path.join(dir, "codex.mjs");
    const lines: string[] = [
      `process.stdout.write(${JSON.stringify(
        JSON.stringify({ type: "thread.started", thread_id: "t1" }) + "\n",
      )});`,
      ...(options.preamble ?? []),
    ];
    options.commands.forEach((command, i) => {
      const ev = {
        type: "item.started",
        item: { id: "c" + i, type: "command_execution", command },
      };
      lines.push(`process.stdout.write(${JSON.stringify(JSON.stringify(ev) + "\n")});`);
    });
    const msg = { type: "item.completed", item: { type: "agent_message", text: "done" } };
    lines.push(`process.stdout.write(${JSON.stringify(JSON.stringify(msg) + "\n")});`);
    lines.push(options.linger ? "setTimeout(() => process.exit(0), 30000);" : "process.exit(0);");
    await writeFile(bin, ["#!/usr/bin/env node", ...lines, ""].join("\n"), "utf8");
    await chmod(bin, 0o755);
    return bin;
  }

  async cleanup(): Promise<void> {
    await Promise.all(this.dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
  }
}

/** A throwaway workspace directory, removed on cleanup. */
export async function makeWorkspace(): Promise<{ dir: string; cleanup: () => Promise<void> }> {
  const dir = await mkdtemp(path.join(tmpdir(), "suite-ws-"));
  return {
    dir,
    cleanup: () => rm(dir, { recursive: true, force: true }),
  };
}
