import { lstat, mkdir, mkdtemp, readFile, readlink, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { safeWriteFile } from "./safe-write.js";
import { WorkspaceManager } from "./workspace.js";
import type { Agent } from "./types.js";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((r) => rm(r, { recursive: true, force: true })));
});

async function sandbox() {
  const root = await mkdtemp(path.join(tmpdir(), "safe-write-"));
  roots.push(root);
  const workspace = path.join(root, "workspace");
  await mkdir(workspace, { recursive: true });
  // Something the host owns that the Agent must never reach — stands in for
  // .data/launchpad.json, the audit store.
  const outside = path.join(root, "audit-store.json");
  await writeFile(outside, "REAL AUDIT EVIDENCE\n", "utf8");
  return { root, workspace, outside };
}

describe("safeWriteFile", () => {
  it("writes normally when nothing is planted", async () => {
    const { workspace } = await sandbox();
    const target = path.join(workspace, "AGENTS.md");
    await safeWriteFile(workspace, target, "hello\n");
    expect(await readFile(target, "utf8")).toBe("hello\n");
  });

  it("refuses a symlink planted at the destination", async () => {
    const { workspace, outside } = await sandbox();
    const target = path.join(workspace, "AGENTS.md");
    await symlink(outside, target);

    await expect(safeWriteFile(workspace, target, "PAYLOAD\n")).rejects.toThrow(
      /non-regular file/i,
    );
    // The host-owned file is untouched and the link itself still a link:
    // nothing was written through it, and nothing replaced it either.
    expect(await readFile(outside, "utf8")).toBe("REAL AUDIT EVIDENCE\n");
    expect((await lstat(target)).isSymbolicLink()).toBe(true);
    expect(await readlink(target)).toBe(outside);
  });

  it("refuses a symlinked intermediate directory", async () => {
    const { root, workspace } = await sandbox();
    const escape = path.join(root, "elsewhere");
    await mkdir(escape, { recursive: true });
    await symlink(escape, path.join(workspace, ".secrets"));

    await expect(
      safeWriteFile(workspace, path.join(workspace, ".secrets", "customer-db-url.txt"), "x"),
    ).rejects.toThrow(/outside the workspace root/i);
    await expect(readFile(path.join(escape, "customer-db-url.txt"), "utf8")).rejects.toThrow();
  });

  it("refuses a path that climbs out with ..", async () => {
    const { workspace, outside } = await sandbox();
    await expect(
      safeWriteFile(workspace, path.join(workspace, "..", "audit-store.json"), "PAYLOAD\n"),
    ).rejects.toThrow(/outside the workspace root/i);
    expect(await readFile(outside, "utf8")).toBe("REAL AUDIT EVIDENCE\n");
  });

  it("refuses a directory or FIFO squatting on the destination", async () => {
    const { workspace } = await sandbox();
    const target = path.join(workspace, "AGENTS.md");
    await mkdir(target);
    await expect(safeWriteFile(workspace, target, "x")).rejects.toThrow(/non-regular file/i);
  });

  it("replaces an existing regular file atomically and leaves no temp behind", async () => {
    const { workspace } = await sandbox();
    const target = path.join(workspace, "AGENTS.md");
    await writeFile(target, "old\n", "utf8");
    await safeWriteFile(workspace, target, "new\n");
    expect(await readFile(target, "utf8")).toBe("new\n");

    const { readdir } = await import("node:fs/promises");
    expect((await readdir(workspace)).filter((n) => n.startsWith(".safe-write-"))).toEqual([]);
  });

  it("honours an explicit mode for the protected fixture", async () => {
    const { workspace } = await sandbox();
    const target = path.join(workspace, "secret.txt");
    await safeWriteFile(workspace, target, "s\n", { mode: 0o600 });
    expect((await lstat(target)).mode & 0o777).toBe(0o600);
  });
});

// @covers TM-AGENT-008
describe("workspace writes cannot be redirected by the Agent", () => {
  it("refuses to rewrite AGENTS.md through an Agent-planted symlink", async () => {
    // The reproduction that motivated safe-write.ts: the Agent replaces
    // AGENTS.md with a link to the audit store, then the operator edits the
    // Agent and PATCH /api/agents/:id calls writeInstructions().
    const { root, workspace, outside } = await sandbox();
    const manager = new WorkspaceManager(workspace);
    await manager.initialize();

    const agent = {
      id: "agent-1",
      name: "Probe",
      description: null,
      instructions: "initial",
      workspacePath: path.join(workspace, "agent-1"),
    } as unknown as Agent;
    await manager.create(agent);

    const agentsFile = path.join(agent.workspacePath, "AGENTS.md");
    await rm(agentsFile);
    await symlink(outside, agentsFile);

    const attacker = { ...agent, instructions: "PAYLOAD the caller controls" } as Agent;
    await expect(manager.writeInstructions(attacker)).rejects.toThrow(/non-regular file/i);
    expect(await readFile(outside, "utf8")).toBe("REAL AUDIT EVIDENCE\n");
    expect(root).toBeTruthy();
  });
});
