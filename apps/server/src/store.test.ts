import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { JsonStore } from "./store.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

describe("JsonStore", () => {
  it("does not publish a mutation in memory when persistence fails", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "launchpad-store-test-"));
    temporaryDirectories.push(root);
    const originalPath = path.join(root, "db.json");
    const store = new JsonStore(originalPath);
    await store.initialize();

    const mutableStore = store as unknown as { filePath: string };
    mutableStore.filePath = path.join(root, "missing-directory", "db.json");
    await expect(
      store.mutate((database) => {
        database.messages.push({
          id: "message-1",
          agentId: "agent-1",
          runId: "run-1",
          role: "user",
          content: "must not become visible",
          createdAt: new Date().toISOString(),
        });
      }),
    ).rejects.toThrow();
    expect(store.snapshot().messages).toEqual([]);

    mutableStore.filePath = originalPath;
    await store.mutate((database) => {
      database.messages.push({
        id: "message-2",
        agentId: "agent-1",
        runId: "run-2",
        role: "user",
        content: "queue recovered",
        createdAt: new Date().toISOString(),
      });
    });
    expect(store.snapshot().messages.map((message) => message.content)).toEqual([
      "queue recovered",
    ]);
  });

  // @covers TM-OPS-001
  it("prunes policyEvents older than retentionDays on the next mutation", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "launchpad-store-test-"));
    temporaryDirectories.push(root);
    const store = new JsonStore(path.join(root, "db.json"), 1);
    await store.initialize();

    const twoDaysAgo = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString();
    await store.mutate((database) => {
      database.policyEvents.push({
        id: "event-1",
        agentId: "agent-1",
        runId: "run-1",
        rule: "network-egress-denied",
        command: "curl https://attacker.example",
        detail: "non-allowlisted host",
        enforced: true,
        decidedAt: twoDaysAgo,
      });
    });

    expect(store.snapshot().policyEvents).toEqual([]);
  });

  it("never prunes a pending approval, however old its requestedAt is", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "launchpad-store-test-"));
    temporaryDirectories.push(root);
    const store = new JsonStore(path.join(root, "db.json"), 1);
    await store.initialize();

    const twoDaysAgo = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString();
    await store.mutate((database) => {
      database.approvals.push({
        id: "approval-1",
        agentId: "agent-1",
        runId: "run-1",
        prompt: "resume the task",
        rule: "network-egress-denied",
        command: "curl https://registry.npmjs.org/react",
        detail: "non-allowlisted host",
        hosts: ["registry.npmjs.org"],
        status: "pending",
        requestedAt: twoDaysAgo,
        resolvedBy: null,
        decisionReason: null,
        resolvedAt: null,
        continuationRunId: null,
      });
    });

    expect(store.snapshot().approvals.map((approval) => approval.id)).toEqual([
      "approval-1",
    ]);
  });

  it("prunes a resolved approval once resolvedAt is older than retentionDays", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "launchpad-store-test-"));
    temporaryDirectories.push(root);
    const store = new JsonStore(path.join(root, "db.json"), 1);
    await store.initialize();

    const twoDaysAgo = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString();
    await store.mutate((database) => {
      database.approvals.push({
        id: "approval-2",
        agentId: "agent-1",
        runId: "run-1",
        prompt: "resume the task",
        rule: "network-egress-denied",
        command: "curl https://registry.npmjs.org/react",
        detail: "non-allowlisted host",
        hosts: ["registry.npmjs.org"],
        status: "approved",
        requestedAt: twoDaysAgo,
        resolvedBy: "operator",
        decisionReason: "known-good registry",
        resolvedAt: twoDaysAgo,
        continuationRunId: null,
      });
    });

    expect(store.snapshot().approvals).toEqual([]);
  });
});
