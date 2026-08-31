import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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
        resolvedByAttribution: "credential",
        decisionReason: "known-good registry",
        resolvedAt: twoDaysAgo,
        continuationRunId: null,
      });
    });

    expect(store.snapshot().approvals).toEqual([]);
  });
});

/** A resolved approval exactly as a pre-v2 release wrote it: no attribution. */
const v1Approval = (over: Record<string, unknown> = {}) => ({
  id: "ap-1",
  agentId: "agent-1",
  runId: "run-1",
  prompt: "fetch it",
  rule: "network-egress-denied",
  command: "curl https://registry.npmjs.org/react",
  detail: "non-allowlisted host",
  hosts: ["registry.npmjs.org"],
  status: "approved",
  requestedAt: "2026-08-30T10:00:00.000Z",
  resolvedBy: "operator",
  decisionReason: "known-good registry",
  resolvedAt: "2026-08-30T10:00:05.000Z",
  continuationRunId: null,
  ...over,
});

const v1File = (approvals: unknown[]) =>
  JSON.stringify({
    version: 1,
    agents: [],
    messages: [],
    runs: [],
    policyEvents: [],
    approvals,
  });

async function storeOn(contents?: string) {
  const root = await mkdtemp(path.join(tmpdir(), "launchpad-store-migrate-"));
  temporaryDirectories.push(root);
  const filePath = path.join(root, "db.json");
  if (contents !== undefined) await writeFile(filePath, contents, "utf8");
  const store = new JsonStore(filePath);
  await store.initialize();
  return { store, filePath };
}

describe("JsonStore schema migration", () => {
  it("labels a v1 record's approver self-asserted rather than letting it pass as authenticated", async () => {
    // Before v2 the approver was a free-text body field, so "operator" here was
    // asserted by whoever held the shared token. Loading it unlabelled would
    // make it indistinguishable from a credential-derived one.
    const { store } = await storeOn(
      v1File([
        v1Approval(),
        v1Approval({ id: "ap-2", status: "pending", resolvedBy: null, resolvedAt: null }),
      ]),
    );
    const { approvals, version } = store.snapshot();
    expect(version).toBe(2);
    expect(approvals[0]!.resolvedByAttribution).toBe("self-asserted");
    expect(approvals[0]!.resolvedBy).toBe("operator");
    // Still pending, so there is no approver to attribute either way.
    expect(approvals[1]!.resolvedByAttribution).toBeNull();
  });

  it("writes the upgrade back so it is not redone on every start", async () => {
    const { filePath } = await storeOn(v1File([v1Approval()]));
    const onDisk = JSON.parse(await readFile(filePath, "utf8"));
    expect(onDisk.version).toBe(2);
    expect(onDisk.approvals[0].resolvedByAttribution).toBe("self-asserted");

    // Reopening must read it as v2 and change nothing.
    const reopened = new JsonStore(filePath);
    await reopened.initialize();
    expect(reopened.snapshot().approvals[0]!.resolvedByAttribution).toBe("self-asserted");
  });

  it("leaves a v2 record's attribution alone", async () => {
    const { store } = await storeOn(
      JSON.stringify({
        version: 2,
        agents: [],
        messages: [],
        runs: [],
        policyEvents: [],
        approvals: [v1Approval({ resolvedBy: "alice", resolvedByAttribution: "credential" })],
      }),
    );
    expect(store.snapshot().approvals[0]!.resolvedByAttribution).toBe("credential");
  });

  it("starts a fresh store at the current version", async () => {
    const { store } = await storeOn();
    expect(store.snapshot().version).toBe(2);
  });

  it("still refuses a version it cannot migrate", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "launchpad-store-migrate-"));
    temporaryDirectories.push(root);
    const filePath = path.join(root, "db.json");
    await writeFile(filePath, JSON.stringify({ version: 3, agents: [], approvals: [] }), "utf8");
    await expect(new JsonStore(filePath).initialize()).rejects.toThrow(/Unsupported/i);
  });
});
