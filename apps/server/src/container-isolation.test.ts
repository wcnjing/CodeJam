import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { ContainerCodexRunner } from "./container-codex-runner.js";
import { loadConfig } from "./config.js";

/**
 * @covers TM-AGENT-006
 * The runner's real start path with egress isolation ON — setup, the readiness
 * gate, then the Agent — driven end to end against a fake engine executable.
 *
 * The argv tests in network-isolation.test.ts assert what we would ask an
 * engine to do; container-runner-policy.test.ts turns isolation off entirely.
 * Neither exercises `startIsolation`, which is where the readiness probe lives,
 * so a probe that can never succeed passed both suites while making every real
 * container run fail. This drives the actual path instead.
 *
 * The engine is faked, not the isolation object: a probe the host cannot
 * perform has to fail here, which is the whole point of the file.
 */

const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

const COMPLETION = [
  { type: "thread.started", thread_id: "t1" },
  { type: "item.completed", item: { id: "m1", type: "agent_message", text: "done" } },
];

/**
 * A fake `docker`. Records its argv so the readiness probe can be inspected,
 * and — crucially — has no host-side listener and no resolvable container name,
 * exactly like a real engine. The only way to observe the broker is to ask it.
 */
async function fakeEngine(logPath: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "fake-engine-iso-"));
  dirs.push(dir);
  const bin = path.join(dir, "engine.mjs");
  const emit = COMPLETION.map(
    (event) => "process.stdout.write(" + JSON.stringify(JSON.stringify(event) + "\n") + ");",
  ).join("\n  ");
  await writeFile(
    bin,
    [
      "#!/usr/bin/env node",
      "import { appendFileSync } from 'node:fs';",
      "const argv = process.argv.slice(2);",
      "appendFileSync(" + JSON.stringify(logPath) + ", JSON.stringify(argv) + '\\n');",
      "const verb = argv[0];",
      // The broker's address on the isolated network, exactly as `docker
      // inspect --format ...` would print it; the runner needs it for --dns.
      "if (verb === 'inspect') { process.stdout.write('172.30.0.9\\n'); process.exit(0); }",
      // The broker runs detached; the Agent does not. Only the Agent streams.
      "if (verb === 'run' && !argv.includes('--detach')) {",
      "  " + emit,
      "  process.exit(0);",
      "}",
      "process.exit(0);",
      "",
    ].join("\n"),
    "utf8",
  );
  await chmod(bin, 0o755);
  return bin;
}

async function makeRunner(engine: string) {
  const state = await mkdtemp(path.join(tmpdir(), "container-iso-"));
  dirs.push(state);
  const config = loadConfig({
    NODE_ENV: "test",
    ARK_API_KEY: "test-key",
    ARK_MODEL: "ep-test",
    ARK_BASE_URL: "https://ark.example.invalid/api/v3",
    CODEX_HOME: state,
    RUNTIME_PROVIDER: "container",
    RUNTIME_INSTANCE_ID: "test",
    CONTAINER_ENGINE: engine,
    CONTAINER_RUNTIME_IMAGE: "runtime:test",
    CONTAINER_USER: "1000:1000",
    CONTAINER_EGRESS_ISOLATION: "true",
    // Short, so a probe that can never succeed fails the test in seconds
    // rather than burning the 15s production default.
    CONTAINER_EGRESS_READY_TIMEOUT_MS: "2000",
  });
  return { runner: new ContainerCodexRunner(config), workspace: state };
}

describe("container runner with egress isolation on", () => {
  it("clears the readiness gate and runs the Agent", async () => {
    const logDir = await mkdtemp(path.join(tmpdir(), "engine-log-"));
    dirs.push(logDir);
    const logPath = path.join(logDir, "argv.log");
    await writeFile(logPath, "", "utf8");
    const engine = await fakeEngine(logPath);
    const { runner, workspace } = await makeRunner(engine);

    const result = await runner.run({
      agentId: "a",
      workspacePath: workspace,
      prompt: "x",
      threadId: null,
    });
    expect(result.threadId).toBe("t1");

    // The Agent's DNS points at the broker's address on the isolated network:
    // the only resolver the --internal network can reach.
    const calls: string[][] = (await readFile(logPath, "utf8"))
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as string[]);
    const agent = calls.find((c) => c[0] === "run" && !c.includes("--detach"));
    expect(agent, "the Agent was never started").toBeDefined();
    expect(agent![agent!.indexOf("--dns") + 1]).toBe("172.30.0.9");
  }, 30_000);

  it("asks the engine about the broker instead of probing from the host", async () => {
    // The host cannot resolve a container name — that name exists only in the
    // network's embedded DNS, which only containers on that network can query.
    // So readiness has to be observed through the engine, or it is not
    // observable at all and every isolated run fails at the gate.
    const logDir = await mkdtemp(path.join(tmpdir(), "engine-log-"));
    dirs.push(logDir);
    const logPath = path.join(logDir, "argv.log");
    await writeFile(logPath, "", "utf8");
    const engine = await fakeEngine(logPath);
    const { runner, workspace } = await makeRunner(engine);

    await runner.run({ agentId: "a", workspacePath: workspace, prompt: "x", threadId: null });

    const calls: string[][] = (await readFile(logPath, "utf8"))
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as string[]);
    const probe = calls.find((c) => c[0] === "exec");
    expect(probe, "readiness was never asked of the engine").toBeDefined();
    expect(probe![1]).toBe("sentinel-test-a-broker");
  }, 30_000);

  it("passes the run's approved hosts into the broker allowlist", async () => {
    // A human-approved host must be reachable through the container's only
    // edge, not just policy-allowed: the broker for the run carries the model
    // API plus the run's granted hosts in its EGRESS_ALLOW_URL.
    const logDir = await mkdtemp(path.join(tmpdir(), "engine-log-"));
    dirs.push(logDir);
    const logPath = path.join(logDir, "argv.log");
    await writeFile(logPath, "", "utf8");
    const engine = await fakeEngine(logPath);
    const { runner, workspace } = await makeRunner(engine);

    await runner.run({
      agentId: "a",
      workspacePath: workspace,
      prompt: "x",
      threadId: null,
      extraAllowedHosts: ["google.com"],
    });

    const calls: string[][] = (await readFile(logPath, "utf8"))
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as string[]);
    const broker = calls.find((c) => c[0] === "run" && c.includes("--detach"));
    expect(broker, "the broker was never started").toBeDefined();
    const allow = broker!.find((arg) => arg.startsWith("EGRESS_ALLOW_URL="));
    expect(allow).toBe("EGRESS_ALLOW_URL=https://ark.example.invalid,https://google.com");
  }, 30_000);

  it("refuses to start the Agent when the broker never answers", async () => {
    // Fail closed: an Agent started against a dead broker has no route out and
    // fails as what looks like a model outage.
    const logDir = await mkdtemp(path.join(tmpdir(), "engine-log-"));
    dirs.push(logDir);
    const logPath = path.join(logDir, "argv.log");
    await writeFile(logPath, "", "utf8");
    const dir = await mkdtemp(path.join(tmpdir(), "fake-engine-dead-"));
    dirs.push(dir);
    const bin = path.join(dir, "engine.mjs");
    await writeFile(
      bin,
      [
        "#!/usr/bin/env node",
        "import { appendFileSync } from 'node:fs';",
        "const argv = process.argv.slice(2);",
        "appendFileSync(" + JSON.stringify(logPath) + ", JSON.stringify(argv) + '\\n');",
        // Everything works except the broker, which never accepts a connection.
        "if (argv[0] === 'inspect') { process.stdout.write('172.30.0.9\\n'); process.exit(0); }",
        "process.exit(argv[0] === 'exec' ? 1 : 0);",
        "",
      ].join("\n"),
      "utf8",
    );
    await chmod(bin, 0o755);
    const { runner, workspace } = await makeRunner(bin);

    await expect(
      runner.run({ agentId: "a", workspacePath: workspace, prompt: "x", threadId: null }),
    ).rejects.toThrow(/did not become ready/);

    // And the topology it created must not survive the refusal.
    const calls: string[][] = (await readFile(logPath, "utf8"))
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as string[]);
    expect(calls.filter((c) => c[0] === "stop").length).toBeGreaterThan(0);
    expect(calls.filter((c) => c[0] === "network" && c[1] === "rm").length).toBeGreaterThan(0);
  }, 30_000);

  it("tears the topology down when the Agent cannot be spawned at all", async () => {
    // The spawn and the ~100 lines of setup after it sat outside the run's own
    // try/finally, so anything throwing there left the network and the broker
    // behind. Self-healing on the next run for the same agent, but only then.
    const logDir = await mkdtemp(path.join(tmpdir(), "engine-log-"));
    dirs.push(logDir);
    const logPath = path.join(logDir, "argv.log");
    await writeFile(logPath, "", "utf8");
    const engine = await fakeEngine(logPath);
    const { runner, workspace } = await makeRunner(engine);

    // A cwd that no longer exists reports asynchronously, so it is already
    // covered. This is the synchronous case: spawn rejects the argument before
    // any process exists, and the throw lands in the unguarded window.
    await expect(
      runner.run({
        agentId: "a",
        workspacePath: "\0" + workspace,
        prompt: "x",
        threadId: null,
      }),
    ).rejects.toThrow();

    const calls: string[][] = (await readFile(logPath, "utf8"))
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as string[]);
    // Setup clears a stale topology first, so a leak shows up as the absence of
    // a teardown *after* the broker was started and probed.
    const lastProbe = calls.map((c) => c[0]).lastIndexOf("exec");
    const after = calls.slice(lastProbe + 1).map((c) => c[0] + (c[1] === "rm" ? " rm" : ""));
    expect(after).toContain("stop");
    expect(after).toContain("network rm");
  }, 30_000);
});
