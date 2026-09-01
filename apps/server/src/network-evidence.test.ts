import { mkdtemp, rm } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { AgentService } from "./agent-service.js";
import { loadConfig, type AppConfig } from "./config.js";
import { ContainerCodexRunner } from "./container-codex-runner.js";
import {
  EgressIsolation,
  buildBrokerLogsArgs,
  buildBrokerRunArgs,
  parseBrokerDenials,
  type EngineResult,
} from "./network-isolation.js";
import { JsonStore } from "./store.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";
import { WorkspaceManager } from "./workspace.js";

/**
 * @covers TM-AGENT-006
 * Broker denials as first-class, persisted evidence.
 *
 * The gap this closes: the classifier has documented residual blind spots — a
 * payload written into a Makefile target, a git hook or a crontab and executed
 * later by something else. For network exfiltration those are contained
 * structurally, because the container has no route out and the broker refuses
 * the destination whether or not the classifier recognised the command. But the
 * containment was INVISIBLE: the broker logged to its own stderr and nothing
 * else, so a run where containment quietly did its job looked identical to a
 * clean one.
 *
 * The fail-closed rule here runs the opposite way from the rest of the network
 * layer, and that is deliberate. Containment failing closed means less access.
 * Evidence collection failing closed would mean failing the RUN, which is
 * wrong: containment already held by the time there is anything to collect. So
 * collection never fails a run — and it must never report "unknown" as "clean",
 * which is the one way a missing record becomes a false assurance.
 */

const ARK_BASE_URL = "https://ark.example.invalid/api/v3";
const BROKER_IP = "172.30.0.9";

const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

/** One `egress-denied` line exactly as the broker's CLI writes it. */
const denialLine = (host: string, port: number, reason: string, runId = "run-1") =>
  JSON.stringify({
    event: "egress-denied",
    source: "egress-broker",
    runId,
    agentId: "a",
    target: host + ":" + port,
    host,
    port,
    reason,
    at: "2026-09-01T10:00:00.000Z",
  });

/**
 * An engine whose broker log is scripted per call, so the two collection points
 * — after the Agent settles, and again at teardown — can be told apart.
 */
function engineWith(logsByCall: string[]) {
  const calls: string[][] = [];
  let logReads = 0;
  const exec = async (args: string[]): Promise<EngineResult> => {
    calls.push(args);
    if (args[0] === "inspect") return { code: 0, stdout: BROKER_IP + "\n", stderr: "" };
    if (args[0] === "logs") {
      const body = logsByCall[Math.min(logReads, logsByCall.length - 1)] ?? "";
      logReads += 1;
      if (body === "FAIL") return { code: 1, stdout: "", stderr: "no such container" };
      return { code: 0, stdout: "", stderr: body };
    }
    return { code: 0, stdout: "", stderr: "" };
  };
  return { calls, exec, logReads: () => logReads };
}

async function makeConfig(overrides: Record<string, string> = {}) {
  const root = await mkdtemp(path.join(tmpdir(), "network-evidence-"));
  dirs.push(root);
  const config = loadConfig({
    NODE_ENV: "test",
    APP_DATA_DIR: path.join(root, "data"),
    AGENT_WORKSPACE_ROOT: path.join(root, "workspaces"),
    CODEX_HOME: path.join(root, "codex"),
    ARK_API_KEY: "test-key",
    ARK_MODEL: "ep-test",
    ARK_BASE_URL: ARK_BASE_URL,
    RUNTIME_PROVIDER: "container",
    RUNTIME_INSTANCE_ID: "test",
    CONTAINER_USER: "1000:1000",
    CONTAINER_EGRESS_ISOLATION: "true",
    CONTAINER_ENGINE: path.join(tmpdir(), "sentinel-no-such-engine"),
    CONTAINER_EGRESS_READY_TIMEOUT_MS: "2000",
    ...overrides,
  });
  return { config, root };
}

describe("the broker tells the control plane what it refused", () => {
  it("stamps the run into the broker container so a denial can be correlated", () => {
    // The broker is a detached container that otherwise has no idea which run
    // it serves, so a denial it logs would be uncorrelatable evidence.
    const args = buildBrokerRunArgs({
      broker: "b",
      network: "n",
      image: "img",
      allowUrls: ["https://ark.example.invalid"],
      port: 8080,
      user: "1000:1000",
      runId: "run-42",
      agentId: "agent-7",
    });
    expect(args).toContain("EGRESS_RUN_ID=run-42");
    expect(args).toContain("EGRESS_AGENT_ID=agent-7");
  });

  it("omits the correlation env when there is no run to name", () => {
    // `verify:egress` starts a broker outside any run. The denial is still
    // logged and still readable, just uncorrelated.
    const args = buildBrokerRunArgs({
      broker: "b",
      network: "n",
      image: "img",
      allowUrls: ["https://ark.example.invalid"],
      port: 8080,
      user: "1000:1000",
    });
    expect(args.some((arg) => arg.startsWith("EGRESS_RUN_ID"))).toBe(false);
  });

  it("reads the broker log through the engine, bounded", () => {
    // The broker publishes no host port and sits on an --internal network, so
    // the engine is the only thing that can hand its stderr back.
    expect(buildBrokerLogsArgs("b")).toEqual(["logs", "--tail", "2000", "b"]);
  });

  it("parses denials and skips everything else in the log", () => {
    const log = [
      JSON.stringify({ event: "egress-broker-ready", listening: "0.0.0.0:8080" }),
      denialLine("attacker.example", 443, "destination not allowlisted"),
      "some unstructured node warning",
      "{ not json at all",
      denialLine("evil.example", 8443, "resolves to a private address"),
    ].join("\n");

    const records = parseBrokerDenials(log);
    expect(records).toHaveLength(2);
    expect(records[0]).toMatchObject({
      host: "attacker.example",
      port: 443,
      reason: "destination not allowlisted",
      runId: "run-1",
    });
    expect(records[1]).toMatchObject({ host: "evil.example", port: 8443 });
  });

  it("tolerates an engine stream prefix in front of the JSON", () => {
    // Engines differ on how they replay a container's streams; a line that is
    // otherwise a valid denial must not be dropped over a prefix.
    const records = parseBrokerDenials(
      "2026-09-01T10:00:00Z stderr F " + denialLine("attacker.example", 443, "denied"),
    );
    expect(records).toHaveLength(1);
    expect(records[0]?.host).toBe("attacker.example");
  });
});

describe("network denials become persisted run evidence", () => {
  /**
   * Drives the real runner through the engine seam. The Agent container cannot
   * be spawned without an engine, so the run fails at the spawn — which is also
   * the path on which containment evidence matters most, and the path that
   * proves the teardown-time read happens even when the run threw.
   */
  async function runWith(logsByCall: string[]) {
    const { config } = await makeConfig();
    const workspace = await mkdtemp(path.join(tmpdir(), "network-evidence-ws-"));
    dirs.push(workspace);
    const { calls, exec } = engineWith(logsByCall);
    const runner = new ContainerCodexRunner(config, exec);
    let thrown: unknown;
    try {
      await runner.run({
        agentId: "a",
        workspacePath: workspace,
        prompt: "x",
        threadId: null,
        runId: "run-1",
      });
    } catch (error) {
      thrown = error;
    }
    expect(thrown, "the run should have failed at the spawn").toBeDefined();
    return {
      calls,
      denials: (thrown as { networkDenials?: unknown }).networkDenials,
    };
  }

  it("carries a denied destination out of the run", async () => {
    const { denials } = await runWith([
      denialLine("telemetry.example", 443, "destination not allowlisted"),
    ]);
    expect(denials).toEqual([
      {
        host: "telemetry.example",
        port: 443,
        reason: "destination not allowlisted",
        observedAt: "2026-09-01T10:00:00.000Z",
      },
    ]);
  });

  it("reports an empty list — not unknown — when the broker refused nothing", async () => {
    const { denials } = await runWith([
      JSON.stringify({ event: "egress-broker-ready", listening: "0.0.0.0:8080" }),
    ]);
    expect(denials).toEqual([]);
  });

  it("reads the broker log BEFORE stopping it, or the evidence dies with it", async () => {
    // The broker runs --rm: once the container stops, its log is gone. The
    // teardown read is the last chance to see anything the Agent triggered in
    // its final moments, so the ordering is the property, not an incidental.
    const { calls, denials } = await runWith([
      denialLine("late.example", 443, "destination not allowlisted"),
    ]);
    const verbs = calls.map((c) => c[0]);
    expect(verbs).toContain("logs");
    expect(verbs.lastIndexOf("logs")).toBeLessThan(verbs.lastIndexOf("stop"));
    expect(denials).toHaveLength(1);
    expect((denials as { host: string }[])[0]?.host).toBe("late.example");
  });

  it("merges a second read with the first instead of replacing it", async () => {
    // Two collection points — once the Agent's process settles, and again at
    // teardown — and the engine replays the whole log each time. A denial seen
    // only in the second read has to survive, and one seen in both must not be
    // recorded twice. Driven at the isolation seam because the "during the run"
    // read needs the Agent's process to have actually started, which needs an
    // engine this suite deliberately does not assume.
    const { config } = await makeConfig();
    const first = denialLine("early.example", 443, "destination not allowlisted");
    const second = [first, denialLine("late.example", 8443, "resolves to a private address")].join("\n");
    const { exec } = engineWith([first, second]);
    const isolation = new EgressIsolation(config, exec);
    const handle = await isolation.setup("a", [], "run-1");

    const readOne = await isolation.collectDenials(handle);
    const readTwo = await isolation.collectDenials(handle);
    expect(readOne).toHaveLength(1);
    expect(readTwo).toHaveLength(2);
    // The overlap is the same record twice over, and the runner deduplicates it
    // on content; the second read is a superset, never a replacement.
    expect(readTwo?.[0]?.host).toBe("early.example");
    expect(readTwo?.[1]?.host).toBe("late.example");
  });

  it("degrades to unknown, not to clean, when the log cannot be read", async () => {
    // The failure this exists to prevent: an unreadable log rendering as a run
    // where nothing was refused.
    const { denials } = await runWith(["FAIL", "FAIL"]);
    expect(denials).toBeNull();
    expect(denials).not.toEqual([]);
  });

  it("keeps an earlier successful read when a later one fails", async () => {
    // A broker that dies between the two reads must not take the evidence it
    // already gave us with it.
    const { denials } = await runWith([
      denialLine("early.example", 443, "destination not allowlisted"),
      "FAIL",
    ]);
    expect(denials).toHaveLength(1);
    expect((denials as { host: string }[])[0]?.host).toBe("early.example");
  });
});

/** A runner that reports a fixed network verdict, so the service can be driven alone. */
class VerdictRunner implements AgentRunner {
  constructor(private readonly verdict: RunnerResult["networkDenials"]) {}
  async run(_request: RunnerRequest): Promise<RunnerResult> {
    return {
      output: "done",
      threadId: "t1",
      usage: null,
      ...(this.verdict === undefined ? {} : { networkDenials: this.verdict }),
    };
  }
  async cancel(): Promise<boolean> {
    return false;
  }
  async isAvailable(): Promise<boolean> {
    return true;
  }
}

async function serviceWith(config: AppConfig, root: string, runner: AgentRunner) {
  const service = new AgentService(
    config,
    new JsonStore(path.join(root, "data", "db.json")),
    new WorkspaceManager(path.join(root, "workspaces")),
    runner,
  );
  await service.initialize();
  return service;
}

describe("the store keeps network denials apart from policy decisions", () => {
  it("persists a denial with its correlation, tagged as network-layer", async () => {
    const { config, root } = await makeConfig();
    const service = await serviceWith(
      config,
      root,
      new VerdictRunner([
        {
          host: "telemetry.example",
          port: 443,
          reason: "destination not allowlisted",
          observedAt: "2026-09-01T10:00:00.000Z",
        },
      ]),
    );
    const agent = await service.createAgent({ name: "Contained" });
    const { run } = await service.sendMessage(agent.id, "do something");
    await expect.poll(() => service.getRun(run.id).status).toBe("completed");

    const events = service.getNetworkEvents(agent.id);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      agentId: agent.id,
      runId: run.id,
      host: "telemetry.example",
      port: 443,
      reason: "destination not allowlisted",
      source: "egress-broker",
    });

    // Different in kind, so stored apart: a policy decision explains itself
    // before the command runs; this one means the classifier never saw it.
    expect(service.getPolicyEvents(agent.id)).toHaveLength(0);
    expect(service.getRun(run.id).networkEvidence).toBe("collected");
  });

  it("records collected-with-nothing distinctly from unknown", async () => {
    const clean = await makeConfig();
    const cleanService = await serviceWith(clean.config, clean.root, new VerdictRunner([]));
    const cleanAgent = await cleanService.createAgent({ name: "Clean" });
    const cleanRun = (await cleanService.sendMessage(cleanAgent.id, "x")).run;
    await expect.poll(() => cleanService.getRun(cleanRun.id).status).toBe("completed");
    expect(cleanService.getRun(cleanRun.id).networkEvidence).toBe("collected");
    expect(cleanService.getNetworkEvents(cleanAgent.id)).toHaveLength(0);

    const blind = await makeConfig();
    const blindService = await serviceWith(blind.config, blind.root, new VerdictRunner(null));
    const blindAgent = await blindService.createAgent({ name: "Blind" });
    const blindRun = (await blindService.sendMessage(blindAgent.id, "x")).run;
    await expect.poll(() => blindService.getRun(blindRun.id).status).toBe("completed");

    // Same empty event list, opposite meanings. Only the run's own field can
    // tell them apart, which is why it exists.
    expect(blindService.getNetworkEvents(blindAgent.id)).toHaveLength(0);
    expect(blindService.getRun(blindRun.id).networkEvidence).toBe("unavailable");
  });

  it("leaves networkEvidence unset when there was no broker at all", async () => {
    // Isolation off, or the local-process runtime. "Not applicable" is a third
    // thing again, and must not read as either clean or unknown.
    const { config, root } = await makeConfig();
    const service = await serviceWith(config, root, new VerdictRunner(undefined));
    const agent = await service.createAgent({ name: "Unisolated" });
    const { run } = await service.sendMessage(agent.id, "x");
    await expect.poll(() => service.getRun(run.id).status).toBe("completed");
    expect(service.getRun(run.id).networkEvidence).toBeUndefined();
  });

  it("does not fail the run when evidence collection fails", async () => {
    // The rule that keeps this feature from becoming a liability: containment
    // already held; only the record of it is missing.
    const { config, root } = await makeConfig();
    const service = await serviceWith(config, root, new VerdictRunner(null));
    const agent = await service.createAgent({ name: "Blind" });
    const { run } = await service.sendMessage(agent.id, "x");
    await expect.poll(() => service.getRun(run.id).status).toBe("completed");
    expect(service.getRun(run.id).error).toBeNull();
    expect(service.getAgent(agent.id).status).toBe("ready");
  });
});
