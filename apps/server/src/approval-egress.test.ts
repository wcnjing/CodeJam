import { createConnection, createServer, type Server } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { AgentService } from "./agent-service.js";
import { policyContextFrom, scanCommands, type Actor } from "./command-policy.js";
import { loadConfig, type AppConfig } from "./config.js";
import { ContainerCodexRunner } from "./container-codex-runner.js";
import { brokerAllowlist, createEgressBroker } from "./egress-broker.js";
import { PolicyViolationError } from "./errors.js";
import { EgressIsolation, type EngineResult } from "./network-isolation.js";
import { JsonStore } from "./store.js";
import type { Principal } from "./principals.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";
import { WorkspaceManager } from "./workspace.js";

/**
 * @covers TM-AGENT-005 TM-AGENT-006
 * The approval path end to end: policy holds a host, a human grants it, and the
 * RUN'S NETWORK — not just its policy context — is built to include it.
 *
 * The bug this pins down was a disagreement between two layers that are meant
 * to be independent. `extraAllowedHosts` reached the command policy and stopped
 * there; the broker's allowlist was hardcoded to the Ark endpoint. A human
 * approved `registry.npmjs.org`, policy let the command through, and the broker
 * refused the connection — an approval honoured at one layer and denied at the
 * other, which is the worst of both: the operator believes they granted access
 * and the Agent behaves as though they had not.
 *
 * Nothing here restates the production wiring. The policy decision comes from
 * the real `scanCommands`, the topology from the real `EgressIsolation`, the
 * allowlist from the real `brokerAllowlist` parsing the real argv the runner
 * builds, and the allow/deny answers from a real `createEgressBroker`. The only
 * stand-in is the container engine, through the `EngineExec` seam the module
 * already exposes, because a live engine is exactly what a unit suite cannot
 * assume.
 */

const APPROVED_HOST = "registry.npmjs.org";
const OTHER_HOST = "attacker.example";
const ARK_BASE_URL = "https://ark.example.invalid/api/v3";
const ALICE: Principal = { id: "ops-alice" };

const dirs: string[] = [];
const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(
    servers.splice(0).map((s) => new Promise<void>((done) => s.close(() => done()))),
  );
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

function listen(server: Server): Promise<number> {
  servers.push(server);
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve((server.address() as { port: number }).port);
    });
  });
}

/** Sends a raw CONNECT and returns everything the broker wrote back. */
function connect(port: number, request: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = createConnection({ host: "127.0.0.1", port }, () => socket.write(request));
    let buffer = "";
    socket.setTimeout(4000, () => {
      socket.destroy();
      reject(new Error("timeout"));
    });
    socket.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("latin1");
    });
    socket.on("close", () => resolve(buffer));
    socket.on("error", reject);
  });
}

const ok: EngineResult = { code: 0, stdout: "", stderr: "" };

/** Records every engine invocation, so the run's topology can be read back. */
function recorder() {
  const calls: string[][] = [];
  return {
    calls,
    exec: async (args: string[]) => {
      calls.push(args);
      return ok;
    },
  };
}

/** The `--env NAME=value` pairs of one broker `run` invocation. */
function brokerEnv(args: string[]): Record<string, string> {
  const environment: Record<string, string> = {};
  for (let index = 0; index < args.length - 1; index += 1) {
    if (args[index] !== "--env") continue;
    const [name, ...rest] = args[index + 1]!.split("=");
    environment[name!] = rest.join("=");
  }
  return environment;
}

/** A stable label per engine call: the verb, plus the object it acts on. */
const verbs = (calls: string[][]) =>
  calls.map((c) => {
    if (c[0] === "network") return "network " + c[1];
    if (c[0] === "stop") return "stop " + c[c.length - 1];
    return c[0]!;
  });

/** Every broker `run` in the order the engine saw them: one per run of the Agent. */
const brokerRuns = (calls: string[][]) =>
  calls.filter((c) => c[0] === "run" && c.includes("--detach"));

const CURL_APPROVED = "/bin/bash -lc 'curl https://" + APPROVED_HOST + "/react'";

/**
 * The runner under test, minus the one thing a unit suite cannot have.
 *
 * It performs exactly what `ContainerCodexRunner.run` performs, in the same
 * order — isolation first, then policy over the Agent's commands, then teardown
 * in a `finally` — with the container's stdout supplied as a canned command
 * instead of spawned. The policy context is built with the same arguments the
 * real runner builds it with, so an `extraAllowedHosts` that stopped reaching
 * either layer would fail here for the same reason it fails in production.
 *
 * `ContainerCodexRunner` itself is driven directly further down, against the
 * same engine seam, to pin the hop this class necessarily stands in for.
 */
class PolicyGatedIsolatedRunner implements AgentRunner {
  public readonly calls: RunnerRequest[] = [];
  private readonly isolation: EgressIsolation;

  constructor(
    private readonly config: AppConfig,
    exec: (args: string[]) => Promise<EngineResult>,
    private readonly command = CURL_APPROVED,
  ) {
    this.isolation = new EgressIsolation(config, exec);
  }

  async run(request: RunnerRequest): Promise<RunnerResult> {
    this.calls.push(request);
    const approved = request.extraAllowedHosts ?? [];
    const handle = await this.isolation.setup(request.agentId, approved);
    try {
      const actor: Actor = { agentId: request.agentId, threadId: request.threadId };
      const context = policyContextFrom(
        this.config.arkBaseUrl,
        [...this.config.policyAllowedHosts, ...approved],
        [this.config.arkApiKey],
        ["/workspace", "/tmp", "/var/tmp"],
      );
      const violation = scanCommands(actor, [this.command], 0, context)[0];
      if (violation) {
        throw new PolicyViolationError(
          violation.rule,
          violation.command,
          violation.detail,
          violation.hosts ?? [],
          violation.capabilities ?? [],
        );
      }
      return { output: "fetched from " + APPROVED_HOST, threadId: "thread-1", usage: null };
    } finally {
      // The grant lives in the broker container's env, so teardown is what ends
      // it. Always, including the throwing path.
      await this.isolation.teardown(handle);
    }
  }

  async cancel(): Promise<boolean> {
    return false;
  }

  async isAvailable(): Promise<boolean> {
    return true;
  }
}

async function makeConfig(overrides: Record<string, string> = {}) {
  const root = await mkdtemp(path.join(tmpdir(), "approval-egress-"));
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
    ...overrides,
  });
  return { config, root };
}

async function makeService(config: AppConfig, root: string, runner: AgentRunner) {
  const service = new AgentService(
    config,
    new JsonStore(path.join(root, "data", "db.json")),
    new WorkspaceManager(path.join(root, "workspaces")),
    runner,
  );
  await service.initialize();
  return service;
}

describe("an approved host reaches the network, scoped to one run", () => {
  it("holds, is granted by a principal, and lands on that run's broker allowlist", async () => {
    const { config, root } = await makeConfig();
    const { calls, exec } = recorder();
    const runner = new PolicyGatedIsolatedRunner(config, exec);
    const service = await makeService(config, root, runner);
    const agent = await service.createAgent({ name: "Gated" });

    // 1. A run that wants a host nobody allowlisted is HELD, not failed.
    const { run } = await service.sendMessage(agent.id, "fetch the react version");
    await expect.poll(() => service.getRun(run.id).status).toBe("held");

    const pending = service.listApprovals(agent.id);
    expect(pending).toHaveLength(1);
    expect(pending[0]).toMatchObject({ status: "pending", rule: "network-egress-denied" });
    expect(pending[0]?.hosts).toContain(APPROVED_HOST);

    // That first run's broker was built with no grant at all — the variable is
    // absent rather than empty, so an ordinary run carries no approval state.
    const before = brokerEnv(brokerRuns(calls)[0]!);
    expect(before.EGRESS_ALLOW_URL).toBe(ARK_BASE_URL);
    expect(before).not.toHaveProperty("EGRESS_APPROVED_URLS");

    // 2. An authenticated principal grants exactly that host.
    const { continuationRun } = await service.resolveApproval(
      pending[0]!.id,
      "approve",
      ALICE,
      "npm registry is a trusted dependency source",
    );
    expect(continuationRun).not.toBeNull();
    await expect.poll(() => service.getRun(continuationRun!.id).status).toBe("completed");

    // 3. The continuation's broker carries the grant, in its own variable so an
    //    operator can tell a granted allowance from the standing one.
    const granted = brokerEnv(brokerRuns(calls)[1]!);
    expect(granted.EGRESS_ALLOW_URL).toBe(ARK_BASE_URL);
    expect(granted.EGRESS_APPROVED_URLS).toBe("https://" + APPROVED_HOST);

    // 4. Parsed the way the sidecar parses it: Ark plus exactly that one host.
    const allowlist = brokerAllowlist(granted.EGRESS_ALLOW_URL!, granted.EGRESS_APPROVED_URLS!);
    expect(allowlist).toEqual([
      { host: "ark.example.invalid", port: 443 },
      { host: APPROVED_HOST, port: 443 },
    ]);

    // 5. A real broker built from that allowlist lets the approved host through
    //    and still refuses everything else. The upstream is on loopback, which
    //    the address guard rightly forbids, so DNS answers a public address and
    //    the injected dial redirects the socket — the guard stays fully armed.
    const upstream = createServer((socket) => socket.end("hello"));
    const upstreamPort = await listen(upstream);
    const brokerPort = await listen(
      createEgressBroker({
        allow: allowlist,
        resolve: async () => ["93.184.216.34"],
        dial: (_target, onReady) =>
          createConnection({ host: "127.0.0.1", port: upstreamPort }, onReady),
      }),
    );

    const permitted = await connect(
      brokerPort,
      "CONNECT " + APPROVED_HOST + ":443 HTTP/1.1\r\n\r\n",
    );
    expect(permitted).toContain("200 Connection Established");

    const refused = await connect(brokerPort, "CONNECT " + OTHER_HOST + ":443 HTTP/1.1\r\n\r\n");
    expect(refused).toContain("403 Forbidden");

    // The grant is a name on the list, not a port range on that name.
    const wrongPort = await connect(
      brokerPort,
      "CONNECT " + APPROVED_HOST + ":8443 HTTP/1.1\r\n\r\n",
    );
    expect(wrongPort).toContain("403 Forbidden");

    // Ark is still reachable: the grant added to the allowlist, it did not
    // replace it.
    const ark = await connect(brokerPort, "CONNECT ark.example.invalid:443 HTTP/1.1\r\n\r\n");
    expect(ark).toContain("200 Connection Established");

    // 6. Teardown: the granted topology does not survive the run that held it.
    const grantedRunIndex = calls.indexOf(brokerRuns(calls)[1]!);
    const after = verbs(calls.slice(grantedRunIndex));
    expect(after).toContain("stop sentinel-test-" + agent.id + "-broker");
    expect(after).toContain("network rm");

    // 7. A fresh, independent run asking for the same host is held again, and
    //    its broker is built with no grant. The approval bought one run.
    const second = await service.sendMessage(agent.id, "fetch the react version again");
    await expect.poll(() => service.getRun(second.run.id).status).toBe("held");
    expect(brokerEnv(brokerRuns(calls)[2]!)).not.toHaveProperty("EGRESS_APPROVED_URLS");
    expect(service.listApprovals(agent.id).filter((a) => a.status === "pending")).toHaveLength(1);
  }, 30_000);

  it("does not leak the grant to another agent's run", async () => {
    // Scoping is per RUN, and the topology is named per agent, so the check
    // that matters is that a second agent's broker is built from its own
    // (empty) list rather than from anything the first agent was granted.
    const { config, root } = await makeConfig();
    const { calls, exec } = recorder();
    const runner = new PolicyGatedIsolatedRunner(config, exec);
    const service = await makeService(config, root, runner);

    const granted = await service.createAgent({ name: "Granted" });
    const other = await service.createAgent({ name: "Other" });

    const first = await service.sendMessage(granted.id, "fetch");
    await expect.poll(() => service.getRun(first.run.id).status).toBe("held");
    const approval = service.listApprovals(granted.id)[0]!;
    const { continuationRun } = await service.resolveApproval(
      approval.id,
      "approve",
      ALICE,
      "trusted registry",
    );
    await expect.poll(() => service.getRun(continuationRun!.id).status).toBe("completed");

    const second = await service.sendMessage(other.id, "fetch");
    await expect.poll(() => service.getRun(second.run.id).status).toBe("held");

    const otherBroker = brokerRuns(calls).find((c) =>
      c.includes("sentinel-test-" + other.id + "-broker"),
    );
    expect(otherBroker, "the second agent never got a broker").toBeDefined();
    expect(brokerEnv(otherBroker!)).not.toHaveProperty("EGRESS_APPROVED_URLS");
  }, 30_000);

  it("refuses an approved host that resolves into a private range", async () => {
    // Approval is not a way past the rebinding check. The host is on the
    // allowlist and still does not connect, because the guard runs on the
    // RESOLVED address and runs for every allowlisted name, not only Ark's.
    const allowlist = brokerAllowlist(ARK_BASE_URL, "https://" + APPROVED_HOST);
    const denials: string[] = [];
    const port = await listen(
      createEgressBroker({
        allow: allowlist,
        resolve: async () => ["169.254.169.254"],
        onDenied: (reason) => denials.push(reason),
      }),
    );

    const response = await connect(port, "CONNECT " + APPROVED_HOST + ":443 HTTP/1.1\r\n\r\n");
    expect(response).toContain("403 Forbidden");
    expect(denials).toContain("resolves to a private address");
  });

  it("refuses an approved host whose answers are only partly private", async () => {
    // One public answer alongside a private one is a rebinding attempt, not a
    // dual-stack convenience. The grant does not soften that.
    const allowlist = brokerAllowlist(ARK_BASE_URL, "https://" + APPROVED_HOST);
    const port = await listen(
      createEgressBroker({
        allow: allowlist,
        resolve: async () => ["93.184.216.34", "127.0.0.1"],
      }),
    );
    expect(
      await connect(port, "CONNECT " + APPROVED_HOST + ":443 HTTP/1.1\r\n\r\n"),
    ).toContain("403 Forbidden");
  });

  it("refuses to build a topology at all for a grant it cannot express", async () => {
    // Fail closed on nonsense rather than dropping the entry: a grant that
    // cannot be turned into an endpoint must not become a broker that silently
    // lacks it, because the operator has already been told it was honoured.
    const { config } = await makeConfig();
    const { calls, exec } = recorder();
    await expect(
      new EgressIsolation(config, exec).setup("a", ["not a host"]),
    ).rejects.toThrow();
    expect(calls, "nothing should have been created").toHaveLength(0);
  });
});

describe("ContainerCodexRunner hands the run's grant to the network", () => {
  /**
   * The hop the class above necessarily stands in for: `run()` ->
   * `startIsolation` -> `setup`. Driven against the real runner through the
   * engine seam. The Agent container cannot be spawned here — that needs an
   * engine — so the run fails at the spawn, which is also what makes this the
   * check that teardown happens on the THROWING path.
   */
  async function runAndCapture(extraAllowedHosts?: string[]) {
    const { config } = await makeConfig({
      // A path no engine lives at: setup and readiness run through the seam,
      // and the Agent's spawn is what fails.
      CONTAINER_ENGINE: path.join(tmpdir(), "sentinel-no-such-engine"),
      CONTAINER_EGRESS_READY_TIMEOUT_MS: "2000",
    });
    const workspace = await mkdtemp(path.join(tmpdir(), "approval-egress-ws-"));
    dirs.push(workspace);
    const { calls, exec } = recorder();
    const runner = new ContainerCodexRunner(config, exec);

    await expect(
      runner.run({
        agentId: "a",
        workspacePath: workspace,
        prompt: "x",
        threadId: null,
        ...(extraAllowedHosts ? { extraAllowedHosts } : {}),
      }),
    ).rejects.toThrow();
    return calls;
  }

  it("puts the run's extraAllowedHosts into the broker it starts", async () => {
    const calls = await runAndCapture([APPROVED_HOST]);
    const broker = brokerRuns(calls)[0]!;
    expect(brokerEnv(broker).EGRESS_APPROVED_URLS).toBe("https://" + APPROVED_HOST);
  }, 30_000);

  it("starts an ungranted run's broker with no approval variable", async () => {
    const calls = await runAndCapture();
    expect(brokerEnv(brokerRuns(calls)[0]!)).not.toHaveProperty("EGRESS_APPROVED_URLS");
  }, 30_000);

  it("tears the granted topology down even though the run threw", async () => {
    const calls = await runAndCapture([APPROVED_HOST]);
    const started = calls.indexOf(brokerRuns(calls)[0]!);
    const after = verbs(calls.slice(started));
    expect(after).toContain("stop sentinel-test-a-broker");
    expect(after).toContain("network rm");
  }, 30_000);
});
