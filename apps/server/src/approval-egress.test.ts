import { createConnection, createServer, type Server } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { AgentService } from "./agent-service.js";
import { policyContextFrom, scanCommands, type Actor } from "./command-policy.js";
import { loadConfig, type AppConfig } from "./config.js";
import { ContainerCodexRunner, buildContainerRunArgs } from "./container-codex-runner.js";
import { createEgressBroker, parseEgressEndpoints } from "./egress-broker.js";
import { PolicyViolationError } from "./errors.js";
import { EgressIsolation, buildEgressAllowUrls, type EngineResult } from "./network-isolation.js";
import { JsonStore } from "./store.js";
import type { Principal } from "./principals.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";
import { WorkspaceManager } from "./workspace.js";

/**
 * @covers TM-AGENT-005 TM-AGENT-006
 * The approval path end to end: policy holds a host, a human grants it, and the
 * RUN'S NETWORK — not just its policy context — is built to include it.
 *
 * There are three sources of network authority and they must not be confused:
 *
 *   1. the platform endpoint (ARK_BASE_URL), always present;
 *   2. the STANDING allowlist — POLICY_ALLOWED_HOSTS plus the store-backed
 *      overrides an operator edits or widens by approving — persistent;
 *   3. the RUN-SCOPED grant an approval attaches to one continuation run.
 *
 * Enforcement is their union. Lifetime is not: 2 outlives the run and 3 dies
 * with it. This file pins both halves of that, because the failure mode either
 * way is silent — a grant that never reaches the network is an approval the
 * operator was told was honoured and the Agent sees refused, and a grant that
 * outlives its run is a standing allowance nobody decided to make.
 *
 * Nothing here restates the production wiring. The policy decision comes from
 * the real `scanCommands`, the topology from the real `EgressIsolation`, the
 * allowlist from the real `buildEgressAllowUrls` parsed by the real
 * `parseEgressEndpoints` out of the real argv, and the allow/deny answers from
 * a real `createEgressBroker`. The only stand-in is the container engine,
 * through the `EngineExec` seam the module already exposes, because a live
 * engine is exactly what a unit suite cannot assume.
 */

const APPROVED_HOST = "registry.npmjs.org";
const STANDING_HOST = "deb.debian.org";
const OTHER_HOST = "attacker.example";
const ARK_BASE_URL = "https://ark.example.invalid/api/v3";
const ARK_HOST = "ark.example.invalid";
const BROKER_IP = "172.30.0.9";
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

/**
 * Records every engine invocation so the run's topology can be read back.
 *
 * `inspect` has to answer with an address: setup refuses the run without one,
 * because an Agent that cannot resolve anything is a containment failure
 * dressed as a model outage.
 */
function recorder() {
  const calls: string[][] = [];
  const exec = async (args: string[]): Promise<EngineResult> => {
    calls.push(args);
    if (args[0] === "inspect") return { code: 0, stdout: BROKER_IP + "\n", stderr: "" };
    return { code: 0, stdout: "", stderr: "" };
  };
  return { calls, exec };
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

/** The hosts one broker was actually started with, parsed the way the sidecar parses them. */
const allowedHosts = (args: string[]) =>
  parseEgressEndpoints(brokerEnv(args).EGRESS_ALLOW_URL ?? "").map((e) => e.host);

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
    const extra = request.extraAllowedHosts ?? [];
    const handle = await this.isolation.setup(request.agentId, [...extra]);
    try {
      const actor: Actor = { agentId: request.agentId, threadId: request.threadId };
      const context = policyContextFrom(
        this.config.arkBaseUrl,
        [...this.config.policyAllowedHosts, ...extra],
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

    // That first run's broker was built with the platform endpoint alone: no
    // standing entry configured, and nothing granted yet.
    expect(allowedHosts(brokerRuns(calls)[0]!)).toEqual([ARK_HOST]);

    // 2. An authenticated principal grants exactly that host, WITHOUT widening
    //    the standing allowlist — the run-scoped path.
    const { continuationRun } = await service.resolveApproval(
      pending[0]!.id,
      "approve",
      ALICE,
      "npm registry is a trusted dependency source",
    );
    expect(continuationRun).not.toBeNull();
    await expect.poll(() => service.getRun(continuationRun!.id).status).toBe("completed");

    // 3. The continuation's broker carries the grant beside the platform
    //    endpoint, and nothing else.
    const granted = brokerRuns(calls)[1]!;
    expect(allowedHosts(granted)).toEqual([ARK_HOST, APPROVED_HOST]);

    // The audit record says the grant did NOT become standing.
    const resolved = service.getApproval(pending[0]!.id);
    expect(resolved.status).toBe("approved");
    expect(resolved.resolvedBy).toBe(ALICE.id);
    expect(resolved.allowlistWidened ?? null).toBeNull();
    expect(service.getAllowlist().overrides).not.toContain(APPROVED_HOST);

    // 4. A real broker built from that argv lets the approved host through and
    //    still refuses everything else. The upstream is on loopback, which the
    //    address guard rightly forbids, so DNS answers a public address and the
    //    injected dial redirects the socket — the guard stays fully armed.
    const upstream = createServer((socket) => socket.end("hello"));
    const upstreamPort = await listen(upstream);
    const brokerPort = await listen(
      createEgressBroker({
        allow: parseEgressEndpoints(brokerEnv(granted).EGRESS_ALLOW_URL!),
        resolve: async () => ["93.184.216.34"],
        dial: (_target, onReady) =>
          createConnection({ host: "127.0.0.1", port: upstreamPort }, onReady),
      }),
    );

    expect(
      await connect(brokerPort, "CONNECT " + APPROVED_HOST + ":443 HTTP/1.1\r\n\r\n"),
    ).toContain("200 Connection Established");

    expect(
      await connect(brokerPort, "CONNECT " + OTHER_HOST + ":443 HTTP/1.1\r\n\r\n"),
    ).toContain("403 Forbidden");

    // The grant is a name on the list, not a port range on that name.
    expect(
      await connect(brokerPort, "CONNECT " + APPROVED_HOST + ":8443 HTTP/1.1\r\n\r\n"),
    ).toContain("403 Forbidden");

    // The platform endpoint is still reachable: the grant added, it did not
    // replace.
    expect(
      await connect(brokerPort, "CONNECT " + ARK_HOST + ":443 HTTP/1.1\r\n\r\n"),
    ).toContain("200 Connection Established");

    // 5. Teardown: the granted topology does not survive the run that held it.
    const after = verbs(calls.slice(calls.indexOf(granted)));
    expect(after).toContain("stop sentinel-test-" + agent.id + "-broker");
    expect(after).toContain("network rm");

    // 6. A fresh, independent run asking for the same host is held again, and
    //    its broker is back to the platform endpoint alone. The approval bought
    //    one run.
    const second = await service.sendMessage(agent.id, "fetch the react version again");
    await expect.poll(() => service.getRun(second.run.id).status).toBe("held");
    expect(allowedHosts(brokerRuns(calls)[2]!)).toEqual([ARK_HOST]);
    expect(service.listApprovals(agent.id).filter((a) => a.status === "pending")).toHaveLength(1);
  }, 30_000);

  it("makes an approve-and-widen host standing, so the NEXT run keeps it", async () => {
    // The other half of the model, and the one that must not be confused with a
    // run-scoped grant: widening writes to the store, so it survives teardown
    // and applies to runs nobody approved individually.
    const { config, root } = await makeConfig();
    const { calls, exec } = recorder();
    const runner = new PolicyGatedIsolatedRunner(config, exec);
    const service = await makeService(config, root, runner);
    const agent = await service.createAgent({ name: "Widened" });

    const { run } = await service.sendMessage(agent.id, "fetch");
    await expect.poll(() => service.getRun(run.id).status).toBe("held");
    const approval = service.listApprovals(agent.id)[0]!;

    const { continuationRun } = await service.resolveApproval(
      approval.id,
      "approve",
      ALICE,
      "trusted registry, permanently",
      true, // addToAllowlist
    );
    await expect.poll(() => service.getRun(continuationRun!.id).status).toBe("completed");

    // The audit record distinguishes this from a run-scoped grant.
    const resolved = service.getApproval(approval.id);
    expect(resolved.allowlistWidened).toContain(APPROVED_HOST);
    expect(service.getAllowlist().overrides).toContain(APPROVED_HOST);

    // And the next run — with no approval of its own — completes, because the
    // standing allowlist reaches BOTH layers: policy allows the command and the
    // broker carries the host.
    const second = await service.sendMessage(agent.id, "fetch again");
    await expect.poll(() => service.getRun(second.run.id).status).toBe("completed");
    expect(allowedHosts(brokerRuns(calls).at(-1)!)).toContain(APPROVED_HOST);
  }, 30_000);

  it("puts a config-baseline standing host on the broker without any approval", async () => {
    // POLICY_ALLOWED_HOSTS used to reach the command policy only, which made an
    // operator-configured host policy-allowed and network-refused. It now feeds
    // buildEgressAllowUrls too, so the two layers agree from the start.
    const { config } = await makeConfig({ POLICY_ALLOWED_HOSTS: STANDING_HOST });
    expect(buildEgressAllowUrls(config)).toEqual([
      "https://" + ARK_HOST,
      "https://" + STANDING_HOST,
    ]);
    // And it composes with a run-scoped grant rather than replacing it.
    expect(buildEgressAllowUrls(config, [APPROVED_HOST])).toEqual([
      "https://" + ARK_HOST,
      "https://" + STANDING_HOST,
      "https://" + APPROVED_HOST,
    ]);
  });

  it("does not leak the grant to another agent's run", async () => {
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
    expect(allowedHosts(otherBroker!)).toEqual([ARK_HOST]);
  }, 30_000);

  it("refuses an approved host that resolves into a private range", async () => {
    // Approval is not a way past the rebinding check. The host is on the
    // allowlist and still does not connect, because the guard runs on the
    // RESOLVED address and runs for every allowlisted name, not only Ark's.
    const denials: string[] = [];
    const port = await listen(
      createEgressBroker({
        allow: parseEgressEndpoints(ARK_BASE_URL + ",https://" + APPROVED_HOST),
        resolve: async () => ["169.254.169.254"],
        onDenied: (reason) => denials.push(reason),
      }),
    );

    expect(await connect(port, "CONNECT " + APPROVED_HOST + ":443 HTTP/1.1\r\n\r\n")).toContain(
      "403 Forbidden",
    );
    expect(denials).toContain("resolves to a private address");
  });

  it("refuses an approved host whose answers are only partly private", async () => {
    // One public answer alongside a private one is a rebinding attempt, not a
    // dual-stack convenience. The grant does not soften that.
    const port = await listen(
      createEgressBroker({
        allow: parseEgressEndpoints(ARK_BASE_URL + ",https://" + APPROVED_HOST),
        resolve: async () => ["93.184.216.34", "127.0.0.1"],
      }),
    );
    expect(await connect(port, "CONNECT " + APPROVED_HOST + ":443 HTTP/1.1\r\n\r\n")).toContain(
      "403 Forbidden",
    );
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
      // A path no engine lives at: setup, readiness and inspect run through the
      // seam, and the Agent's spawn is what fails.
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
    expect(allowedHosts(brokerRuns(calls)[0]!)).toEqual([ARK_HOST, APPROVED_HOST]);
  }, 30_000);

  it("starts an ungranted run's broker with the platform endpoint alone", async () => {
    const calls = await runAndCapture();
    expect(allowedHosts(brokerRuns(calls)[0]!)).toEqual([ARK_HOST]);
  }, 30_000);

  it("points the Agent's resolver at the broker it just inspected", async () => {
    // An --internal network has no outbound DNS, so without --dns at the
    // broker's address the Agent cannot resolve an allowlisted host at all and
    // the grant is useless even though the CONNECT allowlist carries it.
    //
    // Two hops, checked separately because only the first goes through the
    // engine seam: setup() must READ the address, and the Agent's argv must
    // CARRY it. The Agent container is spawned directly rather than through
    // the seam, so its argv is asserted on the builder that produces it.
    const calls = await runAndCapture([APPROVED_HOST]);
    const inspect = calls.find((c) => c[0] === "inspect");
    expect(inspect, "the broker's address was never read").toBeDefined();
    expect(inspect!.at(-1)).toBe("sentinel-test-a-broker");

    const { config } = await makeConfig();
    const { exec } = recorder();
    const handle = await new EgressIsolation(config, exec).setup("a", [APPROVED_HOST]);
    expect(handle.brokerIp).toBe(BROKER_IP);

    const argv = buildContainerRunArgs(
      { agentId: "a", workspacePath: "/w", prompt: "x", threadId: null },
      config,
      handle.brokerIp,
    );
    expect(argv[argv.indexOf("--dns") + 1]).toBe(BROKER_IP);
  }, 30_000);

  it("tears the granted topology down even though the run threw", async () => {
    const calls = await runAndCapture([APPROVED_HOST]);
    const after = verbs(calls.slice(calls.indexOf(brokerRuns(calls)[0]!)));
    expect(after).toContain("stop sentinel-test-a-broker");
    expect(after).toContain("network rm");
  }, 30_000);
});
