import { execFile, spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { promisify } from "node:util";
import type { AppConfig } from "./config.js";
import { EgressIsolation, type IsolationHandle } from "./network-isolation.js";
import {
  buildCodexArgs,
  emptyParsedEvents,
  parseCodexEventLine,
} from "./codex-runner.js";
import { BudgetExceededError, PolicyViolationError, RunCancelledError } from "./errors.js";
import { policyContextFrom, scanCommands, type Actor, type DetectedViolation } from "./command-policy.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";

const execFileAsync = promisify(execFile);

interface ActiveContainer {
  child: ChildProcess;
  containerName: string;
  cancelled: boolean;
  timedOut: boolean;
  outputExceeded: boolean;
  violation: DetectedViolation | null;
  budgetExceeded: boolean;
  settled: Promise<void>;
  termination: Promise<void> | null;
}

/**
 * A DNS label may not exceed 63 octets, and the broker's container name IS a
 * DNS label: the Agent reaches it as the host in `HTTPS_PROXY`, resolved by the
 * network's embedded DNS. A longer name resolves to nothing, so the Agent has
 * no route to the model at all — and the failure surfaces as a transport error
 * against the Ark URL, which reads like an outage rather than like a naming
 * bug. The budget is the label limit minus the longest suffix we append.
 */
const MAX_DNS_LABEL = 63;
const NAME_SUFFIXES = ["-net", "-broker"];
const MAX_CONTAINER_NAME = MAX_DNS_LABEL - Math.max(...NAME_SUFFIXES.map((s) => s.length));

/**
 * Both `_` and `.` are legal in a container name and wrong in a hostname — a
 * dot would split the label and change which name is being resolved — so the
 * safe set here is narrower than the engine's.
 */
function dnsSafe(value: string): string {
  return value.replace(/[^a-zA-Z0-9-]/g, "-");
}

export function containerName(agentId: string, instanceId = "default"): string {
  const safeInstance = dnsSafe(instanceId).slice(0, 32);
  const safeAgent = dnsSafe(agentId).slice(0, 48);
  const name = "sentinel-" + safeInstance + "-" + safeAgent;
  if (name.length <= MAX_CONTAINER_NAME) return name;

  // Truncating alone would collide across agents that share a prefix — the
  // usual shape, since these are UUIDs under one instance id. A digest of the
  // full name keeps the result unique and still deterministic, which is what
  // stale-topology cleanup depends on.
  const digest = createHash("sha256").update(name).digest("hex").slice(0, 8);
  return name.slice(0, MAX_CONTAINER_NAME - digest.length - 1) + "-" + digest;
}

/**
 * Per-run isolation names. Both derive from the container name so a crashed run
 * leaves behind something the next run can find and clear deterministically.
 * They live here, beside containerName, so network-isolation.ts can import them
 * without the two modules importing each other.
 */
export function agentNetworkName(agentId: string, config: AppConfig): string {
  return containerName(agentId, config.runtimeInstanceId) + "-net";
}

export function agentBrokerName(agentId: string, config: AppConfig): string {
  return containerName(agentId, config.runtimeInstanceId) + "-broker";
}

/** Resolvable by the network's embedded DNS from inside the isolated network. */
function brokerUrl(agentId: string, config: AppConfig): string {
  return (
    "http://" + agentBrokerName(agentId, config) + ":" + config.containerEgressBrokerPort
  );
}

export function buildContainerRunArgs(
  request: RunnerRequest,
  config: AppConfig,
  brokerIp?: string,
): string[] {
  const name = containerName(request.agentId, config.runtimeInstanceId);
  const engineName = config.containerEngine.split(/[\\/]/).at(-1)?.toLowerCase();
  return [
    "run",
    "--rm",
    "--init",
    "--name",
    name,
    "--label",
    "io.codejam.sentinel=agent-runtime",
    "--label",
    "io.codejam.agent-id=" + request.agentId,
    "--label",
    "io.codejam.instance-id=" + config.runtimeInstanceId,
    ...(engineName === "podman" ? ["--userns", "keep-id"] : []),
    // With egress isolation on, the Agent joins a per-run network the engine
    // creates with no outbound route at all, and reaches the model only through
    // the broker sidecar named in the proxy variables below. The command policy
    // still runs; it just stops being the only thing between the Agent and the
    // internet, which is what our README's base64 residual turns on.
    "--network",
    config.containerEgressIsolation ? agentNetworkName(request.agentId, config) : "bridge",
    ...(config.containerEgressIsolation
      ? [
          "--env",
          "HTTPS_PROXY=" + brokerUrl(request.agentId, config),
          "--env",
          "HTTP_PROXY=" + brokerUrl(request.agentId, config),
          "--env",
          "NO_PROXY=",
        ]
      : []),
    // A read-only root still leaves the workspace and CODEX_HOME writable: bind
    // mounts are not part of the container's root filesystem. It stops an Agent
    // writing anywhere else inside its own image, and the tmpfs is mounted
    // noexec so /tmp cannot be used to stage a binary.
    ...(config.containerReadOnlyRoot
      ? ["--read-only", "--tmpfs", "/tmp:rw,nodev,nosuid,noexec,size=64m"]
      : []),
    "--security-opt",
    "no-new-privileges",
    "--cap-drop",
    "ALL",
    "--cpus",
    String(config.containerCpuLimit),
    "--memory",
    config.containerMemoryLimit,
    "--pids-limit",
    String(config.containerPidsLimit),
    "--user",
    config.containerUser,
    "--env",
    "ARK_API_KEY",
    "--env",
    "CODEX_HOME=/codex-home",
    "--env",
    "HOME=/tmp",
    "--env",
    "NO_COLOR=1",
    // DNS for the Agent. With egress isolation on, the embedded resolver
    // refuses external queries on the --internal network and no external
    // resolver is reachable at all, so the ONLY resolver that can answer is
    // the broker's DNS forwarder — the Agent points --dns at the broker's
    // address on the isolated network. In bridge mode (isolation off), the
    // optional CONTAINER_DNS resolvers apply instead.
    ...(config.containerEgressIsolation
      ? brokerIp
        ? ["--dns", brokerIp]
        : []
      : config.containerDns.flatMap((dns) => ["--dns", dns])),
    "--mount",
    "type=bind,src=" + request.workspacePath + ",dst=/workspace",
    "--mount",
    "type=bind,src=" + config.codexHome + ",dst=/codex-home",
    "--workdir",
    "/workspace",
    config.containerRuntimeImage,
    "codex",
    ...buildCodexArgs(request, config.codexSandboxMode, "/workspace"),
  ];
}

export class ContainerCodexRunner implements AgentRunner {
  private readonly active = new Map<string, ActiveContainer>();
  private readonly isolation: EgressIsolation;
  /** Live topology per agent, so teardown can run even if the run throws. */
  private readonly isolated = new Map<string, IsolationHandle>();

  constructor(private readonly config: AppConfig) {
    this.isolation = new EgressIsolation(config);
  }

  /**
   * Brings up the isolated network and broker, and refuses to start the Agent
   * until the broker answers. A run started against a broker that has not bound
   * yet fails as what looks like a model outage — the failure mode most likely
   * to be misread as flakiness rather than as containment being broken.
   *
   * `extraAllowedHosts` are this run's approval grants; they join the broker's
   * own allowlist (beside the config baseline and store overrides) so a host a
   * human approved is actually reachable through the container's only edge.
   */
  private async startIsolation(
    agentId: string,
    extraAllowedHosts: string[] = [],
  ): Promise<IsolationHandle | null> {
    if (!this.config.containerEgressIsolation) return null;
    const handle = await this.isolation.setup(agentId, extraAllowedHosts);
    this.isolated.set(agentId, handle);
    const ready = await this.isolation.waitUntilReady(
      handle,
      this.config.containerEgressReadyTimeoutMs,
    );
    if (!ready) {
      await this.stopIsolation(agentId);
      throw new Error(
        "The egress broker did not become ready; refusing to start the Agent with no route out.",
      );
    }
    return handle;
  }

  private async stopIsolation(agentId: string): Promise<void> {
    const handle = this.isolated.get(agentId);
    if (!handle) return;
    this.isolated.delete(agentId);
    await this.isolation.teardown(handle);
  }

  async isAvailable(): Promise<boolean> {
    try {
      await execFileAsync(this.config.containerEngine, ["version"], {
        timeout: 5_000,
        env: this.childEnvironment(),
      });
      await execFileAsync(
        this.config.containerEngine,
        ["image", "inspect", this.config.containerRuntimeImage],
        { timeout: 5_000, env: this.childEnvironment() },
      );
      // With isolation on, the broker image is as load-bearing as the runtime
      // image: without it every run fails at setup. Report that here rather
      // than letting the first run discover it.
      if (this.config.containerEgressIsolation) {
        await execFileAsync(
          this.config.containerEngine,
          ["image", "inspect", this.config.containerEgressBrokerImage],
          { timeout: 5_000, env: this.childEnvironment() },
        );
      }
      return true;
    } catch {
      return false;
    }
  }

  async cancel(agentId: string): Promise<boolean> {
    const active = this.active.get(agentId);
    if (!active) return false;

    active.cancelled = true;
    await this.removeContainer(active);
    await active.settled;
    return true;
  }

  private removeContainer(active: ActiveContainer): Promise<void> {
    if (!active.termination) {
      active.termination = execFileAsync(
        this.config.containerEngine,
        ["rm", "--force", active.containerName],
        { timeout: 8_000, env: this.childEnvironment() },
      )
        .then(() => undefined)
        .catch(() => {
          active.child.kill("SIGTERM");
          const forceKill = setTimeout(() => active.child.kill("SIGKILL"), 3_000);
          forceKill.unref();
        });
    }
    return active.termination;
  }

  async run(request: RunnerRequest): Promise<RunnerResult> {
    if (this.active.has(request.agentId)) {
      throw new Error("Agent already has an active Runtime container");
    }

    const handle = await this.startIsolation(request.agentId, request.extraAllowedHosts ?? []);
    try {
      return await this.runContained(request, handle?.brokerIp ?? undefined);
    } catch (error) {
      // The spawn and the setup after it used to sit outside any teardown path,
      // so anything throwing there left the network and the broker behind until
      // the next run for this agent cleared them. stopIsolation is idempotent,
      // so the inner finally having already run is harmless.
      await this.stopIsolation(request.agentId);
      throw error;
    }
  }

  private async runContained(request: RunnerRequest, brokerIp?: string): Promise<RunnerResult> {
    const child = spawn(
      this.config.containerEngine,
      buildContainerRunArgs(request, this.config, brokerIp),
      {
        cwd: request.workspacePath,
        env: this.childEnvironment(),
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    const settled = new Promise<void>((resolve) => {
      child.once("close", () => resolve());
      child.once("error", () => resolve());
    });
    const active: ActiveContainer = {
      child,
      containerName: containerName(request.agentId, this.config.runtimeInstanceId),
      cancelled: false,
      timedOut: false,
      outputExceeded: false,
      violation: null,
      budgetExceeded: false,
      settled,
      termination: null,
    };
    this.active.set(request.agentId, active);

    const parsed = emptyParsedEvents(request.threadId);
    const actor: Actor = { agentId: request.agentId, threadId: request.threadId };
    const policyContext = policyContextFrom(
      this.config.arkBaseUrl,
      [...this.config.policyAllowedHosts, ...(request.extraAllowedHosts ?? [])],
      [this.config.arkApiKey],
      // The container runs with `--rm` and exactly two bind mounts
      // (workspacePath -> /workspace, codexHome -> /codex-home). Everything
      // else in this filesystem — /tmp and /var/tmp included — is
      // container-local and destroyed when the container exits, so a write
      // there escapes nothing and reaches no host path. Declaring the scratch
      // dirs keeps ordinary work (`git diff > /tmp/patch.diff`) out of a rule
      // that is hard-denied and terminates the run with no operator appeal.
      // Anything else absolute (/etc, /usr, /codex-home) stays untrusted.
      ["/workspace", "/tmp", "/var/tmp"],
    );
    let stdout = "";
    let stderr = "";
    let totalBytes = 0;
    let scannedCommands = 0;
    const observations: DetectedViolation[] = [];

    const consume = (chunk: Buffer, target: "stdout" | "stderr") => {
      totalBytes += chunk.byteLength;
      if (totalBytes > this.config.codexMaxOutputBytes) {
        active.outputExceeded = true;
        void this.removeContainer(active);
        return;
      }
      if (target === "stdout") {
        stdout += chunk.toString("utf8");
        const lines = stdout.split(/\r?\n/);
        stdout = lines.pop() ?? "";
        for (const line of lines) parseCodexEventLine(line, parsed);
        applyPolicy();
      } else {
        stderr += chunk.toString("utf8");
        if (stderr.length > 16_384) stderr = stderr.slice(-16_384);
      }
    };

    // Scans commands not yet evaluated, records every denial, and destroys the
    // container on the first. Declared here so the final stdout flush (below)
    // is evaluated too — a command in the last unterminated line must not escape.
    const applyPolicy = () => {
      const violations = scanCommands(actor, parsed.commands, scannedCommands, policyContext);
      scannedCommands = parsed.commands.length;
      // Step budget is a hard resource limit: enforced regardless of monitor
      // mode, because a runaway loop must be stopped whether or not command
      // policy is in shadow mode.
      if (!active.budgetExceeded && parsed.commands.length > this.config.policyMaxCommands) {
        active.budgetExceeded = true;
        void this.removeContainer(active);
      }
      for (const violation of violations) observations.push(violation);
      if (violations.length > 0 && !active.violation) {
        active.violation = violations[0]!;
        if (this.config.policyEnforcement === "enforce") void this.removeContainer(active);
      }
    };

    child.stdout.on("data", (chunk: Buffer) => consume(chunk, "stdout"));
    child.stderr.on("data", (chunk: Buffer) => consume(chunk, "stderr"));

    const timeout = setTimeout(() => {
      active.timedOut = true;
      void this.removeContainer(active);
    }, this.config.codexTimeoutMs);
    timeout.unref();

    try {
      const exitCode = await new Promise<number>((resolve, reject) => {
        child.once("error", reject);
        child.once("close", (code) => resolve(code ?? 1));
      });
      if (stdout.trim()) parseCodexEventLine(stdout.trim(), parsed);
      // The final flush may have added commands; evaluate them before deciding.
      applyPolicy();
      if (active.cancelled) throw new RunCancelledError();
      if (active.violation && this.config.policyEnforcement === "enforce") {
        throw new PolicyViolationError(
          active.violation.rule,
          active.violation.command,
          active.violation.detail,
          active.violation.hosts ?? [],
          active.violation.capabilities ?? [],
        );
      }
      if (active.budgetExceeded) {
        throw new BudgetExceededError(
          this.config.policyMaxCommands,
          parsed.commands.length,
          parsed.threadId,
        );
      }
      if (active.timedOut) {
        throw new Error("Runtime timed out after " + this.config.codexTimeoutMs + " ms");
      }
      if (active.outputExceeded) {
        throw new Error("Codex output exceeded CODEX_MAX_OUTPUT_BYTES");
      }
      if (exitCode !== 0) {
        const detail = parsed.errors.at(-1) ?? stderr.trim() ?? "No error detail";
        throw new Error(
          this.config.containerEngine +
            " Runtime exited with code " +
            exitCode +
            ": " +
            detail,
        );
      }
      const output = parsed.messages.at(-1)?.trim();
      if (!output) throw new Error("Codex completed without an agent message");
      return {
        output,
        threadId: parsed.threadId,
        usage: parsed.usage,
        violations: observations,
      };
    } catch (error) {
      // Carry monitor-mode observations out on the failure path too, so a
      // near-miss is not lost when the run later times out, exceeds budget, or
      // errors. AgentService reads these in monitor mode.
      (error as { observations?: DetectedViolation[] }).observations = observations;
      throw error;
    } finally {
      clearTimeout(timeout);
      this.active.delete(request.agentId);
      // Always, including the throw paths above: a leaked network survives the
      // process and the next run's setup would have to clear it blind.
      await this.stopIsolation(request.agentId);
    }
  }

  private childEnvironment(): NodeJS.ProcessEnv {
    const environment: NodeJS.ProcessEnv = {
      ARK_API_KEY: this.config.arkApiKey,
      NO_COLOR: "1",
    };
    for (const name of [
      "PATH",
      "HOME",
      "TMPDIR",
      "LANG",
      "LC_ALL",
      "XDG_RUNTIME_DIR",
    ] as const) {
      if (process.env[name] !== undefined) environment[name] = process.env[name];
    }
    return environment;
  }
}
