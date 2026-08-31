import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { AppConfig } from "./config.js";
import { parseEgressEndpoint, type EgressEndpoint } from "./egress-broker.js";
import { agentBrokerName, agentNetworkName } from "./container-codex-runner.js";

const execFileAsync = promisify(execFile);

/**
 * Creates and tears down the per-run egress topology.
 *
 * Three objects per run: an `--internal` network with no route out, a broker
 * sidecar on it, and the Agent container. The broker is then also connected to
 * the default bridge, which is what makes it dual-homed — the single point with
 * a foot on both sides. The Agent can reach the broker by container name
 * through the network's embedded DNS, and can reach nothing else at all.
 *
 * Ordering matters and is not arbitrary: network, then broker, then wait for
 * the broker to answer, and only then the Agent. Starting the Agent against a
 * broker that has not bound yet gives a run that fails in a way that looks like
 * a model outage, which is the failure mode most likely to be misdiagnosed.
 *
 * Every step goes through the engine, the readiness probe included. Nothing
 * here is reachable from the host: that is the point of an --internal network
 * with no published ports, and a readiness check that assumed otherwise would
 * fail every run while looking like the broker was at fault.
 */

export interface EngineResult {
  code: number;
  stdout: string;
  stderr: string;
}

/** Runs the container engine. Injectable so the lifecycle is testable. */
export type EngineExec = (args: string[]) => Promise<EngineResult>;

export function buildNetworkCreateArgs(network: string): string[] {
  // --internal is the whole control: the engine installs no NAT or gateway, so
  // there is no route off this network for anything attached to it.
  return ["network", "create", "--internal", "--label", "io.codejam.sentinel=agent-egress", network];
}

export function buildNetworkRemoveArgs(network: string): string[] {
  return ["network", "rm", network];
}

export function buildBrokerRunArgs(options: {
  broker: string;
  network: string;
  image: string;
  allowUrls: string[];
  port: number;
  user: string;
  dns?: string[];
  /**
   * The run this broker serves. Stamped into the container's env so every
   * denial it logs can be correlated back to a run without the control plane
   * having to guess from timing. Omitted for a broker started outside a run
   * (`verify:egress`), where the denial is still logged, just uncorrelated.
   */
  runId?: string;
  agentId?: string;
}): string[] {
  return [
    "run",
    "--detach",
    "--rm",
    "--init",
    "--name",
    options.broker,
    "--label",
    "io.codejam.sentinel=agent-egress",
    "--network",
    options.network,
    // The broker resolves allowlisted hostnames itself (node:dns) before
    // connecting, so its resolvers decide whether the isolated Agent's only
    // edge can reach anything. Inherited resolvers are the default; an explicit
    // CONTAINER_DNS keeps the broker working when the host resolver is
    // unreachable from containers.
    ...(options.dns ?? []).flatMap((dns) => ["--dns", dns]),
    // The broker is the thing an escaped Agent attacks next, so it gets the
    // same containment as the Agent: no new privileges, no capabilities, a
    // read-only root, and no writable /tmp it could stage anything in. The one
    // exception is NET_BIND_SERVICE: the broker answers the Agent network's
    // DNS on port 53 (privileged), so it needs exactly that capability —
    // binding low ports — and nothing else.
    "--security-opt",
    "no-new-privileges",
    "--cap-drop",
    "ALL",
    "--cap-add",
    "NET_BIND_SERVICE",
    "--read-only",
    "--user",
    options.user,
    "--env",
    "EGRESS_ALLOW_URL=" + options.allowUrls.join(","),
    "--env",
    "EGRESS_LISTEN_PORT=" + options.port,
    ...(options.runId ? ["--env", "EGRESS_RUN_ID=" + options.runId] : []),
    ...(options.agentId ? ["--env", "EGRESS_AGENT_ID=" + options.agentId] : []),
    options.image,
  ];
}

/**
 * Reads the broker's own log.
 *
 * The broker is a detached container on an `--internal` network with no
 * published port, so the engine is the only thing that can hand its stderr
 * back. `--tail` bounds the read: a run that denied thousands of destinations
 * should cost a bounded amount of evidence collection, and the ratchet on that
 * is a truncated list rather than an unbounded one.
 */
export function buildBrokerLogsArgs(broker: string, tail = 2_000): string[] {
  return ["logs", "--tail", String(tail), broker];
}

/** One `egress-denied` line as the broker's CLI writes it. */
export interface BrokerDenialRecord {
  host: string;
  port: number;
  reason: string;
  target: string;
  runId: string;
  agentId: string;
  at: string;
}

/**
 * Pulls the `egress-denied` records out of a broker log.
 *
 * Tolerant by design: the log carries readiness lines and whatever the node
 * runtime decided to print, so anything that is not a well-formed denial is
 * skipped rather than failing the parse. Losing one malformed line is a smaller
 * harm than discarding a whole run's evidence over it.
 */
export function parseBrokerDenials(log: string): BrokerDenialRecord[] {
  const records: BrokerDenialRecord[] = [];
  for (const line of log.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed.includes("egress-denied")) continue;
    // Engine log lines can carry a stream prefix; start at the JSON.
    const start = trimmed.indexOf("{");
    if (start === -1) continue;
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(trimmed.slice(start)) as Record<string, unknown>;
    } catch {
      continue;
    }
    if (parsed.event !== "egress-denied") continue;
    const target = typeof parsed.target === "string" ? parsed.target : "-";
    records.push({
      host: typeof parsed.host === "string" ? parsed.host : target,
      port: typeof parsed.port === "number" ? parsed.port : 0,
      reason: typeof parsed.reason === "string" ? parsed.reason : "denied",
      target,
      runId: typeof parsed.runId === "string" ? parsed.runId : "",
      agentId: typeof parsed.agentId === "string" ? parsed.agentId : "",
      at: typeof parsed.at === "string" ? parsed.at : "",
    });
  }
  return records;
}

/**
 * Asks the engine for the broker's address on the isolated network — the
 * address the Agent's `--dns` must point at. The broker is dual-homed, so it
 * has more than one address; the network name pins the query to the one the
 * Agent can actually reach. The name contains hyphens, hence the `index` form
 * (a bare `.Networks.<name>` is not valid Go template syntax).
 */
export function buildBrokerInspectArgs(broker: string, network: string): string[] {
  return [
    "inspect",
    "--format",
    '{{(index .NetworkSettings.Networks "' + network + '").IPAddress}}',
    broker,
  ];
}

/**
 * The endpoints one run's broker will permit, as EGRESS_ALLOW_URL entries.
 *
 * Always the model API, plus every host on the effective command-policy
 * allowlist: the config baseline (`POLICY_ALLOWED_HOSTS`), the store-backed
 * overrides the operator edits in the UI, and the run-scoped grant an approval
 * adds. Without this the broker — the container's ONLY route out — refused
 * allowlisted hosts, so a command the policy allowed still could not reach its
 * destination. Allowlisted hosts are CONNECTed on 443, the port a hostname
 * flag carries no information about; the broker only speaks CONNECT anyway, so
 * plain-http destinations are out of scope regardless.
 */
export function buildEgressAllowUrls(
  config: AppConfig,
  extraHosts: readonly string[] = [],
): string[] {
  const endpoints: EgressEndpoint[] = [parseEgressEndpoint(config.arkBaseUrl)];
  for (const host of [...config.policyAllowedHosts, ...extraHosts]) {
    endpoints.push({ host: host.toLowerCase(), port: 443 });
  }
  const seen = new Set<string>();
  const urls: string[] = [];
  for (const endpoint of endpoints) {
    const key = endpoint.host + ":" + endpoint.port;
    if (seen.has(key)) continue;
    seen.add(key);
    urls.push("https://" + endpoint.host + (endpoint.port === 443 ? "" : ":" + endpoint.port));
  }
  return urls;
}

/** Gives the broker its second home: a network that actually has a route out. */
export function buildBrokerConnectArgs(broker: string, outboundNetwork: string): string[] {
  return ["network", "connect", outboundNetwork, broker];
}

/**
 * Asks the broker, from inside itself, whether it is accepting connections yet.
 *
 * The probe cannot run on the host. A container name resolves only through the
 * network's embedded DNS, which only containers on that network may query, and
 * the broker publishes no host port on purpose — publishing one would give
 * anything on the host a second way into the single edge we are trying to keep
 * singular. A host-side `connect()` to either the name or the container IP
 * therefore fails on every platform we support, so the engine is the only thing
 * that can answer the question, and we ask it.
 *
 * `node -e` runs as CommonJS, and the broker image is a node base, so the probe
 * needs nothing installed that is not already there.
 *
 * It dials the broker by NAME rather than by `127.0.0.1`. The Agent reaches the
 * broker as the host in `HTTPS_PROXY`, so name resolution is half of what has
 * to work, and a loopback probe passes with the name broken — which is exactly
 * how a container name too long to be a DNS label got as far as a live run:
 * the broker was up, the Agent could not resolve it, and the run failed against
 * the Ark URL as though the model were down. The broker is on the same network,
 * so the embedded DNS answers for its own name and the probe exercises the same
 * path the Agent will.
 */
export function buildBrokerProbeArgs(broker: string, port: number): string[] {
  const probe = [
    "const s=require('net').createConnection({host:" + JSON.stringify(broker) + ",port:" + port + "});",
    "s.on('connect',()=>{s.destroy();process.exit(0)});",
    "s.on('error',()=>process.exit(1));",
    "s.setTimeout(2000,()=>process.exit(1));",
  ].join("");
  return ["exec", broker, "node", "-e", probe];
}

export function buildBrokerStopArgs(broker: string): string[] {
  return ["stop", "--timeout", "5", broker];
}

async function defaultExec(engine: string, args: string[]): Promise<EngineResult> {
  try {
    const { stdout, stderr } = await execFileAsync(engine, args, { timeout: 60_000 });
    return { code: 0, stdout, stderr };
  } catch (error) {
    const failure = error as { code?: number; stdout?: string; stderr?: string; message?: string };
    return {
      code: typeof failure.code === "number" ? failure.code : 1,
      stdout: failure.stdout ?? "",
      stderr: failure.stderr ?? failure.message ?? "",
    };
  }
}

export interface IsolationHandle {
  network: string;
  broker: string;
  /**
   * The broker's address on the isolated network. The Agent's `--dns` points
   * here: the broker answers DNS for the Agent network (the embedded resolver
   * refuses external queries on --internal networks), so this is the only
   * reachable resolver the Agent has.
   */
  brokerIp: string;
}

export class EgressIsolation {
  private readonly exec: EngineExec;

  constructor(
    private readonly config: AppConfig,
    exec?: EngineExec,
  ) {
    this.exec = exec ?? ((args) => defaultExec(config.containerEngine, args));
  }

  /**
   * Brings up the network and the broker for one run. Any failure tears down
   * whatever was already created and throws: a half-built topology would leave
   * the Agent on an internal network with no broker, which is a hang rather
   * than an error, and leak a network besides.
   *
   * `extraAllowedHosts` are the run-scoped hosts (approval grants) that join
   * the broker's allowlist beside the config baseline and store overrides —
   * the same effective list the command policy evaluates against.
   */
  async setup(
    agentId: string,
    extraAllowedHosts: string[] = [],
    runId?: string,
  ): Promise<IsolationHandle> {
    const network = agentNetworkName(agentId, this.config);
    const broker = agentBrokerName(agentId, this.config);
    // A previous crash can leave both behind; the names are deterministic, so
    // clear them before creating rather than failing on "already exists".
    await this.teardown({ network, broker });

    const created = await this.exec(buildNetworkCreateArgs(network));
    if (created.code !== 0) {
      throw new Error("Could not create the isolated network: " + created.stderr.trim());
    }

    const started = await this.exec(
      buildBrokerRunArgs({
        broker,
        network,
        image: this.config.containerEgressBrokerImage,
        allowUrls: buildEgressAllowUrls(this.config, extraAllowedHosts),
        port: this.config.containerEgressBrokerPort,
        user: this.config.containerUser,
        dns: this.config.containerDns,
        ...(runId ? { runId } : {}),
        agentId,
      }),
    );
    if (started.code !== 0) {
      await this.exec(buildNetworkRemoveArgs(network));
      throw new Error("Could not start the egress broker: " + started.stderr.trim());
    }

    const connected = await this.exec(
      buildBrokerConnectArgs(broker, this.config.containerEgressOutboundNetwork),
    );
    if (connected.code !== 0) {
      await this.teardown({ network, broker });
      throw new Error(
        "Could not give the broker an outbound network: " + connected.stderr.trim(),
      );
    }

    // The Agent must be told where its only resolver lives (--dns takes an IP,
    // not a name), so the broker's address on the isolated network has to come
    // from the engine. Failure here is a containment failure: without it the
    // Agent cannot resolve anything at all, so refuse the run rather than
    // start it half-configured.
    const inspected = await this.exec(buildBrokerInspectArgs(broker, network));
    const brokerIp = inspected.stdout.trim().split(/\s+/)[0] ?? "";
    if (inspected.code !== 0 || !brokerIp) {
      await this.teardown({ network, broker });
      throw new Error(
        "Could not determine the broker's address on the isolated network: " +
          inspected.stderr.trim(),
      );
    }

    return { network, broker, brokerIp };
  }

  /**
   * Polls the broker until it accepts a connection, through the engine.
   *
   * Polls rather than sleeping a fixed interval: a fixed sleep is either too
   * short on a cold image pull or wasted on every warm run. Returns false on
   * the deadline rather than throwing, so the caller decides what a broker that
   * never bound means — here, refusing to start the Agent at all.
   */
  async waitUntilReady(
    handle: Pick<IsolationHandle, "network" | "broker">,
    timeoutMs = 15_000,
    intervalMs = 200,
  ): Promise<boolean> {
    const args = buildBrokerProbeArgs(handle.broker, this.config.containerEgressBrokerPort);
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const probe = await this.exec(args);
      if (probe.code === 0) return true;
      if (Date.now() + intervalMs >= deadline) return false;
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
  }

  /**
   * Reads the denials this run's broker recorded.
   *
   * Returns `null` -- not an empty array -- when the log could not be read.
   * The difference is the whole point: an empty array means the broker was
   * asked and refused nothing, and `null` means nobody knows. Rendering the
   * second as the first would turn missing evidence into a clean bill of
   * health, which is the one failure mode this evidence exists to prevent.
   *
   * Never throws. Evidence collection must not be a reason a run fails:
   * containment already held by the time there is anything to collect, and a
   * run that succeeds with unreadable logs is strictly better than a run that
   * fails because a `docker logs` call did.
   */
  async collectDenials(
    handle: Pick<IsolationHandle, "broker">,
  ): Promise<BrokerDenialRecord[] | null> {
    try {
      const logs = await this.exec(buildBrokerLogsArgs(handle.broker));
      if (logs.code !== 0) return null;
      // The engine splits the container's streams; denials go to stderr, but
      // engines differ on which stream they replay them through, so read both.
      return parseBrokerDenials(logs.stdout + "\n" + logs.stderr);
    } catch {
      return null;
    }
  }

  /** Best-effort and idempotent: teardown runs on paths that already failed. */
  async teardown(handle: Pick<IsolationHandle, "network" | "broker">): Promise<void> {
    await this.exec(buildBrokerStopArgs(handle.broker));
    await this.exec(buildNetworkRemoveArgs(handle.network));
  }
}
