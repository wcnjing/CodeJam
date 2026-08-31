import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { AppConfig } from "./config.js";
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
  return ["network", "create", "--internal", "--label", "io.codejam.launchpad=agent-egress", network];
}

export function buildNetworkRemoveArgs(network: string): string[] {
  return ["network", "rm", network];
}

export function buildBrokerRunArgs(options: {
  broker: string;
  network: string;
  image: string;
  allowUrl: string;
  port: number;
  user: string;
}): string[] {
  return [
    "run",
    "--detach",
    "--rm",
    "--init",
    "--name",
    options.broker,
    "--label",
    "io.codejam.launchpad=agent-egress",
    "--network",
    options.network,
    // The broker is the thing an escaped Agent attacks next, so it gets the
    // same containment as the Agent: no new privileges, no capabilities, a
    // read-only root, and no writable /tmp it could stage anything in.
    "--security-opt",
    "no-new-privileges",
    "--cap-drop",
    "ALL",
    "--read-only",
    "--user",
    options.user,
    "--env",
    "EGRESS_ALLOW_URL=" + options.allowUrl,
    "--env",
    "EGRESS_LISTEN_PORT=" + options.port,
    options.image,
  ];
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
 */
export function buildBrokerProbeArgs(broker: string, port: number): string[] {
  const probe = [
    "const s=require('net').createConnection({host:'127.0.0.1',port:" + port + "});",
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
   */
  async setup(agentId: string): Promise<IsolationHandle> {
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
        allowUrl: this.config.arkBaseUrl,
        port: this.config.containerEgressBrokerPort,
        user: this.config.containerUser,
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

    return { network, broker };
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
    handle: IsolationHandle,
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

  /** Best-effort and idempotent: teardown runs on paths that already failed. */
  async teardown(handle: IsolationHandle): Promise<void> {
    await this.exec(buildBrokerStopArgs(handle.broker));
    await this.exec(buildNetworkRemoveArgs(handle.network));
  }
}
