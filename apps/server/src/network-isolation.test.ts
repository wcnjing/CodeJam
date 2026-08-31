import { describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";
import {
  EgressIsolation,
  buildBrokerConnectArgs,
  buildBrokerInspectArgs,
  buildBrokerRunArgs,
  buildEgressAllowUrls,
  buildNetworkCreateArgs,
  buildBrokerProbeArgs,
  type EngineResult,
} from "./network-isolation.js";

const config = loadConfig({
  NODE_ENV: "test",
  ARK_API_KEY: "k",
  ARK_MODEL: "ep-test",
  ARK_BASE_URL: "https://ark.example.invalid/api/v3",
  RUNTIME_PROVIDER: "container",
  RUNTIME_INSTANCE_ID: "test-instance",
  CONTAINER_EGRESS_ISOLATION: "true",
  CONTAINER_USER: "1000:1000",
});

const ok: EngineResult = { code: 0, stdout: "", stderr: "" };
const fail = (stderr: string): EngineResult => ({ code: 1, stdout: "", stderr });

/** Records every engine invocation so ordering can be asserted, not just calls. */
function recorder(responses: (args: string[]) => EngineResult = () => ok) {
  const calls: string[][] = [];
  return {
    calls,
    exec: async (args: string[]) => {
      calls.push(args);
      return responses(args);
    },
  };
}

/** A stable label per invocation: the command, plus the object it acts on. */
const verbs = (calls: string[][]) =>
  calls.map((c) => {
    if (c[0] === "network") return "network " + c[1];
    if (c[0] === "stop") return "stop " + c[c.length - 1];
    return c[0]!;
  });

describe("isolation argv", () => {
  it("creates the network with --internal, which is the whole control", () => {
    // Without --internal the engine installs a NAT gateway and the Agent has a
    // route out regardless of what the proxy variables say.
    expect(buildNetworkCreateArgs("net-1")).toContain("--internal");
  });

  it("starts the broker contained as tightly as the Agent", () => {
    const args = buildBrokerRunArgs({
      broker: "b", network: "n", image: "img", allowUrls: ["https://ark.example.invalid"], port: 8080, user: "1000:1000",
    });
    expect(args).toContain("--read-only");
    expect(args).toContain("no-new-privileges");
    expect(args).toContain("ALL"); // --cap-drop ALL
    // The one capability the broker keeps: it answers the Agent network's DNS
    // on port 53, and binding a privileged port is the whole of what this
    // grants — no other capability survives.
    expect(args[args.indexOf("--cap-add") + 1]).toBe("NET_BIND_SERVICE");
    expect(args).toContain("EGRESS_ALLOW_URL=https://ark.example.invalid");
    expect(args[args.indexOf("--network") + 1]).toBe("n");
  });

  it("passes the full effective allowlist to the broker", () => {
    const configWithHosts = loadConfig({
      NODE_ENV: "test",
      ARK_API_KEY: "k",
      ARK_MODEL: "ep-test",
      ARK_BASE_URL: "https://ark.example.invalid/api/v3",
      RUNTIME_PROVIDER: "container",
      CONTAINER_EGRESS_ISOLATION: "true",
      POLICY_ALLOWED_HOSTS: "google.com, docs.example.com",
    });
    // Ark always, config baseline, store overrides, and a run-scoped approval
    // grant — deduped into one comma-separated EGRESS_ALLOW_URL.
    const urls = buildEgressAllowUrls(configWithHosts, [
      "docs.example.com",
      "registry.npmjs.org",
    ]);
    expect(urls).toEqual([
      "https://ark.example.invalid",
      "https://google.com",
      "https://docs.example.com",
      "https://registry.npmjs.org",
    ]);
    const args = buildBrokerRunArgs({
      broker: "b", network: "n", image: "img", allowUrls: urls, port: 8080, user: "1000:1000",
    });
    expect(args).toContain(
      "EGRESS_ALLOW_URL=https://ark.example.invalid,https://google.com,https://docs.example.com,https://registry.npmjs.org",
    );
  });

  it("gives the broker a second, outbound network", () => {
    expect(buildBrokerConnectArgs("b", "bridge")).toEqual(["network", "connect", "bridge", "b"]);
  });

  it("pins the broker's own resolvers when CONTAINER_DNS is set", () => {
    const args = buildBrokerRunArgs({
      broker: "b", network: "n", image: "img", allowUrls: ["https://ark.example.invalid"], port: 8080, user: "1000:1000", dns: ["1.1.1.1", "10.255.255.254"],
    });
    // The broker resolves allowlisted hostnames itself, so its --dns flags are
    // what keep the isolated Agent's only edge working when the inherited
    // resolver is unreachable from containers.
    expect(args).toContain("--dns");
    expect(args[args.indexOf("--dns") + 1]).toBe("1.1.1.1");
    expect(args).toContain("10.255.255.254");
  });

  it("asks the engine for the broker's address on the isolated network only", () => {
    // The broker is dual-homed; the Agent can only reach the internal-network
    // address, so the query must be pinned to that network by name.
    const args = buildBrokerInspectArgs("b", "net-1");
    expect(args[0]).toBe("inspect");
    expect(args[1]).toBe("--format");
    expect(args[2]).toContain('Networks "net-1"');
    expect(args.at(-1)).toBe("b");
  });
});

describe("EgressIsolation lifecycle", () => {
  it("clears a stale topology, then creates, starts, dual-homes and reads the broker address", async () => {
    // The inspect call is what tells the runner where the Agent's only
    // resolver lives; without it the Agent could not resolve anything.
    const { calls, exec } = recorder((args) =>
      args[0] === "inspect" ? { code: 0, stdout: "172.30.0.9\n", stderr: "" } : ok,
    );
    const handle = await new EgressIsolation(config, exec).setup("agent-1");

    expect(handle).toEqual({
      network: "sentinel-test-instance-agent-1-net",
      broker: "sentinel-test-instance-agent-1-broker",
      brokerIp: "172.30.0.9",
    });
    // Stale cleanup first: names are deterministic, so a crashed previous run
    // would otherwise make "already exists" the normal startup path.
    expect(verbs(calls)).toEqual([
      "stop sentinel-test-instance-agent-1-broker",
      "network rm",
      "network create",
      "run",
      "network connect",
      "inspect",
    ]);
  });

  it("refuses to start when the broker's address cannot be determined", async () => {
    // No broker IP means no --dns for the Agent, which means the Agent cannot
    // resolve anything on the isolated network — a half-configured run, so it
    // must fail here and tear the topology back down.
    const { calls, exec } = recorder((args) =>
      args[0] === "inspect" ? { code: 0, stdout: "", stderr: "" } : ok,
    );
    await expect(new EgressIsolation(config, exec).setup("agent-1")).rejects.toThrow(
      /broker's address/,
    );
    expect(calls.filter((c) => c[0] === "stop").length).toBeGreaterThan(0);
    expect(calls.filter((c) => c[0] === "network" && c[1] === "rm").length).toBeGreaterThan(0);
  });

  it("removes the network when the broker will not start", async () => {
    const { calls, exec } = recorder((args) =>
      args[0] === "run" ? fail("no such image") : ok,
    );
    await expect(new EgressIsolation(config, exec).setup("agent-1")).rejects.toThrow(
      /Could not start the egress broker: no such image/,
    );
    // The network must not survive the failure, or the next run inherits it.
    expect(verbs(calls).slice(-1)).toEqual(["network rm"]);
  });

  it("tears down both when the broker cannot be given an outbound network", async () => {
    const { calls, exec } = recorder((args) =>
      args[0] === "network" && args[1] === "connect" ? fail("bridge missing") : ok,
    );
    await expect(new EgressIsolation(config, exec).setup("agent-1")).rejects.toThrow(
      /outbound network: bridge missing/,
    );
    expect(verbs(calls).slice(-2)).toEqual(["stop sentinel-test-instance-agent-1-broker", "network rm"]);
  });

  it("fails loudly when the network cannot be created", async () => {
    const { exec } = recorder((args) =>
      args[0] === "network" && args[1] === "create" ? fail("pool exhausted") : ok,
    );
    await expect(new EgressIsolation(config, exec).setup("agent-1")).rejects.toThrow(
      /isolated network: pool exhausted/,
    );
  });

  it("tears down the broker before the network it is attached to", async () => {
    const { calls, exec } = recorder();
    await new EgressIsolation(config, exec).teardown({ network: "n", broker: "b" });
    expect(verbs(calls)).toEqual(["stop b", "network rm"]);
  });
});

describe("broker readiness", () => {
  it("probes through the engine, from inside the broker", async () => {
    // The previous check connected from the host to the broker's container
    // name. Nothing on the host can resolve that name, and the broker publishes
    // no host port, so the probe could never succeed and every isolated run
    // failed at the gate. Readiness is only observable through the engine.
    const args = buildBrokerProbeArgs("b", 8080);
    expect(args.slice(0, 3)).toEqual(["exec", "b", "node"]);
    expect(args.at(-1)).toContain("port:8080");
    expect(args.at(-1)).toContain("127.0.0.1");
  });

  it("returns true as soon as the probe succeeds", async () => {
    const { calls, exec } = recorder();
    const ready = await new EgressIsolation(config, exec).waitUntilReady(
      { network: "n", broker: "b" },
      3_000,
      50,
    );
    expect(ready).toBe(true);
    expect(calls.filter((c) => c[0] === "exec")).toHaveLength(1);
  });

  it("keeps polling while the broker is still binding", async () => {
    let attempts = 0;
    const { exec } = recorder(() => (++attempts < 3 ? fail("not running") : ok));
    const ready = await new EgressIsolation(config, exec).waitUntilReady(
      { network: "n", broker: "b" },
      3_000,
      20,
    );
    expect(ready).toBe(true);
    expect(attempts).toBe(3);
  });

  it("returns false rather than hanging when the broker never answers", async () => {
    // The readiness check is what stops a broken sidecar from presenting as a
    // model outage, so its timeout has to be real.
    const { exec } = recorder(() => fail("no such container"));
    const ready = await new EgressIsolation(config, exec).waitUntilReady(
      { network: "n", broker: "b" },
      300,
      50,
    );
    expect(ready).toBe(false);
  });
});
